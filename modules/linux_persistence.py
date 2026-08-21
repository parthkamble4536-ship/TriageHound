"""
Linux Persistence Collector (v3.0)
=====================================
Collects Linux persistence mechanisms:
- Cron jobs (/etc/cron.*, /var/spool/cron/crontabs/)
- Systemd services (/etc/systemd/system/)
- SUID/SGID binaries (filesystem-wide scan)

Equivalent to Windows Startup Programs / Scheduled Tasks.

Requires: root/sudo for full access.
"""

import os
import stat
import subprocess
from datetime import datetime


# Cron directories to scan
CRON_DIRS = [
    "/etc/crontab",              # System crontab
    "/etc/cron.d",               # Drop-in cron files
    "/etc/cron.daily",           # Daily jobs
    "/etc/cron.hourly",          # Hourly jobs
    "/etc/cron.weekly",          # Weekly jobs
    "/etc/cron.monthly",         # Monthly jobs
    "/var/spool/cron/crontabs",  # Per-user crontabs (Debian)
    "/var/spool/cron",           # Per-user crontabs (RHEL)
]

# Systemd directories
SYSTEMD_DIRS = [
    "/etc/systemd/system",       # Admin-installed services
    "/lib/systemd/system",       # Package-installed services (reference)
]

# Common legitimate SUID binaries (don't flag these)
LEGITIMATE_SUID = {
    "su", "sudo", "passwd", "ping", "mount", "umount",
    "chsh", "chfn", "newgrp", "gpasswd", "pkexec",
    "crontab", "at", "traceroute", "ssh-agent",
    "fusermount", "fusermount3", "unix_chkpwd",
    "Xorg", "dbus-daemon-launch-helper",
}


def collect(db, case_id, scan_suid=True):
    """
    Collect Linux persistence artifacts (cron, systemd, SUID).

    Args:
        db:         DBManager instance
        case_id:    Case identifier string
        scan_suid:  Whether to scan for SUID/SGID binaries (default: True)

    Returns:
        list of dicts with persistence entries
    """
    results = []

    # 1. Cron jobs
    results += _collect_cron(db, case_id)

    # 2. Systemd services
    results += _collect_systemd(db, case_id)

    # 3. SUID/SGID binaries
    if scan_suid:
        results += _collect_suid(db, case_id)

    print(f"    -> Collected {len(results)} persistence entries (cron + systemd + SUID).")
    return results


def _collect_cron(db, case_id):
    """Collect all cron jobs from system and per-user crontabs."""
    entries = []

    for cron_path in CRON_DIRS:
        if os.path.isfile(cron_path):
            entries += _parse_cron_file(db, case_id, cron_path, "system")
        elif os.path.isdir(cron_path):
            try:
                for filename in os.listdir(cron_path):
                    filepath = os.path.join(cron_path, filename)
                    if os.path.isfile(filepath):
                        # Determine if this is a per-user crontab
                        if "spool" in cron_path:
                            owner = filename  # filename IS the username
                        else:
                            owner = "system"
                        entries += _parse_cron_file(db, case_id, filepath, owner)
            except PermissionError:
                print(f"    [!] Permission denied: {cron_path}")

    return entries


def _parse_cron_file(db, case_id, filepath, owner):
    """Parse a single cron file for scheduled commands."""
    entries = []

    try:
        with open(filepath, "r", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Skip environment variable assignments
                if "=" in line and not any(c in line.split("=")[0] for c in " \t*"):
                    continue

                # Check for suspicious commands in cron entries
                suspicious_flags = []
                line_lower = line.lower()
                for keyword in ["curl", "wget", "python", "bash -c", "nc ",
                                "base64", "/tmp/", "/dev/shm", "reverse",
                                "chmod +s", "nohup"]:
                    if keyword in line_lower:
                        suspicious_flags.append(f"SuspiciousCmd:{keyword}")

                raw_data = {
                    "cron_file": filepath,
                    "owner": owner,
                    "line_number": line_no,
                    "cron_entry": line[:500],
                    "suspicious_flags": suspicious_flags,
                    "timestamp": _get_file_mtime(filepath),
                }

                if suspicious_flags:
                    detail = f"[SUSPICIOUS CRON] Owner '{owner}': {line[:120]} [{', '.join(suspicious_flags)}]"
                else:
                    detail = f"[CRON] Owner '{owner}': {line[:150]}"

                db.insert_evidence(
                    evidence_type="linux_persistence",
                    source="Cron Job",
                    detail=detail[:250],
                    timestamp=raw_data["timestamp"],
                    raw_data=raw_data,
                    case_id=case_id,
                )
                entries.append(raw_data)

    except PermissionError:
        print(f"    [!] Permission denied: {filepath}")
    except Exception as e:
        print(f"    [!] Error reading {filepath}: {e}")

    return entries


def _collect_systemd(db, case_id):
    """Collect enabled systemd services."""
    entries = []

    for systemd_dir in SYSTEMD_DIRS:
        if not os.path.isdir(systemd_dir):
            continue

        try:
            for item in os.listdir(systemd_dir):
                service_path = os.path.join(systemd_dir, item)

                # Only process .service and .timer files
                if not (item.endswith(".service") or item.endswith(".timer")):
                    continue

                if not os.path.isfile(service_path):
                    continue

                try:
                    with open(service_path, "r", errors="replace") as f:
                        content = f.read()

                    # Extract key fields
                    exec_start = ""
                    description = ""
                    for svc_line in content.splitlines():
                        svc_line = svc_line.strip()
                        if svc_line.startswith("ExecStart="):
                            exec_start = svc_line.split("=", 1)[1]
                        elif svc_line.startswith("Description="):
                            description = svc_line.split("=", 1)[1]

                    # Flag suspicious services
                    suspicious_flags = []
                    content_lower = content.lower()
                    for keyword in ["curl", "wget", "python", "bash -c",
                                    "/tmp/", "/dev/shm", "reverse", "nc -"]:
                        if keyword in content_lower:
                            suspicious_flags.append(f"SuspiciousExec:{keyword}")

                    raw_data = {
                        "service_name": item,
                        "service_path": service_path,
                        "exec_start": exec_start[:300],
                        "description": description[:200],
                        "suspicious_flags": suspicious_flags,
                        "systemd_dir": systemd_dir,
                        "timestamp": _get_file_mtime(service_path),
                    }

                    if suspicious_flags:
                        detail = f"[SUSPICIOUS SERVICE] {item}: {exec_start[:100]} [{', '.join(suspicious_flags)}]"
                    else:
                        detail = f"[systemd] {item}: {exec_start[:120]}"

                    db.insert_evidence(
                        evidence_type="linux_persistence",
                        source="Systemd Service",
                        detail=detail[:250],
                        timestamp=raw_data["timestamp"],
                        raw_data=raw_data,
                        case_id=case_id,
                    )
                    entries.append(raw_data)

                except PermissionError:
                    pass
                except Exception as e:
                    print(f"    [!] Error reading {service_path}: {e}")

        except PermissionError:
            print(f"    [!] Permission denied: {systemd_dir}")

    return entries


def _collect_suid(db, case_id):
    """Scan for SUID/SGID binaries across the filesystem."""
    entries = []

    # Use 'find' command for efficiency (much faster than Python walk)
    try:
        result = subprocess.run(
            ["find", "/", "-perm", "-4000", "-o", "-perm", "-2000"],
            capture_output=True, text=True, timeout=60,
            stderr=subprocess.DEVNULL,  # Suppress permission denied errors
        )

        for filepath in result.stdout.strip().splitlines():
            filepath = filepath.strip()
            if not filepath:
                continue

            basename = os.path.basename(filepath)

            # Skip known legitimate SUID binaries
            if basename in LEGITIMATE_SUID:
                continue

            # This is a non-standard SUID/SGID binary — flag it
            try:
                file_stat = os.stat(filepath)
                mode = file_stat.st_mode
                is_suid = bool(mode & stat.S_ISUID)
                is_sgid = bool(mode & stat.S_ISGID)
                owner_uid = file_stat.st_uid
                file_size = file_stat.st_size
            except (OSError, PermissionError):
                is_suid = True
                is_sgid = False
                owner_uid = -1
                file_size = 0

            raw_data = {
                "filepath": filepath,
                "basename": basename,
                "is_suid": is_suid,
                "is_sgid": is_sgid,
                "owner_uid": owner_uid,
                "file_size": file_size,
                "timestamp": _get_file_mtime(filepath),
            }

            perm_type = []
            if is_suid:
                perm_type.append("SUID")
            if is_sgid:
                perm_type.append("SGID")

            detail = f"[{'+'.join(perm_type)}] Non-standard privileged binary: {filepath}"

            db.insert_evidence(
                evidence_type="linux_persistence",
                source="SUID/SGID Binary Scan",
                detail=detail[:250],
                timestamp=raw_data["timestamp"],
                raw_data=raw_data,
                case_id=case_id,
            )
            entries.append(raw_data)

    except subprocess.TimeoutExpired:
        print("    [!] SUID scan timed out after 60 seconds.")
    except FileNotFoundError:
        print("    [!] 'find' command not available.")
    except Exception as e:
        print(f"    [!] Error during SUID scan: {e}")

    return entries


def _get_file_mtime(filepath):
    """Get file modification time as ISO string."""
    try:
        mtime = os.path.getmtime(filepath)
        return datetime.fromtimestamp(mtime).isoformat()
    except Exception:
        return datetime.now().isoformat()
