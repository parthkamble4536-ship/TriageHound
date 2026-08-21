"""
Linux In-Memory Drops Collector (v3.0 - Advanced)
=====================================================
Scans RAM-backed filesystems for dropped malware:
- /tmp/          (temporary files, survives reboot on some systems)
- /dev/shm/      (POSIX shared memory, always RAM-only)
- /run/          (runtime data)

Attackers use these locations because:
1. Files in /dev/shm exist only in RAM and vanish on reboot.
2. Many security tools ignore tmpfs mounts.
3. Crypto-miners and reverse shells are commonly staged here.

Also collects SSH artifacts:
- ~/.ssh/authorized_keys (lateral movement)
- ~/.ssh/known_hosts (connection history)
- /etc/passwd and /etc/sudoers (user/privilege anomalies)

Requires: root/sudo for cross-user access.
"""

import os
import hashlib
import stat
import glob
from datetime import datetime


# Directories to scan for in-memory malware drops
MEMORY_DIRS = [
    "/tmp",
    "/dev/shm",
    "/run/user",
    "/var/tmp",
]

# Suspicious file characteristics
SUSPICIOUS_EXTENSIONS = [
    ".sh", ".py", ".pl", ".rb", ".elf",
    ".so", ".bin", ".out",
]

SUSPICIOUS_FILENAMES = [
    "payload", "shell", "reverse", "miner", "xmrig",
    "kinsing", "cryptonight", "bot", "backdoor",
    "exploit", "pwn", "hack", "rootkit",
    "linpeas", "pspy", "chisel", "socat",
]


def collect(db, case_id):
    """
    Collect in-memory drops, SSH artifacts, and user anomalies.

    Args:
        db:       DBManager instance
        case_id:  Case identifier string

    Returns:
        list of dicts with collected entries
    """
    results = []

    # 1. Scan RAM-backed filesystems for malware drops
    results += _scan_memory_dirs(db, case_id)

    # 2. Collect SSH artifacts
    results += _collect_ssh_artifacts(db, case_id)

    # 3. Check for user anomalies
    results += _check_user_anomalies(db, case_id)

    print(f"    -> Collected {len(results)} in-memory drops / SSH / user anomaly entries.")
    return results


def _scan_memory_dirs(db, case_id):
    """Scan RAM-backed directories for suspicious files."""
    entries = []

    for mem_dir in MEMORY_DIRS:
        if not os.path.isdir(mem_dir):
            continue

        try:
            for root, dirs, files in os.walk(mem_dir):
                # Limit depth to avoid huge recursive walks
                depth = root.replace(mem_dir, "").count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue

                for filename in files:
                    filepath = os.path.join(root, filename)

                    try:
                        file_stat = os.stat(filepath)
                        file_size = file_stat.st_size
                        is_executable = bool(file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    except (OSError, PermissionError):
                        file_size = 0
                        is_executable = False

                    # Determine suspiciousness
                    suspicious_reasons = []

                    if is_executable:
                        suspicious_reasons.append("Executable")

                    name_lower = filename.lower()
                    for sus_name in SUSPICIOUS_FILENAMES:
                        if sus_name in name_lower:
                            suspicious_reasons.append(f"SuspiciousName:{sus_name}")

                    for ext in SUSPICIOUS_EXTENSIONS:
                        if name_lower.endswith(ext):
                            suspicious_reasons.append(f"SuspiciousExt:{ext}")

                    # If it has no extension and is executable, flag it
                    if is_executable and "." not in filename:
                        suspicious_reasons.append("NoExtension+Executable")

                    # Skip non-suspicious files to avoid noise
                    if not suspicious_reasons:
                        continue

                    # Calculate file hash
                    file_hash = _sha256(filepath)

                    raw_data = {
                        "filepath": filepath,
                        "filename": filename,
                        "directory": mem_dir,
                        "file_size": file_size,
                        "is_executable": is_executable,
                        "sha256": file_hash,
                        "suspicious_reasons": suspicious_reasons,
                        "timestamp": _get_file_mtime(filepath),
                    }

                    detail = f"[MEMORY DROP] {filepath} ({file_size} bytes) [{', '.join(suspicious_reasons)}]"

                    db.insert_evidence(
                        evidence_type="linux_memory_drop",
                        source=f"In-Memory Scan ({mem_dir})",
                        detail=detail[:250],
                        timestamp=raw_data["timestamp"],
                        raw_data=raw_data,
                        case_id=case_id,
                    )
                    entries.append(raw_data)

        except PermissionError:
            print(f"    [!] Permission denied: {mem_dir}")
        except Exception as e:
            print(f"    [!] Error scanning {mem_dir}: {e}")

    return entries


def _collect_ssh_artifacts(db, case_id):
    """Collect SSH authorized_keys and known_hosts from all users."""
    entries = []

    # Get all user home directories
    home_dirs = []
    if os.path.isdir("/root"):
        home_dirs.append(("/root", "root"))
    if os.path.isdir("/home"):
        for username in os.listdir("/home"):
            user_home = os.path.join("/home", username)
            if os.path.isdir(user_home):
                home_dirs.append((user_home, username))

    for home_dir, username in home_dirs:
        ssh_dir = os.path.join(home_dir, ".ssh")
        if not os.path.isdir(ssh_dir):
            continue

        # authorized_keys — who can log in as this user?
        auth_keys_path = os.path.join(ssh_dir, "authorized_keys")
        if os.path.isfile(auth_keys_path):
            try:
                with open(auth_keys_path, "r", errors="replace") as f:
                    for line_no, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue

                        # Extract the key comment (usually user@host)
                        parts = line.split()
                        key_comment = parts[-1] if len(parts) >= 3 else "unknown"
                        key_type = parts[0] if parts else "unknown"

                        raw_data = {
                            "username": username,
                            "key_type": key_type,
                            "key_comment": key_comment,
                            "line_number": line_no,
                            "file": auth_keys_path,
                            "category": "authorized_keys",
                            "timestamp": _get_file_mtime(auth_keys_path),
                        }

                        detail = f"[SSH AUTH KEY] User '{username}': {key_type} key from {key_comment}"

                        db.insert_evidence(
                            evidence_type="linux_memory_drop",
                            source="SSH authorized_keys",
                            detail=detail[:250],
                            timestamp=raw_data["timestamp"],
                            raw_data=raw_data,
                            case_id=case_id,
                        )
                        entries.append(raw_data)

            except PermissionError:
                print(f"    [!] Permission denied: {auth_keys_path}")

        # known_hosts — where has this user connected to?
        known_hosts_path = os.path.join(ssh_dir, "known_hosts")
        if os.path.isfile(known_hosts_path):
            try:
                with open(known_hosts_path, "r", errors="replace") as f:
                    hosts = [l.strip().split()[0] for l in f if l.strip() and not l.startswith("#")]

                if hosts:
                    raw_data = {
                        "username": username,
                        "host_count": len(hosts),
                        "hosts_sample": hosts[:20],
                        "file": known_hosts_path,
                        "category": "known_hosts",
                        "timestamp": _get_file_mtime(known_hosts_path),
                    }

                    detail = f"[SSH KNOWN HOSTS] User '{username}' has connected to {len(hosts)} host(s)"

                    db.insert_evidence(
                        evidence_type="linux_memory_drop",
                        source="SSH known_hosts",
                        detail=detail[:250],
                        timestamp=raw_data["timestamp"],
                        raw_data=raw_data,
                        case_id=case_id,
                    )
                    entries.append(raw_data)

            except PermissionError:
                print(f"    [!] Permission denied: {known_hosts_path}")

    return entries


def _check_user_anomalies(db, case_id):
    """Check /etc/passwd and /etc/sudoers for anomalies."""
    entries = []

    # Check /etc/passwd for UID 0 accounts (root-equivalent)
    passwd_path = "/etc/passwd"
    if os.path.isfile(passwd_path):
        try:
            with open(passwd_path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(":")
                    if len(parts) >= 4:
                        username = parts[0]
                        uid = parts[2]
                        shell = parts[-1] if len(parts) >= 7 else ""

                        # Flag UID 0 accounts that are NOT 'root'
                        if uid == "0" and username != "root":
                            raw_data = {
                                "username": username,
                                "uid": uid,
                                "shell": shell,
                                "category": "uid0_anomaly",
                                "timestamp": _get_file_mtime(passwd_path),
                            }

                            detail = f"[UID 0 ANOMALY] Non-root account '{username}' has UID 0 (root equivalent)!"

                            db.insert_evidence(
                                evidence_type="linux_memory_drop",
                                source="User Anomaly (/etc/passwd)",
                                detail=detail[:250],
                                timestamp=raw_data["timestamp"],
                                raw_data=raw_data,
                                case_id=case_id,
                            )
                            entries.append(raw_data)

                        # Flag accounts with login shells that shouldn't have them
                        # (e.g., service accounts with /bin/bash)
                        nologin_users = ["daemon", "bin", "sys", "games",
                                         "man", "lp", "mail", "news", "www-data",
                                         "nobody", "sshd", "postfix"]
                        if username in nologin_users and shell in ("/bin/bash", "/bin/sh", "/bin/zsh"):
                            raw_data = {
                                "username": username,
                                "uid": uid,
                                "shell": shell,
                                "category": "shell_anomaly",
                                "timestamp": _get_file_mtime(passwd_path),
                            }

                            detail = f"[SHELL ANOMALY] Service account '{username}' has login shell: {shell}"

                            db.insert_evidence(
                                evidence_type="linux_memory_drop",
                                source="User Anomaly (/etc/passwd)",
                                detail=detail[:250],
                                timestamp=raw_data["timestamp"],
                                raw_data=raw_data,
                                case_id=case_id,
                            )
                            entries.append(raw_data)

        except PermissionError:
            print(f"    [!] Permission denied: {passwd_path}")

    return entries


def _sha256(filepath, max_bytes=10 * 1024 * 1024):
    """Calculate SHA-256 hash of a file (up to max_bytes)."""
    try:
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha.update(chunk)
                if f.tell() > max_bytes:
                    break
        return sha.hexdigest()
    except (PermissionError, OSError):
        return "permission_denied"


def _get_file_mtime(filepath):
    """Get file modification time as ISO string."""
    try:
        mtime = os.path.getmtime(filepath)
        return datetime.fromtimestamp(mtime).isoformat()
    except Exception:
        return datetime.now().isoformat()
