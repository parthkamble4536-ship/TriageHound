"""
Linux System Logs Collector (v3.0)
=====================================
Collects Linux system and authentication logs:
- /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS)
- /var/log/syslog or /var/log/messages
- /var/log/dpkg.log (package installs - Debian)
- /var/log/yum.log or /var/log/dnf.log (package installs - RHEL)

Equivalent to Windows Event Logs (.evtx).

Requires: root/sudo for full log access.
"""

import os
import re
from datetime import datetime


# Log file paths (order of preference)
AUTH_LOG_PATHS = [
    "/var/log/auth.log",        # Debian / Ubuntu
    "/var/log/secure",          # RHEL / CentOS / Fedora
    "/var/log/auth.log.1",      # Rotated backup
]

SYSLOG_PATHS = [
    "/var/log/syslog",          # Debian / Ubuntu
    "/var/log/messages",        # RHEL / CentOS
    "/var/log/syslog.1",        # Rotated
]

PKG_LOG_PATHS = [
    "/var/log/dpkg.log",        # Debian / Ubuntu
    "/var/log/yum.log",         # RHEL / CentOS (old)
    "/var/log/dnf.log",         # Fedora / RHEL 8+
]

# Regex patterns for forensically relevant events
AUTH_PATTERNS = {
    "ssh_login_success": re.compile(r"Accepted\s+(password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)", re.IGNORECASE),
    "ssh_login_failed": re.compile(r"Failed\s+(password|publickey)\s+for\s+(invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)", re.IGNORECASE),
    "sudo_command": re.compile(r"(\S+)\s*:\s*.*COMMAND=(.*)", re.IGNORECASE),
    "user_added": re.compile(r"useradd.*?name=(\S+)", re.IGNORECASE),
    "user_deleted": re.compile(r"userdel.*?name=(\S+)", re.IGNORECASE),
    "su_switch": re.compile(r"su:\s.*?(\S+)\s+to\s+(\S+)", re.IGNORECASE),
    "session_opened": re.compile(r"session opened for user\s+(\S+)", re.IGNORECASE),
}

SYSLOG_PATTERNS = {
    "service_started": re.compile(r"Started\s+(.*)", re.IGNORECASE),
    "service_failed": re.compile(r"Failed\s+to\s+start\s+(.*)", re.IGNORECASE),
    "kernel_panic": re.compile(r"Kernel panic", re.IGNORECASE),
    "oom_kill": re.compile(r"Out of memory.*?Killed process\s+(\d+)", re.IGNORECASE),
    "usb_device": re.compile(r"usb\s+\d+-[\d.]+:\s+(.*)", re.IGNORECASE),
}

# Timestamp regex for standard syslog format: "Aug 21 14:30:01"
SYSLOG_TS_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


def collect(db, case_id):
    """
    Collect Linux system logs (auth, syslog, package manager).

    Args:
        db:       DBManager instance
        case_id:  Case identifier string

    Returns:
        list of dicts with collected log entries
    """
    results = []

    # 1. Auth / Secure logs
    results += _parse_log_file(db, case_id, AUTH_LOG_PATHS, AUTH_PATTERNS, "auth_log")

    # 2. Syslog / messages
    results += _parse_log_file(db, case_id, SYSLOG_PATHS, SYSLOG_PATTERNS, "syslog")

    # 3. Package manager logs
    results += _parse_package_logs(db, case_id)

    print(f"    -> Collected {len(results)} system log entries.")
    return results


def _parse_log_file(db, case_id, file_paths, patterns, log_category):
    """Parse a log file using regex patterns, trying multiple paths."""
    entries = []

    log_path = None
    for path in file_paths:
        if os.path.isfile(path):
            log_path = path
            break

    if not log_path:
        print(f"    [!] No {log_category} log found at expected paths.")
        return entries

    try:
        with open(log_path, "r", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                for event_type, pattern in patterns.items():
                    match = pattern.search(line)
                    if match:
                        timestamp = _extract_timestamp(line)

                        raw_data = {
                            "event_type": event_type,
                            "category": log_category,
                            "line_number": line_no,
                            "log_file": log_path,
                            "raw_line": line[:500],
                            "match_groups": match.groups(),
                            "timestamp": timestamp,
                        }

                        # Build human-readable detail
                        detail = _build_detail(event_type, match, line)

                        db.insert_evidence(
                            evidence_type="linux_system_log",
                            source=f"Linux Log ({log_category})",
                            detail=detail[:250],
                            timestamp=timestamp,
                            raw_data=raw_data,
                            case_id=case_id,
                        )
                        entries.append(raw_data)
                        break  # Only match first pattern per line

    except PermissionError:
        print(f"    [!] Permission denied: {log_path}. Run with sudo.")
    except Exception as e:
        print(f"    [!] Error reading {log_path}: {e}")

    return entries


def _parse_package_logs(db, case_id):
    """Parse package manager logs to detect installed tools."""
    entries = []

    # Suspicious packages an attacker might install
    suspicious_pkgs = [
        "nmap", "masscan", "netcat", "ncat", "nc", "socat",
        "tcpdump", "wireshark", "hydra", "john", "hashcat",
        "metasploit", "aircrack", "nikto", "sqlmap",
        "proxychains", "tor", "openvpn",
        "gcc", "make", "python3-pip",  # compilation tools
    ]

    for pkg_path in PKG_LOG_PATHS:
        if not os.path.isfile(pkg_path):
            continue

        try:
            with open(pkg_path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # dpkg.log format: "2026-08-01 10:00:00 install package_name ..."
                    # yum.log format: "Aug 01 10:00:00 Installed: package_name..."
                    line_lower = line.lower()

                    if "install" in line_lower:
                        is_suspicious = any(pkg in line_lower for pkg in suspicious_pkgs)
                        timestamp = _extract_timestamp(line)

                        raw_data = {
                            "event_type": "package_install",
                            "category": "package_manager",
                            "log_file": pkg_path,
                            "raw_line": line[:500],
                            "suspicious": is_suspicious,
                            "timestamp": timestamp,
                        }

                        if is_suspicious:
                            detail = f"[SUSPICIOUS PKG] {line[:150]}"
                        else:
                            detail = f"[PKG INSTALL] {line[:150]}"

                        db.insert_evidence(
                            evidence_type="linux_system_log",
                            source=f"Package Manager ({os.path.basename(pkg_path)})",
                            detail=detail[:250],
                            timestamp=timestamp,
                            raw_data=raw_data,
                            case_id=case_id,
                        )
                        entries.append(raw_data)

        except PermissionError:
            print(f"    [!] Permission denied: {pkg_path}")
        except Exception as e:
            print(f"    [!] Error reading {pkg_path}: {e}")

    return entries


def _extract_timestamp(line):
    """Extract timestamp from a syslog line. Falls back to current time."""
    # Try syslog format: "Aug 21 14:30:01"
    m = SYSLOG_TS_PATTERN.match(line)
    if m:
        try:
            ts_str = m.group(1)
            year = datetime.now().year
            return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S").isoformat()
        except ValueError:
            pass

    # Try ISO format: "2026-08-21 14:30:01"
    iso_match = re.match(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
    if iso_match:
        return iso_match.group(1).replace(" ", "T")

    return datetime.now().isoformat()


def _build_detail(event_type, match, line):
    """Build a human-readable detail string from the match."""
    groups = match.groups()

    if event_type == "ssh_login_success":
        return f"SSH Login: {groups[1]} from {groups[2]} (port {groups[3]}) via {groups[0]}"
    elif event_type == "ssh_login_failed":
        user = groups[2] if len(groups) >= 3 else "unknown"
        ip = groups[3] if len(groups) >= 4 else "unknown"
        return f"SSH FAILED: {user} from {ip}"
    elif event_type == "sudo_command":
        return f"SUDO: {groups[0]} ran: {groups[1][:100]}"
    elif event_type == "user_added":
        return f"User CREATED: {groups[0]}"
    elif event_type == "user_deleted":
        return f"User DELETED: {groups[0]}"
    elif event_type == "su_switch":
        return f"SU: {groups[0]} switched to {groups[1]}"
    elif event_type == "session_opened":
        return f"Session opened for: {groups[0]}"
    else:
        return f"[{event_type}] {line[:150]}"
