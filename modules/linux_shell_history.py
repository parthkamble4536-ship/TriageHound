"""
Linux Shell History Collector (v3.0)
=======================================
Collects command history from all users:
- ~/.bash_history (Bash shell)
- ~/.zsh_history (Zsh shell)
- ~/.viminfo (Vim editor - files edited)
- ~/.lesshst (less pager - files viewed)

Equivalent to Windows Prefetch (tracks executed commands).

Requires: root/sudo for cross-user access.
"""

import os
import re
import glob
from datetime import datetime


# Suspicious command keywords for forensic detection
SUSPICIOUS_COMMANDS = [
    # Reconnaissance
    "whoami", "id", "uname", "hostname", "ifconfig", "ip addr",
    "cat /etc/passwd", "cat /etc/shadow", "cat /etc/sudoers",
    "netstat", "ss -", "lsof", "ps aux", "w ", "last",
    # Lateral Movement
    "ssh ", "scp ", "rsync", "nc ", "ncat", "socat",
    "curl ", "wget ", "python -m http", "python3 -m http",
    # Privilege Escalation
    "sudo ", "su ", "chmod +s", "chmod 4", "chown root",
    "find / -perm", "find / -writable", "getcap",
    # Persistence
    "crontab", "systemctl enable", "echo >> /etc",
    ".bashrc", ".bash_profile", ".zshrc",
    # Data Exfiltration
    "tar czf", "zip ", "base64", "openssl enc",
    "nc -l", "python -c", "python3 -c",
    # Anti-Forensics
    "history -c", "shred", "rm -rf /var/log",
    "unset HISTFILE", "export HISTSIZE=0",
    "truncate", "wipe",
    # Offensive tools
    "nmap", "masscan", "hydra", "nikto", "sqlmap",
    "metasploit", "msfconsole", "msfvenom",
    "hashcat", "john", "aircrack",
]


def collect(db, case_id):
    """
    Collect shell history, vim history, and less history from all users.

    Args:
        db:       DBManager instance
        case_id:  Case identifier string

    Returns:
        list of dicts with history entries
    """
    results = []

    # Get all user home directories
    home_dirs = _get_all_home_dirs()

    for home_dir, username in home_dirs:
        # Bash history
        results += _parse_shell_history(db, case_id, home_dir, username,
                                         ".bash_history", "bash")
        # Zsh history
        results += _parse_shell_history(db, case_id, home_dir, username,
                                         ".zsh_history", "zsh")
        # Vim history (files edited)
        results += _parse_viminfo(db, case_id, home_dir, username)

        # Less history (files viewed)
        results += _parse_lesshst(db, case_id, home_dir, username)

    print(f"    -> Collected {len(results)} shell/editor history entries across {len(home_dirs)} users.")
    return results


def _get_all_home_dirs():
    """Get all user home directories from /etc/passwd and /root."""
    homes = []

    # Root user
    if os.path.isdir("/root"):
        homes.append(("/root", "root"))

    # All users in /home/
    if os.path.isdir("/home"):
        for username in os.listdir("/home"):
            user_home = os.path.join("/home", username)
            if os.path.isdir(user_home):
                homes.append((user_home, username))

    return homes


def _parse_shell_history(db, case_id, home_dir, username, filename, shell_type):
    """Parse a shell history file (bash or zsh)."""
    entries = []
    history_path = os.path.join(home_dir, filename)

    if not os.path.isfile(history_path):
        return entries

    try:
        with open(history_path, "r", errors="replace") as f:
            lines = f.readlines()

        timestamp = None
        cmd_index = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Zsh extended history format: ": 1234567890:0;command"
            zsh_match = re.match(r"^:\s*(\d+):\d+;(.+)", line)
            if zsh_match:
                ts_epoch = int(zsh_match.group(1))
                command = zsh_match.group(2)
                timestamp = datetime.fromtimestamp(ts_epoch).isoformat()
            # Bash timestamp marker: "#1234567890"
            elif line.startswith("#") and line[1:].strip().isdigit():
                try:
                    ts_epoch = int(line[1:].strip())
                    timestamp = datetime.fromtimestamp(ts_epoch).isoformat()
                except (ValueError, OSError):
                    pass
                continue
            else:
                command = line

            cmd_index += 1

            # Check if command is suspicious
            is_suspicious = _is_suspicious(command)

            raw_data = {
                "command": command,
                "username": username,
                "shell": shell_type,
                "history_file": history_path,
                "command_index": cmd_index,
                "timestamp": timestamp or _get_file_mtime(history_path),
                "suspicious": is_suspicious,
            }

            if is_suspicious:
                detail = f"[SUSPICIOUS] User '{username}' ({shell_type}): {command[:150]}"
            else:
                detail = f"[{shell_type}] User '{username}': {command[:150]}"

            db.insert_evidence(
                evidence_type="linux_shell_history",
                source=f"Shell History ({shell_type})",
                detail=detail[:250],
                timestamp=raw_data["timestamp"],
                raw_data=raw_data,
                case_id=case_id,
            )
            entries.append(raw_data)

    except PermissionError:
        print(f"    [!] Permission denied: {history_path}")
    except Exception as e:
        print(f"    [!] Error reading {history_path}: {e}")

    return entries


def _parse_viminfo(db, case_id, home_dir, username):
    """Parse .viminfo to find files edited by the user."""
    entries = []
    viminfo_path = os.path.join(home_dir, ".viminfo")

    if not os.path.isfile(viminfo_path):
        return entries

    try:
        with open(viminfo_path, "r", errors="replace") as f:
            in_file_marks = False
            for line in f:
                line = line.strip()

                # File marks section starts with "# File marks:"
                if line.startswith("# File marks:"):
                    in_file_marks = True
                    continue

                if in_file_marks:
                    # File mark lines start with "'" followed by a marker
                    # Format: '0  1234  567  /path/to/file
                    if line.startswith("'"):
                        parts = line.split()
                        if len(parts) >= 4:
                            filepath = parts[-1]

                            # Check if this is a sensitive file
                            sensitive_files = [
                                "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                                "/etc/ssh/", "/etc/crontab", ".bashrc",
                                ".ssh/", "authorized_keys",
                            ]
                            is_sensitive = any(s in filepath for s in sensitive_files)

                            raw_data = {
                                "file_edited": filepath,
                                "username": username,
                                "category": "viminfo",
                                "sensitive": is_sensitive,
                                "timestamp": _get_file_mtime(viminfo_path),
                            }

                            prefix = "[SENSITIVE FILE EDITED]" if is_sensitive else "[vim]"
                            detail = f"{prefix} User '{username}' edited: {filepath}"

                            db.insert_evidence(
                                evidence_type="linux_shell_history",
                                source="Vim History (.viminfo)",
                                detail=detail[:250],
                                timestamp=raw_data["timestamp"],
                                raw_data=raw_data,
                                case_id=case_id,
                            )
                            entries.append(raw_data)

                    elif line.startswith("#") and "marks" not in line.lower():
                        in_file_marks = False

    except PermissionError:
        print(f"    [!] Permission denied: {viminfo_path}")
    except Exception as e:
        print(f"    [!] Error reading {viminfo_path}: {e}")

    return entries


def _parse_lesshst(db, case_id, home_dir, username):
    """Parse .lesshst to find files viewed with 'less' pager."""
    entries = []
    lesshst_path = os.path.join(home_dir, ".lesshst")

    if not os.path.isfile(lesshst_path):
        return entries

    try:
        with open(lesshst_path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                # .lesshst lines are just file paths or search strings
                if line.startswith("/") or line.startswith("~"):
                    raw_data = {
                        "file_viewed": line,
                        "username": username,
                        "category": "lesshst",
                        "timestamp": _get_file_mtime(lesshst_path),
                    }

                    detail = f"[less] User '{username}' viewed: {line}"

                    db.insert_evidence(
                        evidence_type="linux_shell_history",
                        source="Less History (.lesshst)",
                        detail=detail[:250],
                        timestamp=raw_data["timestamp"],
                        raw_data=raw_data,
                        case_id=case_id,
                    )
                    entries.append(raw_data)

    except PermissionError:
        print(f"    [!] Permission denied: {lesshst_path}")
    except Exception as e:
        print(f"    [!] Error reading {lesshst_path}: {e}")

    return entries


def _is_suspicious(command):
    """Check if a shell command matches known suspicious patterns."""
    cmd_lower = command.lower()
    return any(keyword in cmd_lower for keyword in SUSPICIOUS_COMMANDS)


def _get_file_mtime(filepath):
    """Get file modification time as ISO string."""
    try:
        mtime = os.path.getmtime(filepath)
        return datetime.fromtimestamp(mtime).isoformat()
    except Exception:
        return datetime.now().isoformat()
