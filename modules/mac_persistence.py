"""
macOS Persistence Collector (v2.0)
=====================================
Collects persistence mechanisms from macOS systems:
- LaunchDaemons (/Library/LaunchDaemons)
- LaunchAgents (/Library/LaunchAgents, ~/Library/LaunchAgents)
- Login Items (com.apple.loginitems.plist)

Equivalent to Windows Startup Programs / Registry Run keys.

Requires: sudo for system-level LaunchDaemons.
"""

import os
import plistlib
import glob


# Paths to scan for persistence plists
SYSTEM_LAUNCH_DAEMONS = "/Library/LaunchDaemons"
SYSTEM_LAUNCH_AGENTS = "/Library/LaunchAgents"
USER_LAUNCH_AGENTS_PATTERN = "/Users/*/Library/LaunchAgents"
LOGIN_ITEMS_PATTERN = "/Users/*/Library/Preferences/com.apple.loginitems.plist"


def collect(db, case_id):
    """
    Collect all macOS persistence artifacts (LaunchDaemons, LaunchAgents, Login Items).

    Args:
        db:       DBManager instance
        case_id:  Case identifier string

    Returns:
        list of dicts with persistence entries
    """
    results = []

    # 1. System LaunchDaemons
    results += _scan_plist_dir(db, case_id, SYSTEM_LAUNCH_DAEMONS, "LaunchDaemon")

    # 2. System LaunchAgents
    results += _scan_plist_dir(db, case_id, SYSTEM_LAUNCH_AGENTS, "LaunchAgent (System)")

    # 3. Per-user LaunchAgents
    for user_dir in glob.glob(USER_LAUNCH_AGENTS_PATTERN):
        user = user_dir.split("/Users/")[1].split("/")[0]
        results += _scan_plist_dir(db, case_id, user_dir, f"LaunchAgent (User: {user})")

    # 4. Login Items
    results += _collect_login_items(db, case_id)

    print(f"    -> Collected {len(results)} persistence entries.")
    return results


def _scan_plist_dir(db, case_id, directory, category):
    """Scan a directory of .plist files and extract persistence info."""
    entries = []

    if not os.path.isdir(directory):
        return entries

    for plist_file in os.listdir(directory):
        if not plist_file.endswith(".plist"):
            continue

        full_path = os.path.join(directory, plist_file)
        try:
            with open(full_path, "rb") as f:
                plist_data = plistlib.load(f)

            label = plist_data.get("Label", plist_file)
            program = plist_data.get("Program", "")
            program_args = plist_data.get("ProgramArguments", [])
            run_at_load = plist_data.get("RunAtLoad", False)
            keep_alive = plist_data.get("KeepAlive", False)
            disabled = plist_data.get("Disabled", False)

            # Build the command line from ProgramArguments
            if program_args:
                cmd_line = " ".join(str(a) for a in program_args)
            elif program:
                cmd_line = program
            else:
                cmd_line = "(no program specified)"

            # Flag suspicious indicators
            suspicious_flags = []
            if run_at_load:
                suspicious_flags.append("RunAtLoad=True")
            if keep_alive:
                suspicious_flags.append("KeepAlive=True")
            # Check for common attacker patterns
            for keyword in ["curl", "wget", "python", "bash", "sh", "osascript", "base64", "/tmp/"]:
                if keyword in cmd_line.lower():
                    suspicious_flags.append(f"SuspiciousCmd:{keyword}")

            raw_data = {
                "label": label,
                "plist_path": full_path,
                "category": category,
                "program": program,
                "program_arguments": program_args,
                "command_line": cmd_line,
                "run_at_load": run_at_load,
                "keep_alive": keep_alive,
                "disabled": disabled,
                "suspicious_flags": suspicious_flags,
            }

            detail = f"[{category}] {label}: {cmd_line[:120]}"
            if suspicious_flags:
                detail += f" [FLAGS: {', '.join(suspicious_flags)}]"

            db.insert_evidence(
                evidence_type="mac_persistence",
                source=f"plist ({category})",
                detail=detail,
                timestamp=_get_file_mtime(full_path),
                raw_data=raw_data,
                case_id=case_id,
            )
            entries.append(raw_data)

        except plistlib.InvalidFileException:
            print(f"    [!] Invalid plist: {full_path}")
        except PermissionError:
            print(f"    [!] Permission denied: {full_path}")
        except Exception as e:
            print(f"    [!] Error parsing {full_path}: {e}")

    return entries


def _collect_login_items(db, case_id):
    """Collect Login Items from per-user preferences."""
    entries = []

    for plist_path in glob.glob(LOGIN_ITEMS_PATTERN):
        user = plist_path.split("/Users/")[1].split("/")[0]
        try:
            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)

            # Login Items are stored under SessionItems -> CustomListItems
            session_items = plist_data.get("SessionItems", {})
            custom_items = session_items.get("CustomListItems", [])

            for item in custom_items:
                name = item.get("Name", "Unknown")
                alias = item.get("Alias", b"")

                raw_data = {
                    "name": name,
                    "user": user,
                    "category": "LoginItem",
                    "plist_path": plist_path,
                }

                db.insert_evidence(
                    evidence_type="mac_persistence",
                    source="Login Items",
                    detail=f"[LoginItem] User '{user}': {name}",
                    timestamp=_get_file_mtime(plist_path),
                    raw_data=raw_data,
                    case_id=case_id,
                )
                entries.append(raw_data)

        except Exception as e:
            print(f"    [!] Error reading login items for {user}: {e}")

    return entries


def _get_file_mtime(filepath):
    """Get file modification time as ISO string."""
    try:
        mtime = os.path.getmtime(filepath)
        from datetime import datetime
        return datetime.fromtimestamp(mtime).isoformat()
    except Exception:
        from datetime import datetime
        return datetime.now().isoformat()
