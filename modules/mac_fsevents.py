"""
macOS FSEvents Collector (v2.0)
==================================
Parses macOS FSEvents records from /.fseventsd/ to track file system
activity (creations, deletions, renames, permission changes).

Equivalent to Windows USN Journal.

Requires: sudo + Full Disk Access for /.fseventsd/ access.
"""

import os
import gzip
import struct
from datetime import datetime


# FSEvent flags (from Apple's FSEvents documentation)
FS_FLAGS = {
    0x00000001: "Created",
    0x00000002: "Removed",
    0x00000004: "InodeMetaMod",
    0x00000008: "Renamed",
    0x00000010: "Modified",
    0x00000020: "FinderInfoMod",
    0x00000040: "ChangeOwner",
    0x00000080: "XattrMod",
    0x00000100: "IsFile",
    0x00000200: "IsDir",
    0x00000400: "IsSymlink",
    0x00001000: "IsHardlink",
    0x00002000: "IsLastHardlink",
    0x00010000: "Mount",
    0x00020000: "Unmount",
    0x00800000: "ItemCloned",
}

FSEVENTSD_PATH = "/.fseventsd"

# DLS (Database Log Stream) header magic
DLS_MAGIC_V1 = b"1SLD"
DLS_MAGIC_V2 = b"2SLD"


def collect(db, case_id, max_files=50):
    """
    Collect and parse macOS FSEvents records.

    Args:
        db:         DBManager instance
        case_id:    Case identifier string
        max_files:  Maximum number of .gz log files to parse (default: 50)

    Returns:
        list of dicts with FSEvent entries
    """
    results = []

    if not os.path.isdir(FSEVENTSD_PATH):
        print("    [!] /.fseventsd/ not found. Ensure sudo and Full Disk Access are granted.")
        return results

    try:
        log_files = sorted(
            [f for f in os.listdir(FSEVENTSD_PATH)
             if not f.startswith(".") and f not in ("fseventsd-uuid", "no_log")],
            reverse=True
        )[:max_files]
    except PermissionError:
        print("    [!] Permission denied reading /.fseventsd/. Run with sudo.")
        return results

    for log_file in log_files:
        full_path = os.path.join(FSEVENTSD_PATH, log_file)
        try:
            entries = _parse_fsevent_file(full_path)
            for entry in entries:
                flags_str = _decode_flags(entry["flags"])
                raw_data = {
                    "filename": entry["path"],
                    "event_id": entry["event_id"],
                    "flags": entry["flags"],
                    "flags_decoded": flags_str,
                    "source_file": log_file,
                }

                # Filter for forensically interesting events
                if not _is_interesting(entry["path"], entry["flags"]):
                    continue

                detail = f"FSEvent: {entry['path']} [{flags_str}]"

                db.insert_evidence(
                    evidence_type="mac_fsevents",
                    source="FSEvents (/.fseventsd/)",
                    detail=detail[:250],
                    timestamp=datetime.now().isoformat(),
                    raw_data=raw_data,
                    case_id=case_id,
                )
                results.append(raw_data)

        except PermissionError:
            print(f"    [!] Permission denied: {full_path}")
        except Exception as e:
            print(f"    [!] Error parsing {log_file}: {e}")

    print(f"    -> Collected {len(results)} interesting FSEvent entries from {len(log_files)} log files.")
    return results


def _parse_fsevent_file(filepath):
    """
    Parse a single FSEvent gzip-compressed log file.

    FSEvent files are gzip-compressed and contain a DLS header followed
    by a sequence of records. Each record has:
    - Null-terminated file path (variable length)
    - 8-byte event_id (uint64, little-endian)
    - 4-byte flags (uint32, little-endian)
    """
    records = []

    try:
        with gzip.open(filepath, "rb") as f:
            data = f.read()
    except gzip.BadGzipFile:
        # Some files may not be gzip compressed
        with open(filepath, "rb") as f:
            data = f.read()

    if len(data) < 12:
        return records

    # Check for DLS magic header
    magic = data[:4]
    if magic not in (DLS_MAGIC_V1, DLS_MAGIC_V2):
        return records

    # Skip the 12-byte DLS header (magic + unknown bytes)
    offset = 12

    while offset < len(data) - 12:
        try:
            # Find the null-terminated path string
            null_pos = data.index(b"\x00", offset)
            path_bytes = data[offset:null_pos]

            try:
                path = path_bytes.decode("utf-8", errors="replace")
            except Exception:
                path = path_bytes.decode("ascii", errors="replace")

            # After the null byte, read event_id (8 bytes) and flags (4 bytes)
            record_offset = null_pos + 1

            if record_offset + 12 > len(data):
                break

            event_id = struct.unpack("<Q", data[record_offset:record_offset + 8])[0]
            flags = struct.unpack("<I", data[record_offset + 8:record_offset + 12])[0]

            records.append({
                "path": path,
                "event_id": event_id,
                "flags": flags,
            })

            offset = record_offset + 12

        except (ValueError, struct.error):
            break

    return records


def _decode_flags(flags):
    """Decode FSEvent flags bitmask into human-readable string."""
    decoded = []
    for bit, name in FS_FLAGS.items():
        if flags & bit:
            decoded.append(name)
    return ", ".join(decoded) if decoded else f"Unknown(0x{flags:08x})"


def _is_interesting(path, flags):
    """
    Filter for forensically interesting FSEvents.
    We care about: executables, scripts, persistence dirs, tmp files.
    """
    path_lower = path.lower()

    # Always include removals and creations
    is_created = flags & 0x00000001
    is_removed = flags & 0x00000002

    # Interesting paths
    interesting_dirs = [
        "/tmp/", "/private/tmp/", "/dev/shm",
        "/library/launchdaemons/", "/library/launchagents/",
        "launchagents/", "launchdaemons/",
        "/applications/", "/usr/local/bin/",
        ".ssh/", ".bash_profile", ".zshrc",
        "/downloads/", "cron",
    ]

    interesting_extensions = [
        ".sh", ".py", ".rb", ".pl", ".dylib", ".so",
        ".app", ".command", ".pkg", ".dmg",
        ".plist", ".scpt",
    ]

    for d in interesting_dirs:
        if d in path_lower:
            return True

    for ext in interesting_extensions:
        if path_lower.endswith(ext):
            return True

    # Always include created or removed executables
    if (is_created or is_removed) and (
        path_lower.endswith(".app") or
        "/bin/" in path_lower or
        "/sbin/" in path_lower
    ):
        return True

    return False
