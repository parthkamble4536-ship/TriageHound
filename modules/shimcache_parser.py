r"""
ShimCache (AppCompatCache) Parser
==================================
Parses the Application Compatibility Cache from the SYSTEM registry hive.

Location: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

ShimCache records programs that were executed or shimmed by Windows. It
survives reboots and is harder to wipe than Prefetch — making it a second
independent source of execution evidence.

Combined with Prefetch, this gives two independent ways to prove a program
ran on the system.
"""

import struct
import os
from datetime import datetime, timedelta

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False


def _filetime_to_iso(filetime):
    """Convert Windows FILETIME to ISO datetime string."""
    if not filetime or filetime == 0:
        return None
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _parse_win10_cache(data):
    """
    Parse Windows 10/11 AppCompatCache format.

    Win10 format (header signature '10ts' at offset 48-51):
      - Header: 48 bytes (signature at byte 48 = 0x30747331 '10ts')
      - Entries start at offset 52
      - Each entry:
          Signature (4) + unknown (4) + DataSize (4) + PathSize (2) +
          Path (variable, UTF-16LE) + LastModified (8) + DataFieldSize (4) +
          Data (variable)
    """
    entries = []

    # Try to find the start of entries
    # Win10 header is 52 bytes, entries start after
    offset = 52
    if len(data) < offset:
        return entries

    position = 0
    while offset < len(data) - 12:
        try:
            # Read signature — should be '10ts' (0x73743031)
            sig = struct.unpack_from('<I', data, offset)[0]
            if sig != 0x73743031:
                # Try alternate: some Win10 builds don't have per-entry sigs
                break

            # Skip sig (4) + unknown (4)
            entry_offset = offset + 8

            # DataSize (4)
            cache_entry_data_size = struct.unpack_from('<I', data, entry_offset)[0]
            entry_offset += 4

            # PathSize in bytes (2)
            path_size = struct.unpack_from('<H', data, entry_offset)[0]
            entry_offset += 2

            # Path (UTF-16LE)
            if entry_offset + path_size > len(data):
                break
            path = data[entry_offset:entry_offset + path_size]
            path = path.decode('utf-16-le', errors='replace').rstrip('\x00')
            entry_offset += path_size

            # LastModified FILETIME (8)
            if entry_offset + 8 > len(data):
                break
            last_modified_ft = struct.unpack_from('<Q', data, entry_offset)[0]
            last_modified = _filetime_to_iso(last_modified_ft)
            entry_offset += 8

            # DataFieldSize (4) + Data (variable)
            if entry_offset + 4 > len(data):
                break
            data_field_size = struct.unpack_from('<I', data, entry_offset)[0]
            entry_offset += 4 + data_field_size

            entries.append({
                'executable_path': path,
                'last_modified': last_modified,
                'cache_position': position,
                'source': 'ShimCache (AppCompatCache)',
            })

            offset = entry_offset
            position += 1

        except (struct.error, UnicodeDecodeError):
            break

    return entries


def _parse_win8_cache(data):
    """
    Parse Windows 8/8.1 AppCompatCache format.

    Header: 128 bytes, entries start at offset 128.
    Each entry:
        PathLength (4) + Path (variable, UTF-16LE, null-padded) +
        LastModified (8) + DataSize (4) + Data (variable)
    """
    entries = []
    offset = 128
    position = 0

    while offset < len(data) - 12:
        try:
            # Signature check '00ts'
            sig = struct.unpack_from('<I', data, offset)[0]
            if sig != 0x73743030:
                break

            # Skip signature (4) + unknown (4)
            entry_offset = offset + 8

            # Unknown (4)
            entry_offset += 4

            # PathSize in bytes (2)
            path_size = struct.unpack_from('<H', data, entry_offset)[0]
            entry_offset += 2

            # Path
            if entry_offset + path_size > len(data):
                break
            path = data[entry_offset:entry_offset + path_size]
            path = path.decode('utf-16-le', errors='replace').rstrip('\x00')
            entry_offset += path_size

            # LastModified FILETIME (8)
            if entry_offset + 8 > len(data):
                break
            last_modified_ft = struct.unpack_from('<Q', data, entry_offset)[0]
            last_modified = _filetime_to_iso(last_modified_ft)
            entry_offset += 8

            # DataSize (4) + Data
            if entry_offset + 4 > len(data):
                break
            data_size = struct.unpack_from('<I', data, entry_offset)[0]
            entry_offset += 4 + data_size

            entries.append({
                'executable_path': path,
                'last_modified': last_modified,
                'cache_position': position,
                'source': 'ShimCache (AppCompatCache)',
            })

            offset = entry_offset
            position += 1

        except (struct.error, UnicodeDecodeError):
            break

    return entries


def _parse_win7_cache(data):
    """
    Parse Windows 7 AppCompatCache format.

    Header: 128 bytes with entry count at offset 4.
    Each entry (fixed 552 bytes for 32-bit, 832 bytes for 64-bit):
        Path (520 bytes UTF-16LE, null-padded) + LastModified (8) +
        InsertFlags (4) + ShimFlags (4) + DataSize (4) + DataOffset (4)
    """
    entries = []
    if len(data) < 8:
        return entries

    num_entries = struct.unpack_from('<I', data, 4)[0]
    if num_entries > 2000:
        num_entries = 2000

    offset = 128
    entry_size = 552  # 64-bit Win7 typically uses 552

    for i in range(num_entries):
        if offset + entry_size > len(data):
            break

        try:
            # Path: 520 bytes of UTF-16LE
            path = data[offset:offset + 520]
            path = path.decode('utf-16-le', errors='replace').rstrip('\x00')

            # LastModified FILETIME at offset + 520
            last_modified_ft = struct.unpack_from('<Q', data, offset + 520)[0]
            last_modified = _filetime_to_iso(last_modified_ft)

            if path and path.strip():
                entries.append({
                    'executable_path': path,
                    'last_modified': last_modified,
                    'cache_position': i,
                    'source': 'ShimCache (AppCompatCache)',
                })

        except (struct.error, UnicodeDecodeError):
            pass

        offset += entry_size

    return entries


def collect_shimcache():
    """
    Parse the ShimCache (AppCompatCache) from the SYSTEM registry hive.

    Returns:
        list of dicts with executable_path, last_modified, cache_position.
        Empty list if not on Windows or insufficient permissions.
    """
    if not WINREG_AVAILABLE:
        return []

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        )
        value, reg_type = winreg.QueryValueEx(key, "AppCompatCache")
        winreg.CloseKey(key)
    except (OSError, WindowsError, PermissionError):
        return []

    if not value or len(value) < 52:
        return []

    data = bytes(value)

    # Detect format by checking header signature
    header_sig = struct.unpack_from('<I', data, 0)[0]

    # Windows 10/11: header starts with 0x30 (48 decimal) at offset 0
    # and '10ts' at offset 48
    if len(data) > 52:
        try:
            sig_at_48 = struct.unpack_from('<I', data, 48)[0]
            if sig_at_48 == 0x73743031:  # '10ts'
                return _parse_win10_cache(data)
        except struct.error:
            pass

    # Windows 8/8.1: look for '00ts' at offset 128
    if len(data) > 132:
        try:
            sig_at_128 = struct.unpack_from('<I', data, 128)[0]
            if sig_at_128 == 0x73743030:  # '00ts'
                return _parse_win8_cache(data)
        except struct.error:
            pass

    # Windows 7: header signature 0xEE (238)
    if header_sig == 0xEE:
        return _parse_win7_cache(data)

    # Fallback: try Win10 format
    entries = _parse_win10_cache(data)
    if entries:
        return entries

    # Last resort: try Win7 format
    return _parse_win7_cache(data)
