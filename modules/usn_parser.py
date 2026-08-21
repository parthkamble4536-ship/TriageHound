r"""
USN Journal Parser
===================
Parses the NTFS USN (Update Sequence Number) Journal ($Extend\$UsnJrnl:$J)
to extract a rolling log of every file system change on the volume.

Even if an attacker deletes their malware, wipes Prefetch, AND clears
Amcache, the USN Journal often still records that the file existed.

Requires Administrator privileges for raw disk access.
"""

import ctypes
try:
    import ctypes.wintypes
except ImportError:
    pass
import struct
import os
from datetime import datetime, timedelta


# ── Windows constants ─────────────────────────────────────────────────────────
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL = 0x000900BB
FSCTL_ENUM_USN_DATA = 0x000900B3

# USN Reason flags
USN_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}


def _decode_reasons(reason_flags):
    """Decode USN reason bitmask into a list of human-readable reason strings."""
    reasons = []
    for flag, name in USN_REASONS.items():
        if reason_flags & flag:
            reasons.append(name)
    return reasons


def _filetime_to_datetime(filetime):
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to ISO string."""
    if not filetime or filetime == 0:
        return None
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _open_volume(volume_letter):
    """Open a raw handle to the NTFS volume. Requires Admin."""
    volume_path = fr"\\.\{volume_letter}:"

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        volume_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    if handle == -1 or handle == 0xFFFFFFFFFFFFFFFF:
        return None
    return handle


def _query_usn_journal(handle):
    """Query the USN journal metadata to get the journal ID and bounds."""
    kernel32 = ctypes.windll.kernel32

    # USN_JOURNAL_DATA_V0 structure (64 bytes)
    output_buffer = ctypes.create_string_buffer(64)
    bytes_returned = ctypes.wintypes.DWORD(0)

    result = kernel32.DeviceIoControl(
        handle,
        FSCTL_QUERY_USN_JOURNAL,
        None, 0,
        output_buffer, 64,
        ctypes.byref(bytes_returned),
        None
    )

    if not result:
        return None

    # Parse USN_JOURNAL_DATA: UsnJournalID (8), FirstUsn (8), NextUsn (8), ...
    journal_id = struct.unpack_from('<Q', output_buffer.raw, 0)[0]
    first_usn = struct.unpack_from('<Q', output_buffer.raw, 8)[0]
    next_usn = struct.unpack_from('<Q', output_buffer.raw, 16)[0]

    return {
        'journal_id': journal_id,
        'first_usn': first_usn,
        'next_usn': next_usn,
    }


def _read_usn_records(handle, journal_id, start_usn, max_entries=5000):
    """Read USN records from the journal using FSCTL_READ_USN_JOURNAL."""
    kernel32 = ctypes.windll.kernel32
    records = []

    # READ_USN_JOURNAL_DATA_V0 input structure:
    #   StartUsn (8) + ReasonMask (4) + ReturnOnlyOnClose (4) +
    #   Timeout (8) + BytesToWaitFor (8) + UsnJournalID (8) = 40 bytes
    reason_mask = 0xFFFFFFFF  # All reasons
    input_buffer = struct.pack('<QIIQqQ',
                               start_usn,
                               reason_mask,
                               0,          # ReturnOnlyOnClose = False
                               0,          # Timeout
                               0,          # BytesToWaitFor
                               journal_id)

    output_size = 65536  # 64KB read buffer
    output_buffer = ctypes.create_string_buffer(output_size)
    bytes_returned = ctypes.wintypes.DWORD(0)

    current_usn = start_usn

    while len(records) < max_entries:
        # Update StartUsn in input buffer
        input_buffer = struct.pack('<QIIQqQ',
                                   current_usn,
                                   reason_mask,
                                   0, 0, 0,
                                   journal_id)

        result = kernel32.DeviceIoControl(
            handle,
            FSCTL_READ_USN_JOURNAL,
            input_buffer, len(input_buffer),
            output_buffer, output_size,
            ctypes.byref(bytes_returned),
            None
        )

        if not result or bytes_returned.value <= 8:
            break

        # First 8 bytes of output = next USN to continue from
        next_usn = struct.unpack_from('<Q', output_buffer.raw, 0)[0]
        data = output_buffer.raw[8:bytes_returned.value]

        if not data:
            break

        offset = 0
        parsed_any = False
        while offset < len(data) and len(records) < max_entries:
            if offset + 4 > len(data):
                break

            record_length = struct.unpack_from('<I', data, offset)[0]
            if record_length == 0 or offset + record_length > len(data):
                break

            if record_length < 60:
                offset += record_length
                continue

            try:
                # Parse USN_RECORD_V2:
                #   RecordLength (4) + MajorVersion (2) + MinorVersion (2) +
                #   FileReferenceNumber (8) + ParentFileReferenceNumber (8) +
                #   Usn (8) + TimeStamp (8) + Reason (4) + SourceInfo (4) +
                #   SecurityId (4) + FileAttributes (4) +
                #   FileNameLength (2) + FileNameOffset (2) + FileName (variable)
                major_ver = struct.unpack_from('<H', data, offset + 4)[0]
                if major_ver != 2:
                    offset += record_length
                    continue

                file_ref = struct.unpack_from('<Q', data, offset + 8)[0]
                parent_ref = struct.unpack_from('<Q', data, offset + 16)[0]
                usn = struct.unpack_from('<Q', data, offset + 24)[0]
                timestamp = struct.unpack_from('<q', data, offset + 32)[0]
                reason = struct.unpack_from('<I', data, offset + 40)[0]
                file_attrs = struct.unpack_from('<I', data, offset + 52)[0]
                name_length = struct.unpack_from('<H', data, offset + 56)[0]
                name_offset = struct.unpack_from('<H', data, offset + 58)[0]

                if name_length > 0 and name_offset + name_length <= record_length:
                    filename = data[offset + name_offset:offset + name_offset + name_length]
                    filename = filename.decode('utf-16-le', errors='replace')
                else:
                    filename = "<unknown>"

                ts_str = _filetime_to_datetime(timestamp)
                reasons = _decode_reasons(reason)
                is_directory = bool(file_attrs & 0x10)

                records.append({
                    'filename': filename,
                    'timestamp': ts_str,
                    'usn': usn,
                    'reasons': reasons,
                    'reason_flags': reason,
                    'reason_summary': ' | '.join(reasons[:4]),
                    'file_reference': file_ref & 0x0000FFFFFFFFFFFF,
                    'parent_reference': parent_ref & 0x0000FFFFFFFFFFFF,
                    'is_directory': is_directory,
                })
                parsed_any = True

            except (struct.error, UnicodeDecodeError):
                pass

            offset += record_length

        if next_usn == current_usn or not parsed_any:
            break
        current_usn = next_usn

    return records


def collect_usn_journal(volume='C', max_entries=5000):
    """
    Parse the USN Journal from the given NTFS volume.

    Args:
        volume: Drive letter (default 'C')
        max_entries: Maximum number of entries to collect (default 5000)

    Returns:
        list of dicts, one per USN record. Empty if not Admin or not NTFS.
    """
    if os.name != 'nt':
        return []

    handle = _open_volume(volume)
    if handle is None:
        return []

    try:
        journal_info = _query_usn_journal(handle)
        if journal_info is None:
            return []

        # Read from recent entries — start from a position that gives us
        # roughly max_entries records (estimate ~128 bytes per record)
        estimated_start = max(
            journal_info['first_usn'],
            journal_info['next_usn'] - (max_entries * 128)
        )

        records = _read_usn_records(
            handle, journal_info['journal_id'],
            estimated_start, max_entries
        )

        return records

    finally:
        ctypes.windll.kernel32.CloseHandle(handle)
