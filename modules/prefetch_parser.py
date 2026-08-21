r"""
Windows Prefetch Parser
========================
Parses .pf files from C:\Windows\Prefetch to extract program execution evidence.

NOTE: Reading the Prefetch directory requires Administrator privileges on modern
Windows. If the tool is not run as Administrator, this module gracefully skips
and returns an empty list with a warning.

Prefetch files store:
  - The name of the executed .exe
  - How many times it was run (run count)
  - The last 8 timestamps when it was executed
  - Which files/DLLs were loaded during execution
"""

import os
import struct
import glob
import platform
from datetime import datetime, timedelta


PREFETCH_DIR = r"C:\Windows\Prefetch"


def _filetime_to_datetime(filetime):
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    if not filetime:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
    except (OverflowError, OSError):
        return None


def _parse_pf_file(filepath):
    """
    Parse a single .pf prefetch file.
    Supports Windows XP/Vista/7 (v17/v23/v26) and Windows 8.1/10 (v30).
    Windows 10 compressed prefetch (MAM format) is detected but skipped gracefully.
    """
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
    except (PermissionError, OSError):
        return None

    if len(raw) < 84:
        return None

    # Check for Windows 10 MAM-compressed prefetch
    if raw[:4] == b'MAM\x04':
        return {
            'pf_filename':     os.path.basename(filepath),
            'executable_name': os.path.basename(filepath).split('-')[0],
            'run_count':       '?',
            'last_run':        'Compressed (Win10 MAM — requires decompression)',
            'all_run_times':   [],
            'note':            'Windows 10 compressed prefetch — install python-xpress to parse'
        }

    version = struct.unpack_from('<I', raw, 0)[0]
    sig     = raw[4:8]

    if sig != b'SCCA':
        return None  # Not a prefetch file

    # Executable name — offset 16, 60 bytes, UTF-16LE
    exe_raw  = raw[16:76]
    exe_name = exe_raw.decode('utf-16-le', errors='replace').rstrip('\x00').split('\x00')[0]

    # Version-specific offsets for run count and last run times
    if version == 17:    # XP/2003
        run_count_off   = 80
        last_run_off    = 76
        num_times       = 1
    elif version in (23, 26):  # Vista/7
        run_count_off   = 152
        last_run_off    = 128
        num_times       = 1
    elif version == 30:  # Win 8.1 / 10 (uncompressed)
        run_count_off   = 208
        last_run_off    = 128
        num_times       = 8
    else:
        run_count_off   = 152
        last_run_off    = 128
        num_times       = 1

    # Run count
    try:
        run_count = struct.unpack_from('<I', raw, run_count_off)[0]
    except struct.error:
        run_count = 0

    # Last run timestamps (up to 8 for v30)
    run_times = []
    for i in range(num_times):
        offset = last_run_off + (i * 8)
        if offset + 8 > len(raw):
            break
        try:
            ft = struct.unpack_from('<Q', raw, offset)[0]
            dt = _filetime_to_datetime(ft)
            if dt and dt.year > 1970:
                run_times.append(dt.isoformat())
        except struct.error:
            break

    last_run = run_times[0] if run_times else None

    return {
        'pf_filename':     os.path.basename(filepath),
        'executable_name': exe_name,
        'run_count':       run_count,
        'last_run':        last_run,
        'all_run_times':   run_times,
    }


def collect_prefetch(prefetch_dir=PREFETCH_DIR):
    """
    Parse all .pf files in the Prefetch directory.

    Returns:
        list of dicts, one per .pf file successfully parsed.
        Empty list if the directory is inaccessible (e.g. no admin rights).
    """
    results = []

    if platform.system() != 'Windows':
        return results

    if not os.path.exists(prefetch_dir):
        return results

    try:
        pf_files = glob.glob(os.path.join(prefetch_dir, '*.pf'))
    except PermissionError:
        print(f"[!] Prefetch: Permission denied accessing {prefetch_dir}. Run as Administrator.")
        return results

    for pf_path in sorted(pf_files):
        entry = _parse_pf_file(pf_path)
        if entry:
            results.append(entry)

    return results
