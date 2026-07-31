r"""
Volume Shadow Copy (VSS) Extractor
=====================================
Lists and mounts Windows Volume Shadow Copies to recover older or deleted
versions of forensic artifacts.

Shadow copies are automatic system backups that can contain files an attacker
thought they destroyed (deleted registry hives, event logs, prefetch files).

Requires Administrator privileges.
"""

import subprocess
import os
import re
import tempfile
from datetime import datetime


# Key forensic artifacts to look for inside shadow copies
ARTIFACTS_OF_INTEREST = [
    r"Windows\Prefetch",
    r"Windows\System32\winevt\Logs",
    r"Windows\System32\config\SYSTEM",
    r"Windows\System32\config\SAM",
    r"Windows\System32\config\SOFTWARE",
    r"Windows\AppCompat\Programs\Amcache.hve",
    r"Users",
]


def list_shadow_copies():
    """
    List all available Volume Shadow Copies on the system.

    Returns:
        list of dicts:
            {
                'shadow_id': str (e.g., '\\\\?\\GLOBALROOT\\Device\\...'),
                'creation_time': str,
                'volume': str,
                'provider': str,
            }
        Empty list if not Admin or no shadows exist.
    """
    shadows = []

    try:
        result = subprocess.run(
            ['vssadmin', 'list', 'shadows'],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            return shadows

        output = result.stdout
        current_shadow = {}

        for line in output.splitlines():
            line = line.strip()

            # Shadow Copy ID line
            shadow_match = re.search(r'Shadow Copy Volume:\s*(.+)', line)
            if shadow_match:
                current_shadow['shadow_id'] = shadow_match.group(1).strip()

            # Creation time
            time_match = re.search(r'creation time:\s*(.+)', line, re.IGNORECASE)
            if time_match:
                current_shadow['creation_time'] = time_match.group(1).strip()

            # Original volume
            vol_match = re.search(r'Original Volume:\s*(.+)', line)
            if vol_match:
                current_shadow['volume'] = vol_match.group(1).strip()

            # Provider
            prov_match = re.search(r'Provider:\s*(.+)', line, re.IGNORECASE)
            if prov_match:
                current_shadow['provider'] = prov_match.group(1).strip()

            # Detect end of a shadow block (empty line or new "Contents of...")
            if (not line or 'Contents of' in line) and current_shadow.get('shadow_id'):
                shadows.append(dict(current_shadow))
                current_shadow = {}

        # Don't forget the last block
        if current_shadow.get('shadow_id'):
            shadows.append(dict(current_shadow))

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return shadows


def mount_shadow(shadow_id, mount_point):
    """
    Mount a shadow copy to a local directory using mklink.

    Args:
        shadow_id: The shadow copy volume path (e.g., \\\\?\\GLOBALROOT\\Device\\...)
        mount_point: Local directory path to mount to

    Returns:
        True if mount succeeded, False otherwise
    """
    try:
        # Ensure shadow_id ends with backslash
        if not shadow_id.endswith('\\'):
            shadow_id += '\\'

        # Remove existing mount point if it exists
        if os.path.exists(mount_point):
            subprocess.run(['rmdir', mount_point], shell=True, timeout=10,
                           capture_output=True)

        # Create symbolic link
        result = subprocess.run(
            ['cmd', '/c', 'mklink', '/d', mount_point, shadow_id],
            capture_output=True, text=True, timeout=10
        )

        return result.returncode == 0 and os.path.exists(mount_point)

    except (subprocess.TimeoutExpired, OSError):
        return False


def unmount_shadow(mount_point):
    """Remove a shadow copy mount point."""
    try:
        if os.path.exists(mount_point):
            subprocess.run(['rmdir', mount_point], shell=True, timeout=10,
                           capture_output=True)
            return True
    except (subprocess.TimeoutExpired, OSError):
        pass
    return False


def scan_shadow_artifacts(mount_point):
    """
    Scan a mounted shadow copy for forensic artifacts of interest.

    Args:
        mount_point: Path where the shadow copy is mounted

    Returns:
        list of dicts:
            {
                'artifact_type': str,
                'path': str (path inside shadow),
                'exists': bool,
                'size_bytes': int or None,
                'modified': str or None,
            }
    """
    found = []

    for artifact_rel in ARTIFACTS_OF_INTEREST:
        full_path = os.path.join(mount_point, artifact_rel)
        entry = {
            'artifact_type': artifact_rel.split('\\')[-1],
            'path': full_path,
            'relative_path': artifact_rel,
            'exists': False,
            'size_bytes': None,
            'modified': None,
        }

        try:
            if os.path.exists(full_path):
                entry['exists'] = True
                if os.path.isfile(full_path):
                    stat = os.stat(full_path)
                    entry['size_bytes'] = stat.st_size
                    entry['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
                elif os.path.isdir(full_path):
                    # Count items in directory
                    try:
                        items = os.listdir(full_path)
                        entry['size_bytes'] = len(items)
                        entry['modified'] = f"{len(items)} items"
                    except PermissionError:
                        entry['modified'] = "Permission denied"
        except (OSError, PermissionError):
            pass

        found.append(entry)

    return found


def collect_vss_info():
    """
    Collect Volume Shadow Copy information and scan each for forensic artifacts.

    This is the main entry point for the VSS module.

    Returns:
        list of dicts — one per shadow copy found, with artifact scan results.
    """
    shadows = list_shadow_copies()

    if not shadows:
        return []

    results = []
    for i, shadow in enumerate(shadows):
        mount_point = os.path.join(
            os.environ.get('TEMP', '.'),
            f'_dftk_vss_mount_{i}'
        )

        shadow_result = {
            'shadow_id': shadow.get('shadow_id', ''),
            'creation_time': shadow.get('creation_time', ''),
            'volume': shadow.get('volume', ''),
            'artifacts_found': [],
        }

        if mount_shadow(shadow.get('shadow_id', ''), mount_point):
            try:
                artifacts = scan_shadow_artifacts(mount_point)
                shadow_result['artifacts_found'] = [
                    a for a in artifacts if a['exists']
                ]
            finally:
                unmount_shadow(mount_point)

        results.append(shadow_result)

    return results
