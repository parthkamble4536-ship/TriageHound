import hashlib
import os
from datetime import datetime


def hash_file_sha256(filepath):
    """Return the SHA-256 hex digest of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, IOError):
        return None


def seal_report(pdf_path, db_path, case_id, output_dir='.'):
    """
    Generate a cryptographic seal manifest for the investigation artifacts.

    Hashes both the final PDF report and the SQLite database and writes a
    human-readable seal file.  If either file is later tampered with, the
    hash stored here will no longer match — providing legally-defensible
    evidence of tampering.

    Returns:
        seal_path (str): path to the generated seal file
        seal_data (dict): dict containing file paths and their SHA-256 hashes
    """
    seal_data = {
        'case_id':       case_id,
        'sealed_at':     datetime.now().isoformat(),
        'artifacts':     {}
    }

    for label, fpath in [('pdf_report', pdf_path), ('forensic_database', db_path)]:
        if fpath and os.path.exists(fpath):
            digest = hash_file_sha256(fpath)
            size   = os.path.getsize(fpath)
            seal_data['artifacts'][label] = {
                'path':       os.path.abspath(fpath),
                'sha256':     digest,
                'size_bytes': size,
            }
        else:
            seal_data['artifacts'][label] = {
                'path':   fpath,
                'sha256': None,
                'error':  'File not found',
            }

    # Write human-readable manifest
    seal_path = os.path.join(output_dir, f'seal_{case_id}.txt')
    with open(seal_path, 'w', encoding='utf-8') as f:
        f.write('=' * 70 + '\n')
        f.write('  DIGITAL FORENSICS TOOLKIT — CRYPTOGRAPHIC SEAL MANIFEST\n')
        f.write('=' * 70 + '\n\n')
        f.write(f'  Case ID   : {seal_data["case_id"]}\n')
        f.write(f'  Sealed At : {seal_data["sealed_at"]}\n\n')
        f.write('-' * 70 + '\n')
        f.write('  Artifact Integrity Hashes (SHA-256)\n')
        f.write('-' * 70 + '\n\n')
        for label, info in seal_data['artifacts'].items():
            f.write(f'  [{label.upper()}]\n')
            f.write(f'    File   : {info["path"]}\n')
            if info.get('sha256'):
                f.write(f'    SHA256 : {info["sha256"]}\n')
                f.write(f'    Size   : {info["size_bytes"]:,} bytes\n')
            else:
                f.write(f'    ERROR  : {info.get("error", "Unknown error")}\n')
            f.write('\n')
        f.write('-' * 70 + '\n')
        f.write('  VERIFICATION INSTRUCTIONS:\n')
        f.write('  To verify file integrity, run:\n')
        f.write('    certutil -hashfile <filepath> SHA256\n')
        f.write('  and compare with the hash recorded above.\n')
        f.write('  Any difference indicates tampering.\n')
        f.write('=' * 70 + '\n')

    return seal_path, seal_data
