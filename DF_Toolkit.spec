# DF_Toolkit.spec
# PyInstaller spec file for Digital Forensics Toolkit
# Generated for one-file GUI bundle

import os

block_cipher = None

a = Analysis(
    ['gui.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        # Bundle the rules directory
        ('rules', 'rules'),
        # Bundle the database schema
        ('database/schema.sql', 'database'),
    ],
    hiddenimports=[
        'psutil',
        'win32api',
        'win32con',
        'win32security',
        'pywintypes',
        'reportlab',
        'reportlab.graphics',
        'reportlab.platypus',
        'reportlab.lib',
        'pandas',
        'yara',
        'Evtx',
        'Evtx.Evtx',
        'PIL',
        'PIL.Image',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='DF_Toolkit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,   # GUI mode — no terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='DF_Toolkit',
)
