# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

spec_root = os.path.abspath(SPECPATH)
project_root = os.path.abspath(os.path.join(spec_root, '..'))

datas = []
datas += collect_data_files('botocore')

hiddenimports = [
    'sqlalchemy.dialects.sqlite',
    'aioboto3',
    'aiohttp',
    'fastapi',
    'cryptography',
    'zstandard',
    'argon2',
    'dateutil',
]
hiddenimports += collect_submodules('uvicorn')
hiddenimports += collect_submodules('structlog')

a = Analysis(
    [os.path.join(project_root, 'src', 'boveda', 'cli.py')],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='boveda',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

