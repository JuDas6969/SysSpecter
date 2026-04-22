# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for a single-file, portable SysSpecter executable.
#
# Build:  .venv\Scripts\pyinstaller.exe sysspecter.spec --clean
# Output: dist\SysSpecter.exe
#
# The EXE defaults to launching the GUI when double-clicked (no args), so the
# technician just copies it to a USB stick and runs it on any Windows box.
# CLI usage is preserved: `SysSpecter.exe monitor --mode support` etc.

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules("psutil")
hiddenimports += collect_submodules("jinja2")
# Pull the whole sysspecter package in even though we only name sysspecter.py:
# subcommand dispatch lazy-imports `sysspecter.gui.app`, `sysspecter.splitter.*`,
# `sysspecter.comparer.*`, `sysspecter.reporter.*`, `sysspecter.analyzer.*`.
hiddenimports += collect_submodules("sysspecter")


a = Analysis(
    ["sysspecter.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Keep the binary lean -- none of these are needed for sysspecter.
    excludes=[
        "numpy", "pandas", "matplotlib", "scipy", "PIL", "PySide2",
        "PySide6", "PyQt5", "PyQt6", "IPython", "pytest", "sphinx",
    ],
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
    name="SysSpecter",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
