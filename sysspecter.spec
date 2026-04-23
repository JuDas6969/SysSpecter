# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for a single-file, portable SysSpecter executable.
#
# Build:  .venv\Scripts\pyinstaller.exe sysspecter.spec --clean
# Output: dist\SysSpecter.exe
#
# The EXE defaults to launching the GUI when double-clicked (no args), so the
# technician just copies it to a USB stick and runs it on any Windows box.
# CLI usage is preserved: `SysSpecter.exe monitor --mode support` etc.

import os

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules("psutil")
hiddenimports += collect_submodules("jinja2")
# Pull the whole sysspecter package in even though we only name sysspecter.py:
# subcommand dispatch lazy-imports `sysspecter.gui.app`, `sysspecter.splitter.*`,
# `sysspecter.comparer.*`, `sysspecter.reporter.*`, `sysspecter.analyzer.*`.
hiddenimports += collect_submodules("sysspecter")


# Bundle logos / icons so the GUI can show them inside the frozen EXE.
_datas = []
for name in ("logo.png", "logo_long.png", "icon.png"):
    p = os.path.join("assets", name)
    if os.path.exists(p):
        _datas.append((p, "assets"))

# Bundle the HTML report template + CSS so html_report.py can load them
# at runtime from inside the frozen EXE.
_datas.append((os.path.join("sysspecter", "reporter", "templates",
                            "final_report.html.j2"),
               os.path.join("sysspecter", "reporter", "templates")))
_datas.append((os.path.join("sysspecter", "reporter", "styles",
                            "report.css"),
               os.path.join("sysspecter", "reporter", "styles")))

_icon_path = os.path.join("assets", "icon.ico")
_icon = _icon_path if os.path.exists(_icon_path) else None


a = Analysis(
    ["sysspecter.py"],
    pathex=["."],
    binaries=[],
    datas=_datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Keep the binary lean -- none of these are needed for sysspecter.
    # Pillow (PIL) is build-only (make_icon.py) so we exclude it from the EXE too.
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
    icon=_icon,
)
