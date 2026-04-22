# Third-Party Notices

SysSpecter bundles and/or depends on the third-party components listed below.
Each component is distributed under the terms of its own license; the full
text of each license is available from the project pages linked.

---

## Runtime dependencies (shipped inside the EXE)

### psutil
- **License:** BSD 3-Clause
- **Project:** https://github.com/giampaolo/psutil
- **Used for:** system + process metrics collection

### Jinja2
- **License:** BSD 3-Clause
- **Project:** https://palletsprojects.com/p/jinja/
- **Used for:** HTML report templating

### pywin32
- **License:** Python Software Foundation License (PSF-like, permissive)
- **Project:** https://github.com/mhammond/pywin32
- **Used for:** Windows-specific capabilities on supported Python versions

### Python Standard Library
- **License:** Python Software Foundation License
- **Project:** https://www.python.org/
- **Used for:** the base runtime, Tkinter GUI, `subprocess`, `ctypes`, etc.

### Tcl/Tk
- **License:** Tcl/Tk License (BSD-style, permissive)
- **Project:** https://www.tcl.tk/
- **Used for:** the Tkinter GUI widgets

---

## Build-only tooling (NOT redistributed inside the EXE)

### PyInstaller
- **License:** GPLv2 with a distribution exception — end users of programs
  packaged with PyInstaller are NOT required to license their programs
  under the GPL. See: https://pyinstaller.org/en/stable/license.html
- **Used for:** packaging `SysSpecter.exe`
- **Note:** a small PyInstaller bootloader is embedded in the executable;
  its source is available upon request per the GPL exception.

### Pillow
- **License:** HPND (Historical Permission Notice and Disclaimer, permissive)
- **Project:** https://python-pillow.github.io/
- **Used for:** converting `assets/icon.png` into the multi-resolution
  `assets/icon.ico` at build time. Pillow itself is **not** included in
  the shipped EXE.

---

## Notes

- SysSpecter invokes the following Windows built-in executables at runtime:
  `powershell.exe`, `logman.exe`, `tracerpt.exe`, `route.exe`, `ipconfig.exe`,
  `powercfg.exe`. These are part of the Windows operating system and are
  covered by Microsoft's own licensing.
- The bundled logo artwork in `assets/` is copyrighted material of
  David Juriga and is not covered by the permissive licenses above.

© 2026 David Juriga
