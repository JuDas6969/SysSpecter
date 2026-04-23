# ADR 0003 — PyInstaller --onefile for the portable EXE

**Status:** Accepted (v1.0.0)

## Context

The portable-USB deployment path asks the technician to copy ONE file
to a stick and run it on any Windows 10 / 11 box — no installer, no
admin rights. We need a single-file executable that embeds the Python
interpreter, standard library, and runtime dependencies.

## Decision

Build with PyInstaller `--onefile` via [sysspecter.spec](sysspecter.spec),
orchestrated by [build_exe.bat](build_exe.bat):
- Entry point: top-level `sysspecter.py`.
- Hidden imports: every `sysspecter.*` sub-package, `psutil.*`,
  `jinja2.*`, `pydantic.*`.
- Asset bundling: `assets/*.png` + the generated `icon.ico` + the
  externalised `sysspecter/reporter/styles/report.css` and
  `sysspecter/reporter/templates/final_report.html.j2`.
- `console=True` so CLI usage still shows stdout; double-click still
  drops straight into the GUI because `sysspecter.py::main` defaults
  to `gui` when argv is empty.

## Consequences

**Pro**
- A single file is trivially easy to copy, sign, checksum, and
  verify. `dist/SysSpecter.exe` + `LICENSE.txt` +
  `THIRD_PARTY_NOTICES.md` + `SysSpecter.sbom.json` +
  `SysSpecter.exe.sha256` is the entire ship-kit.
- No admin required on the target machine.
- Output root defaults to `<exe_dir>\SysSpecter` when `sys.frozen`, so
  reports stay on the USB stick.

**Contra**
- Binary size ~21 MB (Python + Tcl/Tk + pydantic + psutil + assets).
  Acceptable for a USB workflow, would be a problem for bandwidth-
  constrained distribution.
- First-run unpack: PyInstaller extracts to `%TEMP%\_MEIxxxxxx`
  (~200 ms on modern hardware). Subsequent runs from the same EXE use
  the same temp dir.
- SmartScreen will warn on unsigned binaries — the code-signing plan
  lives in `BUILDING.md`. Roadmap items W3.10 / W3.11 automate the
  signed + reproducible build once a cert is provisioned.

## Alternatives considered

- **PyInstaller `--onedir`** — faster startup, but breaks the "single
  file on a stick" UX.
- **Nuitka** — produces smaller binaries and genuine native code, but
  slower build, harder to reason about, and Tkinter integration
  requires extra hooks. Reconsidered in v2 if binary size becomes a
  problem.
- **Shiv / zipapp** — needs Python installed on the host, breaking
  the "plug-and-play" promise.
