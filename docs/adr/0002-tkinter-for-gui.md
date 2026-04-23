# ADR 0002 — Tkinter as the GUI toolkit

**Status:** Accepted (v1.0.0)

## Context

SysSpecter needs a GUI for technicians who are not comfortable on the
command line. The GUI must run on a fresh Windows install with no
extra dependencies, because step-3 of the product is a single-file
portable EXE shipped on a USB stick.

## Decision

We use the standard library's `tkinter` / `ttk` module, themed via
`sysspecter/gui/theme.py` and populated with shared tokens from
`sysspecter/theme.py`.

## Consequences

**Pro**
- Bundled with every Python install. Frozen EXE size grows by ~1 MB
  for Tk libs, no extra wheels.
- Supports native Windows look via the `vista` ttk theme.
- PyInstaller packages Tcl/Tk without any special hook work.
- Drop-in widgets for everything we need: `Notebook`, `Treeview`,
  `Progressbar`, `Combobox`, `Toplevel` (for Toast / Tooltip / Modal).

**Contra**
- Dated default look. Mitigated by the design-token system + hover /
  focus / disabled variants in `sysspecter/gui/theme.py::apply_theme`.
- Screen-reader (UIA) support is minimal; dark-mode requires manual
  styling instead of automatic OS-theme following.
- Some premium-feeling interactions (animated transitions, elevated
  surfaces) are not trivially available. Accepted for v1; dark mode
  and modern animations are on the v1.1 roadmap.

## Alternatives considered

- **PyQt6 / PySide6** — ~40 MB extra inside the EXE, licensing
  considerations for PyQt, overkill for a diagnostic tool.
- **Web UI (Flask + browser)** — depends on a working default browser
  on the host machine; customers on locked-down devices fail to launch.
- **Textual TUI** — great look, but no way to show CPU / memory charts
  inline; needs a terminal, misses the "double-click the EXE" UX.
