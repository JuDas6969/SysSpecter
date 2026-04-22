"""Tkinter-based GUI for SysSpecter.

Minimal, stdlib-only interface so it survives packaging into a single-file
USB executable (see Phase 3). The GUI wraps the CLI subcommands: it launches
them as subprocesses and streams their stdout into a log pane, so nothing
blocks the event loop.
"""
