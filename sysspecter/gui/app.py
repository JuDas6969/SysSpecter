"""SysSpecter GUI main application window."""

from __future__ import annotations

import os
import sys
import tkinter as tk
import traceback
from tkinter import messagebox, ttk

from ..config import DEFAULT_OUTPUT_ROOT
from ..logging_setup import get_logger
from ..settings import UserPrefs, load_prefs
from .components.status_bar import StatusBar
from .components.toast import ToastService
from .tab_compare import CompareTab
from .tab_history import HistoryTab
from .tab_monitor import MonitorTab
from .tab_runs import RunsTab
from .tab_settings import SettingsTab
from .theme import apply_theme

_log = get_logger(__name__)

_ABOUT_TEXT = (
    "SysSpecter — See everything. Find the cause.\n"
    "Windows performance diagnostic + comparative benchmark framework.\n\n"
    "Tabs\n"
    "  • Monitor  — captures system + process timelines for a session\n"
    "  • Runs     — browse finished runs; rebuild, trim, split into phases\n"
    "  • Compare  — select 2+ runs; auto-detects before/after / pair / fleet mode\n\n"
    "All reports and artifacts live under the output-root folder "
    f"(default: {DEFAULT_OUTPUT_ROOT}).\n\n"
    "Phase 3 collectors (GPU / event log / ETW disk) are opt-in on the Monitor tab. "
    "ETW requires running as Administrator.\n\n"
    "Hover any label or field for a short description of what it does.\n\n"
    "© 2026 David Juriga. All rights reserved."
)


def _assets_dir() -> str | None:
    """Locate the assets/ folder next to the script or bundled EXE."""
    # Running as a PyInstaller frozen exe: _MEIPASS holds the temp extract dir
    meipass = getattr(sys, "_MEIPASS", None)
    candidates: list[str] = []
    if meipass:
        candidates.append(os.path.join(meipass, "assets"))
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, "..", ".."))
    candidates.append(os.path.join(repo, "assets"))
    try:
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.append(os.path.join(exe_dir, "assets"))
    except Exception:
        pass
    for c in candidates:
        if os.path.isdir(c):
            return c
    return None


def _load_photo(path: str, max_height: int) -> tk.PhotoImage | None:
    """Load a PNG via Tk's PhotoImage and downsample until its height fits."""
    if not os.path.exists(path):
        return None
    try:
        img = tk.PhotoImage(file=path)
    except tk.TclError:
        return None
    h = img.height()
    if h > max_height and max_height > 0:
        factor = max(1, h // max_height)
        img = img.subsample(factor, factor)
    return img


class App:
    def __init__(self, output_root: str = DEFAULT_OUTPUT_ROOT) -> None:
        self.root = tk.Tk()
        self.root.title("SysSpecter")
        self.root.geometry("1180x780")
        self.root.minsize(960, 640)

        # Apply the shared ttk theme (colors, typography, primary/danger variants).
        apply_theme(self.root)

        # Persistent user preferences. If the user has pinned an
        # output-root in settings, that beats the CLI default.
        self._prefs: UserPrefs = load_prefs()
        if self._prefs.output_root_mru:
            output_root = self._prefs.output_root_mru[0]

        self._output_root = output_root
        self._assets = _assets_dir()
        self._images: list[tk.PhotoImage] = []  # keep refs alive

        self._apply_window_icon()

        # Toast service is app-wide, one instance on the root.
        self.toasts = ToastService(self.root)

        header = ttk.Frame(self.root, padding=(12, 8))
        header.pack(fill="x")
        self._apply_header_logo(header)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.monitor_tab = MonitorTab(
            self.notebook, default_output_root=output_root,
            on_run_finished=self._on_run_finished,
        )
        self.runs_tab = RunsTab(
            self.notebook, default_output_root=output_root,
            get_output_root=lambda: self._output_root,
        )
        self.compare_tab = CompareTab(
            self.notebook, default_output_root=output_root,
            get_output_root=lambda: self._output_root,
        )

        self.history_tab = HistoryTab(
            self.notebook, get_output_root=lambda: self._output_root,
        )
        self.settings_tab = SettingsTab(
            self.notebook, prefs=self._prefs,
            on_saved=self._on_settings_saved,
        )

        self.notebook.add(self.monitor_tab, text="Monitor")
        self.notebook.add(self.runs_tab, text="Runs")
        self.notebook.add(self.compare_tab, text="Compare")
        self.notebook.add(self.history_tab, text="History")
        self.notebook.add(self.settings_tab, text="Settings")

        about = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(about, text="About")
        self._build_about_tab(about)

        # Proper status bar replaces the copyright-only footer.
        self.status_bar = StatusBar(
            self.root, get_output_root=lambda: self._output_root,
        )
        self.status_bar.pack(fill="x", side="bottom")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # Route unhandled Tk callback exceptions into a user-visible dialog.
        self.root.report_callback_exception = self._on_tk_exception

        self._install_shortcuts()

        # First-run onboarding dialog. Scheduled after a brief delay so
        # the main window is already visible when it pops up.
        if not self._prefs.first_run_completed:
            self.root.after(250, self._show_onboarding)

    def _show_onboarding(self) -> None:
        from ..settings import save_prefs
        from .onboarding import OnboardingDialog

        def _choice(tab: str) -> None:
            mapping = {
                "monitor": self.monitor_tab,
                "runs": self.runs_tab,
                "compare": self.compare_tab,
                "history": self.history_tab,
            }
            target = mapping.get(tab)
            if target is not None:
                try:
                    self.notebook.select(target)
                except tk.TclError:
                    pass

        def _done() -> None:
            # Mark first-run completed so the dialog does not come back.
            from dataclasses import replace
            self._prefs = replace(self._prefs, first_run_completed=True)
            try:
                save_prefs(self._prefs)
            except Exception:
                pass

        try:
            OnboardingDialog(self.root, on_choice=_choice, on_dismiss=_done)
        except tk.TclError:
            pass

    def _install_shortcuts(self) -> None:
        def _refresh(_event=None) -> None:
            tab = self._current_tab_widget()
            if tab is not None and hasattr(tab, "refresh"):
                tab.refresh()
        def _quit(_event=None) -> None:
            self._on_close()
        def _open_selection(_event=None) -> None:
            tab = self._current_tab_widget()
            if tab is self.runs_tab:
                self.runs_tab._action_open_report()
        self.root.bind_all("<Control-r>", _refresh)
        self.root.bind_all("<Control-R>", _refresh)
        self.root.bind_all("<Control-q>", _quit)
        self.root.bind_all("<Control-Q>", _quit)
        self.root.bind_all("<Return>", _open_selection)

    def _current_tab_widget(self) -> ttk.Frame | None:
        try:
            idx = self.notebook.index(self.notebook.select())
            tabs = (self.monitor_tab, self.runs_tab, self.compare_tab,
                    self.history_tab, self.settings_tab, None)
            return tabs[idx] if 0 <= idx < len(tabs) else None
        except tk.TclError:
            return None

    # --------------------------------------------------------------- chrome
    def _apply_window_icon(self) -> None:
        if not self._assets:
            return
        for name in ("icon.png", "logo.png"):
            img = _load_photo(os.path.join(self._assets, name), max_height=64)
            if img is not None:
                try:
                    self.root.iconphoto(True, img)
                    self._images.append(img)
                    return
                except tk.TclError:
                    continue

    def _apply_header_logo(self, header: ttk.Frame) -> None:
        wordmark_img: tk.PhotoImage | None = None
        if self._assets:
            wordmark_img = _load_photo(
                os.path.join(self._assets, "logo_long.png"), max_height=48,
            )
        if wordmark_img is not None:
            self._images.append(wordmark_img)
            ttk.Label(header, image=wordmark_img).pack(side="left")
        else:
            ttk.Label(header, text="SysSpecter",
                      font=("Segoe UI", 14, "bold")).pack(side="left")
            ttk.Label(header, text="See everything. Find the cause.",
                      foreground="#6b7a99").pack(side="left", padx=12)

    def _build_about_tab(self, parent: ttk.Frame) -> None:
        big_logo: tk.PhotoImage | None = None
        if self._assets:
            big_logo = _load_photo(os.path.join(self._assets, "logo.png"), max_height=220)
        if big_logo is not None:
            self._images.append(big_logo)
            ttk.Label(parent, image=big_logo).pack(pady=(0, 8))

        try:
            bg = ttk.Style().lookup("TFrame", "background") or "#f0f0f0"
        except tk.TclError:
            bg = "#f0f0f0"
        txt = tk.Text(parent, wrap="word", height=14, relief="flat", background=bg)
        txt.insert("1.0", _ABOUT_TEXT)
        txt.configure(state="disabled")
        txt.pack(fill="both", expand=True)

        # Update-check status label, filled asynchronously. Only runs
        # when the user opted in via Settings.
        self._update_label_var = tk.StringVar(
            value=("Checking for updates…" if self._prefs.check_updates_on_start
                   else "Update check disabled in Settings."),
        )
        ttk.Label(parent, textvariable=self._update_label_var,
                  foreground="#6b7a99").pack(pady=(8, 0))
        if self._prefs.check_updates_on_start:
            self._kick_off_update_check()

    def _kick_off_update_check(self) -> None:
        import threading

        def _run() -> None:
            try:
                from ..updater.check import check_for_updates
                info = check_for_updates()
            except Exception:
                info = None
            if info is None:
                text = "Update check: offline or GitHub unreachable."
            elif info.update_available:
                text = (f"A newer version is available: v{info.current} -> "
                        f"{info.latest}.")
            else:
                text = f"SysSpecter v{info.current} (up to date)."
            try:
                self.root.after(0, self._update_label_var.set, text)
            except tk.TclError:
                pass

        threading.Thread(target=_run, daemon=True).start()

    # --------------------------------------------------------------- runtime
    def _on_run_finished(self) -> None:
        try:
            self.runs_tab.refresh()
            self.compare_tab.refresh()
            self.history_tab.refresh()
        except Exception:
            _log.debug("post-run refresh failed", exc_info=True)

    def _on_settings_saved(self, prefs: UserPrefs) -> None:
        """Called by SettingsTab after a successful save. Apply what we can
        live (output root + status bar refresh) and toast the user."""
        self._prefs = prefs
        if prefs.output_root_mru:
            self._output_root = prefs.output_root_mru[0]
        try:
            self.status_bar.refresh_context()
            self.runs_tab.refresh()
            self.compare_tab.refresh()
        except Exception:
            _log.debug("post-settings refresh failed", exc_info=True)
        try:
            self.toasts.show("Settings saved.", kind="success")
        except Exception:
            _log.debug("toast show failed", exc_info=True)

    def _active_subprocesses(self) -> list[str]:
        """Return a short description of any still-running child subprocesses."""
        still: list[str] = []
        m_runner = getattr(self.monitor_tab, "_runner", None)
        if m_runner is not None and m_runner.is_running():
            still.append("Monitor")
        for tab_name, attr in (("Runs", "_runner"), ("Compare", "_runner")):
            r = getattr(self.runs_tab if tab_name == "Runs" else self.compare_tab, attr, None)
            if r is not None and r.is_running():
                still.append(tab_name)
        return still

    def _on_close(self) -> None:
        running = self._active_subprocesses()
        if not running:
            self.root.destroy()
            return
        msg = (
            "These operations are still running:\n\n"
            + "\n".join(f"  - {r}" for r in running)
            + "\n\nClosing now will stop them immediately. Reports for monitor "
              "sessions that have not finalised will be missing.\n\n"
              "Stop everything and close?"
        )
        if not messagebox.askyesno("SysSpecter — still running", msg):
            return
        # Try graceful stop first so monitor finalises, then force-kill on timeout.
        m_runner = getattr(self.monitor_tab, "_runner", None)
        if m_runner is not None and m_runner.is_running():
            try:
                m_runner.send_ctrl_break()
            except Exception:
                pass
        for tab in (self.runs_tab, self.compare_tab):
            r = getattr(tab, "_runner", None)
            if r is not None and r.is_running():
                try:
                    r.kill()
                except Exception:
                    pass
        # give the monitor a couple of seconds to finalise
        self.root.after(2500, self._force_close)

    def _force_close(self) -> None:
        m_runner = getattr(self.monitor_tab, "_runner", None)
        if m_runner is not None and m_runner.is_running():
            try:
                m_runner.kill()
            except Exception:
                pass
        self.root.destroy()

    def _on_tk_exception(self, exc_type, exc_value, exc_tb) -> None:
        tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        short = f"{exc_type.__name__}: {exc_value}"
        # Dump a crash report next to the output root so the user can ship it.
        crash_path: str | None = None
        try:
            from ..telemetry.crash_reporter import write_crash_report
            try:
                idx = self.notebook.index(self.notebook.select())
            except tk.TclError:
                idx = -1
            crash_path = write_crash_report(
                self._output_root, exc_type, exc_value, exc_tb,
                extra={"active_tab_index": idx},
            )
        except Exception:
            _log.debug("crash-report write failed", exc_info=True)
            crash_path = None
        try:
            msg = f"{short}\n\n{tb.splitlines()[-1] if tb.splitlines() else ''}"
            if crash_path:
                msg += f"\n\nFull crash report:\n{crash_path}"
            messagebox.showerror("SysSpecter — unexpected error", msg)
        except Exception:
            pass
        # also dump to stderr so users launching via sysspecter.bat gui see it
        sys.stderr.write(tb)
        sys.stderr.flush()

    def mainloop(self) -> None:
        self.root.mainloop()


def run_gui(output_root: str = DEFAULT_OUTPUT_ROOT) -> int:
    App(output_root=output_root).mainloop()
    return 0
