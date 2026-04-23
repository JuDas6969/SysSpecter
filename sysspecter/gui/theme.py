"""ttk Style setup driven by the shared design tokens.

Call `apply_theme(root)` once after creating the `Tk()` root. That
configures hover / focus / disabled / primary / danger variants of
the ttk buttons and aligns typography with the HTML report.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..theme import COLORS, TYPOGRAPHY


def apply_theme(root: tk.Misc) -> None:
    """Apply the SysSpecter ttk theme. Safe to call multiple times."""
    style = ttk.Style(root)

    # Keep the native theme as a base so ttk.Treeview etc. still look right.
    try:
        windowing = root.tk.call("tk", "windowingsystem")
    except tk.TclError:
        windowing = "x11"
    if windowing == "win32":
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

    base_font = (TYPOGRAPHY.family, TYPOGRAPHY.size_body)
    bold_font = (TYPOGRAPHY.family, TYPOGRAPHY.size_body, "bold")

    # Typography hierarchy so H1/H2/H3 are readable at a glance.
    style.configure("H1.TLabel", font=(TYPOGRAPHY.family, 16, "bold"),
                    foreground=COLORS.fg_primary)
    style.configure("H2.TLabel", font=(TYPOGRAPHY.family, 13, "bold"),
                    foreground=COLORS.fg_primary)
    style.configure("H3.TLabel", font=(TYPOGRAPHY.family, 11, "bold"),
                    foreground=COLORS.fg_body)
    style.configure("Muted.TLabel", font=base_font, foreground=COLORS.fg_muted)

    # Core widgets
    style.configure("TLabel", font=base_font, foreground=COLORS.fg_body)
    style.configure("TFrame", background=COLORS.bg_app)
    style.configure("TButton", padding=(12, 6), font=base_font)
    style.map(
        "TButton",
        foreground=[("disabled", COLORS.fg_muted),
                    ("focus", COLORS.brand_indigo)],
        # Visible focus outline for keyboard navigation.
        focuscolor=[("focus", COLORS.brand_cyan)],
    )

    # Primary button — used for Start Monitor, Start Compare, Apply
    style.configure(
        "Primary.TButton", padding=(14, 7),
        font=bold_font,
        foreground="white",
        background=COLORS.brand_cyan,
    )
    style.map(
        "Primary.TButton",
        background=[("pressed", COLORS.brand_indigo),
                    ("active", COLORS.brand_indigo),
                    ("disabled", COLORS.bg_subtle)],
        foreground=[("disabled", COLORS.fg_muted)],
    )

    # Danger button — used for Stop / Delete
    style.configure(
        "Danger.TButton", padding=(12, 6), font=base_font,
        foreground="white",
        background=COLORS.danger_fg,
    )
    style.map(
        "Danger.TButton",
        background=[("pressed", COLORS.danger_fg_strong),
                    ("active", COLORS.danger_fg_strong),
                    ("disabled", COLORS.bg_subtle)],
        foreground=[("disabled", COLORS.fg_muted)],
    )

    # Notebook tabs
    style.configure("TNotebook", background=COLORS.bg_app)
    style.configure("TNotebook.Tab", padding=(14, 6), font=base_font)
    style.map(
        "TNotebook.Tab",
        foreground=[("selected", COLORS.brand_indigo),
                    ("!selected", COLORS.fg_muted)],
    )

    # Treeview (runs table)
    style.configure(
        "Treeview", background=COLORS.bg_surface,
        fieldbackground=COLORS.bg_surface,
        foreground=COLORS.fg_body,
        rowheight=24, font=base_font,
    )
    style.configure(
        "Treeview.Heading", background=COLORS.bg_header,
        foreground=COLORS.fg_primary, font=bold_font,
    )
    style.map(
        "Treeview",
        background=[("selected", COLORS.brand_cyan)],
        foreground=[("selected", "white")],
    )

    # Entry + Combobox focus ring (subtle brand-cyan accent)
    style.map(
        "TEntry",
        bordercolor=[("focus", COLORS.brand_cyan)],
        lightcolor=[("focus", COLORS.brand_cyan)],
    )
    style.map(
        "TCombobox",
        bordercolor=[("focus", COLORS.brand_cyan)],
        fieldbackground=[("readonly", COLORS.bg_surface)],
    )

    # Progressbar colored to match the brand gradient start
    style.configure(
        "Horizontal.TProgressbar",
        troughcolor=COLORS.bg_subtle,
        background=COLORS.brand_cyan,
    )
