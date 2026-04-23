"""Design tokens used by the HTML report AND the Tkinter GUI.

Single source of truth for colors / spacing / typography. Importing
from a central module stops the hex-literals from drifting across
`reporter/styles/report.css`, `comparer/compare_report.py`,
`splitter/overview.py`, and `gui/*`.

Keep this module pure Python — no Tk / jinja imports — so it can be
consumed by tests and docs alike.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _Colors:
    """Semantic color tokens. Every name here is used in at least one surface."""

    # Brand gradient anchors
    brand_cyan: str = "#06b6d4"
    brand_indigo: str = "#6366f1"
    brand_purple: str = "#a855f7"

    # Foreground
    fg_primary: str = "#1b2a4e"          # dark navy — headings + emphasised text
    fg_body: str = "#222222"             # main body text
    fg_muted: str = "#6b7a99"            # secondary text / captions
    fg_dim: str = "#777777"              # very muted, e.g. table footnotes

    # Backgrounds
    bg_app: str = "#f7f7f9"              # app / report background
    bg_surface: str = "#ffffff"          # card
    bg_subtle: str = "#f3f5fa"           # score tiles, code spans
    bg_hover: str = "#fafbff"            # row hover
    bg_header: str = "#f6f8fc"            # table header
    bg_divider: str = "#e2e6ee"          # card border / h2 underline
    bg_divider_soft: str = "#eef0f7"     # table row separator

    # Semantic states
    danger_fg: str = "#cf1322"
    danger_bg: str = "#fff1f0"
    danger_border: str = "#ffa39e"
    danger_fg_strong: str = "#5a0f1c"

    warn_fg: str = "#d46b08"
    warn_bg: str = "#fffbe6"
    warn_border: str = "#ffe58f"
    warn_fg_strong: str = "#614700"

    ok_fg: str = "#389e0d"
    ok_bg: str = "#f6ffed"
    ok_border: str = "#b7eb8f"

    info_fg: str = "#2c7be5"

    # Confidence / tier palette (used by badges in the HTML report)
    tier_suspicious_bg: str = "#fff7e6"
    tier_suspicious_fg: str = "#ad6800"
    tier_likely_bg: str = "#fff2e8"
    tier_likely_fg: str = "#d4380d"
    tier_strong_bg: str = "#fff1f0"
    tier_strong_fg: str = "#a8071a"


@dataclass(frozen=True)
class _Spacing:
    """4-8-12-16-24-32 scale. No other spacing values should appear in the UI."""

    xs: int = 4
    sm: int = 8
    md: int = 12
    lg: int = 16
    xl: int = 24
    xxl: int = 32


@dataclass(frozen=True)
class _Typography:
    """Typographic tokens. Sizes in pixels/pt depending on surface."""

    family: str = "Segoe UI"
    family_mono: str = "Consolas"

    size_body: int = 13
    size_caption: int = 11
    size_small: int = 12
    size_h1: int = 26
    size_h2: int = 18
    size_h3: int = 16


@dataclass(frozen=True)
class _Radius:
    sm: int = 3
    md: int = 4
    lg: int = 6
    pill: int = 10


COLORS = _Colors()
SPACING = _Spacing()
TYPOGRAPHY = _Typography()
RADIUS = _Radius()


# Pre-computed gradients used by the report/GUI so callers don't rebuild them.
GRADIENT_BRAND_HORIZONTAL = (
    f"linear-gradient(90deg, {COLORS.brand_cyan} 0%, "
    f"{COLORS.brand_indigo} 50%, {COLORS.brand_purple} 100%)"
)
GRADIENT_BRAND_SHORT = (
    f"linear-gradient(90deg, {COLORS.brand_cyan} 0%, {COLORS.brand_purple} 100%)"
)


def css_root_variables() -> str:
    """Emit a `:root { --token: value; ... }` block for inclusion in CSS.

    Every field on the COLORS dataclass becomes `--color-<name>`. Spacing
    becomes `--space-<name>`. Typography becomes `--font-size-<name>` /
    `--font-family`. Gives `report.css` (and any future stylesheet) a
    single place to reach for the brand values.
    """
    lines: list[str] = [":root {"]
    for name, value in vars(COLORS).items():
        lines.append(f"  --color-{name.replace('_', '-')}: {value};")
    for name, value in vars(SPACING).items():
        lines.append(f"  --space-{name}: {value}px;")
    lines.append(f"  --font-family: {TYPOGRAPHY.family}, -apple-system, Roboto, Helvetica, Arial, sans-serif;")
    lines.append(f"  --font-family-mono: {TYPOGRAPHY.family_mono}, monospace;")
    for name in ("body", "caption", "small", "h1", "h2", "h3"):
        lines.append(f"  --font-size-{name}: {getattr(TYPOGRAPHY, f'size_{name}')}px;")
    for name, value in vars(RADIUS).items():
        lines.append(f"  --radius-{name}: {value}px;")
    lines.append(f"  --gradient-brand: {GRADIENT_BRAND_HORIZONTAL};")
    lines.append(f"  --gradient-brand-short: {GRADIENT_BRAND_SHORT};")
    lines.append("}")
    return "\n".join(lines)


__all__ = [
    "COLORS",
    "SPACING",
    "TYPOGRAPHY",
    "RADIUS",
    "GRADIENT_BRAND_HORIZONTAL",
    "GRADIENT_BRAND_SHORT",
    "css_root_variables",
]
