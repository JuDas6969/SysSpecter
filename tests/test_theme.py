"""Tests for the design-token layer."""

from __future__ import annotations

from sysspecter.theme import (
    COLORS,
    GRADIENT_BRAND_HORIZONTAL,
    GRADIENT_BRAND_SHORT,
    RADIUS,
    SPACING,
    TYPOGRAPHY,
    css_root_variables,
)


def test_colors_are_hex() -> None:
    for name, value in vars(COLORS).items():
        assert isinstance(value, str), name
        assert value.startswith("#"), name
        # 6 hex digits plus the leading '#'
        assert len(value) == 7, f"{name} = {value}"


def test_spacing_scale_monotonic() -> None:
    scale = [SPACING.xs, SPACING.sm, SPACING.md, SPACING.lg,
             SPACING.xl, SPACING.xxl]
    assert scale == sorted(scale)


def test_typography_sane_font_sizes() -> None:
    # body is smaller than h3 is smaller than h2 is smaller than h1
    assert TYPOGRAPHY.size_body < TYPOGRAPHY.size_h3
    assert TYPOGRAPHY.size_h3 <= TYPOGRAPHY.size_h2
    assert TYPOGRAPHY.size_h2 < TYPOGRAPHY.size_h1


def test_radius_strictly_monotonic() -> None:
    assert RADIUS.sm < RADIUS.md < RADIUS.lg < RADIUS.pill


def test_gradients_reference_brand_anchors() -> None:
    # the brand short gradient should go from cyan to purple and
    # the horizontal version should include the indigo mid-stop.
    assert COLORS.brand_cyan in GRADIENT_BRAND_SHORT
    assert COLORS.brand_purple in GRADIENT_BRAND_SHORT
    assert COLORS.brand_indigo in GRADIENT_BRAND_HORIZONTAL


def test_css_root_variables_includes_every_color() -> None:
    css = css_root_variables()
    for name in vars(COLORS):
        # dataclass field `brand_cyan` -> CSS variable `--color-brand-cyan`
        tok = f"--color-{name.replace('_', '-')}"
        assert tok in css, tok
    assert ":root {" in css
    assert css.endswith("}")
    assert "--gradient-brand:" in css
