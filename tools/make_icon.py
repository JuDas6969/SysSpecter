"""Convert assets/icon.png to assets/icon.ico at build time.

Run once before PyInstaller picks up the .ico. Called from build_exe.bat.
Requires Pillow (listed in requirements-dev.txt).
"""

from __future__ import annotations

import os
import sys

from PIL import Image  # type: ignore[import-not-found]


SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    src = os.path.join(repo, "assets", "icon.png")
    dst = os.path.join(repo, "assets", "icon.ico")
    if not os.path.exists(src):
        print(f"make_icon: no source at {src}, skipping", file=sys.stderr)
        return 0
    img = Image.open(src).convert("RGBA")
    # Pillow can emit multi-resolution ICO directly.
    img.save(dst, format="ICO", sizes=SIZES)
    print(f"make_icon: wrote {dst} ({len(SIZES)} resolutions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
