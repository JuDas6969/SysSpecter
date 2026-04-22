# Building SysSpecter

This file documents how to build SysSpecter from source, including the
portable USB executable, and covers the SmartScreen story + code-signing
roadmap.

## Prerequisites

- Windows 10 or 11 (x64).
- Python 3.12, 3.13, or 3.14 installed (either system-wide or via the
  `py` launcher). Python 3.12 is the safest because the widest wheel
  coverage is available there.
- Git for Windows (only needed if you are cloning from GitHub).

## Dev setup

```
install.bat
```

`install.bat` is idempotent. Re-running it reuses the existing `.venv`,
only resynchronising dependencies when their pinned versions in
`requirements.txt` have changed.

## Running the tests

```
.venv\Scripts\python.exe -m pip install "pytest>=8.0"
.venv\Scripts\python.exe -m pytest -q
```

The test suite covers the duration parser, manifest repair, and the
splitter's change-point detection. Expect ~30 fast tests.

## Packaging the portable single-file EXE

```
build_exe.bat
```

Output: `dist\SysSpecter.exe`, `dist\LICENSE.txt`,
`dist\THIRD_PARTY_NOTICES.md`.

What the script does:

1. Verifies that `.venv\Scripts\python.exe` exists (re-run `install.bat`
   if not).
2. Installs the pinned build-time deps (`pyinstaller`, `Pillow`) from
   `requirements-dev.txt` **only when missing**. No implicit upgrades.
3. Generates `assets\icon.ico` (multi-resolution 16/24/32/48/64/128/256)
   from `assets\icon.png` via `tools\make_icon.py`.
4. Cleans `build\` and `dist\`.
5. Runs `pyinstaller sysspecter.spec --clean --noconfirm`.
6. Copies `LICENSE` + `THIRD_PARTY_NOTICES.md` next to the EXE.

The resulting EXE is ~14 MB and self-contained. Dropping it on a USB
stick is enough — SysSpecter defaults its output root to
`<exe_dir>\SysSpecter\Runs\` when running as a PyInstaller-frozen
binary, so all reports stay on the stick.

## SmartScreen & unsigned binaries

The EXE is **not code-signed** at present. On a fresh Windows 10/11
machine, the first launch will likely show a blue "Windows protected
your PC — Windows Defender SmartScreen prevented an unrecognised app
from starting" dialog.

### Customer workaround (until a signed build ships)

1. When the dialog appears, click **"More info"**.
2. Click the new **"Run anyway"** button that appears.
3. Future launches of the same EXE on the same account are silent.

If IT policy blocks that dialog entirely, the fallback is to unblock
the file:

```
powershell -Command "Unblock-File -Path 'X:\SysSpecter.exe'"
```

### Roadmap: code signing

Shipping a signed build eliminates the SmartScreen warning for all
customers. The two viable options:

| Option | Cost | SmartScreen behaviour |
|---|---|---|
| **Self-signed / internal CA** | free | Still warned; cert must be imported into the machine's trust store first. Good for intra-company deployment. |
| **Standard OV certificate** | ~$200–400/year | No warning after the EXE accumulates a few downloads via Microsoft's reputation system (typically days–weeks). |
| **EV (Extended Validation) certificate** | ~$400–700/year + USB token | **No warning on first launch.** This is the only option that fully eliminates SmartScreen. |

For a customer-facing release, an **EV certificate is recommended**.
Integration into `build_exe.bat` is straightforward:

```bat
signtool sign /tr http://timestamp.sectigo.com /td sha256 ^
  /fd sha256 /a "%HERE%dist\SysSpecter.exe"
```

— add this step after PyInstaller, before the `LICENSE` copy. The
signing cert has to be plugged in (EV) or importable (OV).

## Reproducible builds

Versions are pinned exactly in `requirements.txt` and
`requirements-dev.txt`, so the same commit should produce functionally
equivalent binaries on different machines. Timestamps inside the EXE
still vary — that is by design and not security-relevant.

If bit-for-bit reproducibility is required (e.g. for supply-chain
audits), rebuild with `SOURCE_DATE_EPOCH` set and `-T` (no timestamps)
passed to `pyinstaller`. This is not scripted yet; raise an issue if
you need it.

## File layout of the build output

```
dist\
  SysSpecter.exe               (~14 MB, portable)
  LICENSE.txt
  THIRD_PARTY_NOTICES.md
```

Drop the three files together on a USB stick; when the EXE runs, it
writes its reports under `<stick>\SysSpecter\Runs\`.
