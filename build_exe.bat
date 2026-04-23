@echo off
setlocal

REM Build a single-file, portable SysSpecter executable.
REM Output ends up at dist\SysSpecter.exe.
REM Run after install.bat has created .venv.

set "HERE=%~dp0"
set "VENV=%HERE%.venv"
set "PY=%VENV%\Scripts\python.exe"

if not exist "%PY%" (
  echo.
  echo  ERROR: Virtual environment not found at "%VENV%".
  echo  Run install.bat first to create it.
  echo.
  exit /b 1
)

echo.
echo ============================================================
echo  SysSpecter -- packaging single-file EXE
echo ============================================================

REM Make sure build-time dependencies are present at the pinned versions.
REM No --upgrade: a clean reinstall only fires if something is missing.
"%PY%" -m pip show pyinstaller >NUL 2>&1
if errorlevel 1 (
  echo  Installing pinned build-time dependencies from requirements-dev.txt...
  "%PY%" -m pip install -r "%HERE%requirements-dev.txt"
  if errorlevel 1 (
    echo  ERROR: pip install build requirements failed.
    exit /b 1
  )
)

if exist "%HERE%assets\icon.png" (
  echo  Generating multi-resolution icon.ico from assets\icon.png...
  "%PY%" "%HERE%tools\make_icon.py"
  if errorlevel 1 echo  WARNING: icon conversion failed; EXE will have the default icon.
) else (
  echo  [skip] No assets\icon.png found. EXE will have the default icon.
)

echo  Cleaning previous build artifacts...
if exist "%HERE%build"  rmdir /S /Q "%HERE%build"
if exist "%HERE%dist"   rmdir /S /Q "%HERE%dist"

REM Reproducible-ish build: if SOURCE_DATE_EPOCH is unset, pin it to the
REM tree's last-commit time. PyInstaller's bootloader still writes its own
REM timestamp, but the base_library.zip + hooked tools honour the envvar
REM so byte-stability of those components is restored.
if not defined SOURCE_DATE_EPOCH (
  for /f "tokens=*" %%i in ('git -C "%HERE%" log -1 --format=%%ct 2^>NUL') do (
    set "SOURCE_DATE_EPOCH=%%i"
  )
)
if defined SOURCE_DATE_EPOCH (
  echo  SOURCE_DATE_EPOCH=%SOURCE_DATE_EPOCH%
)

echo  Running PyInstaller...
"%PY%" -m PyInstaller "%HERE%sysspecter.spec" --clean --noconfirm
if errorlevel 1 (
  echo.
  echo  ERROR: PyInstaller failed. See output above.
  exit /b 1
)

if not exist "%HERE%dist\SysSpecter.exe" (
  echo  ERROR: expected dist\SysSpecter.exe was not produced.
  exit /b 1
)

REM Bundle LICENSE + third-party notices next to the EXE.
if exist "%HERE%LICENSE" copy /Y "%HERE%LICENSE" "%HERE%dist\LICENSE.txt" >NUL
if exist "%HERE%THIRD_PARTY_NOTICES.md" copy /Y "%HERE%THIRD_PARTY_NOTICES.md" "%HERE%dist\THIRD_PARTY_NOTICES.md" >NUL

REM Generate CycloneDX SBOM for the runtime dependency set.
"%PY%" -c "import cyclonedx_py" 2>NUL
if errorlevel 1 (
  echo  Skipping SBOM: cyclonedx-bom not installed -- run "pip install -r requirements-dev.txt" first.
) else (
  echo  Generating CycloneDX SBOM ...
  REM `environment` mode inspects the venv so the SBOM reflects what is
  REM actually bundled (includes transitive deps, not just top-level pins).
  "%PY%" -m cyclonedx_py environment -o "%HERE%dist\SysSpecter.sbom.json" --output-format JSON
  if errorlevel 1 (
    echo  WARNING: SBOM generation failed.
  ) else (
    echo  Wrote dist\SysSpecter.sbom.json
  )
)

REM SHA-256 checksum for the EXE (lets customers verify the drop).
certutil -hashfile "%HERE%dist\SysSpecter.exe" SHA256 > "%HERE%dist\SysSpecter.exe.sha256" 2>NUL

echo.
echo ============================================================
echo  Build OK
echo ============================================================
echo  Output: %HERE%dist\SysSpecter.exe
echo.
echo  Copy this EXE to a USB stick and run it on any Windows box.
echo  Default output root will be ^<stick^>\SysSpecter\Runs.
echo ============================================================
endlocal
