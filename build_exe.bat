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

"%PY%" -m pip show pyinstaller >NUL 2>&1
if errorlevel 1 (
  echo  Installing PyInstaller into the venv...
  "%PY%" -m pip install --upgrade pyinstaller
  if errorlevel 1 (
    echo  ERROR: pip install pyinstaller failed.
    exit /b 1
  )
)

echo  Cleaning previous build artifacts...
if exist "%HERE%build"  rmdir /S /Q "%HERE%build"
if exist "%HERE%dist"   rmdir /S /Q "%HERE%dist"

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
