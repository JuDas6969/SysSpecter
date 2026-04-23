@echo off
setlocal EnableExtensions EnableDelayedExpansion
title SysSpecter - Installer

REM Handle --uninstall first so the header banner only shows for installs.
if /i "%~1"=="--uninstall" goto :uninstall
if /i "%~1"=="/uninstall" goto :uninstall

echo ============================================================
echo   SysSpecter Installer
echo   See everything. Find the cause.
echo ============================================================
echo.
echo   This installer will:
echo     1^) find or install a compatible Python ^(3.12 / 3.13 / 3.14^)
echo     2^) create a .venv in this folder
echo     3^) install pinned dependencies from requirements.txt
echo.
echo   Re-running install.bat is safe: existing venv is reused,
echo   and deps only get re-synced when versions don't match.
echo.

rem ============================================================
rem  1) Decide install path (default: same folder as this script)
rem ============================================================

set "HERE=%~dp0"
if "%HERE:~-1%" == "\" set "HERE=%HERE:~0,-1%"

set "IS_REPO=0"
if exist "%HERE%\sysspecter.py" set "IS_REPO=1"

set "SS_DIR="
if "%IS_REPO%" == "1" (
    echo Running from a SysSpecter checkout: %HERE%
    set "SS_DIR=%HERE%"
) else (
    call :ask_ss_path
)

echo.
echo   Install path: !SS_DIR!
echo.

rem ============================================================
rem  2) Clone the repo if SS_DIR is empty
rem ============================================================

if not exist "!SS_DIR!\sysspecter.py" (
    where git >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Git is not installed.
        echo.
        echo   Install Git for Windows first:
        echo     winget install Git.Git
        echo   or from https://git-scm.com/download/win
        echo.
        pause
        exit /b 1
    )

    if not exist "!SS_DIR!" (
        mkdir "!SS_DIR!" 2>nul
    )

    dir /b /a "!SS_DIR!" 2>nul | findstr "." >nul
    if not errorlevel 1 (
        echo [ERROR] Destination folder is not empty: !SS_DIR!
        echo   Pick an empty folder or delete its contents.
        pause
        exit /b 1
    )

    echo Cloning SysSpecter into !SS_DIR! ...
    git clone https://github.com/JuDas6969/SysSpecter.git "!SS_DIR!"
    if errorlevel 1 (
        echo [ERROR] git clone failed.
        pause
        exit /b 1
    )
    echo.
)

rem ============================================================
rem  3) Find Python, or offer to install 3.12
rem ============================================================

set "PYEXE="
set "PYTAG="

for %%V in (3.12 3.13 3.14) do (
    if not defined PYEXE (
        py -%%V -c "import sys" >nul 2>&1
        if !errorlevel! == 0 (
            set "PYEXE=py -%%V"
            set "PYTAG=%%V"
        )
    )
)

if not defined PYEXE (
    echo No compatible Python found ^(need 3.12 / 3.13 / 3.14^).
    echo.
    set /p "INST_PY=Install Python 3.12 via winget now? [Y/n]: "
    if /i "!INST_PY!" == "n" (
        echo.
        echo   Please install Python manually with "Add python.exe to PATH" ticked:
        echo     https://www.python.org/downloads/release/python-3127/
        echo   Then re-run install.bat.
        pause
        exit /b 1
    )

    where winget >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] winget is not available on this machine.
        echo   Install Python manually: https://www.python.org/downloads/
        pause
        exit /b 1
    )

    set "PY_DIR="
    set /p "PY_DIR=Python install path ^(empty = winget default^): "

    if defined PY_DIR (
        echo Installing Python 3.12 into !PY_DIR! ...
        winget install --id Python.Python.3.12 --location "!PY_DIR!" --accept-package-agreements --accept-source-agreements --silent
    ) else (
        echo Installing Python 3.12 ^(default path^) ...
        winget install --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent
    )
    if errorlevel 1 (
        echo [ERROR] winget install failed.
        pause
        exit /b 1
    )

    py -3.12 -c "import sys" >nul 2>&1
    if errorlevel 1 (
        echo.
        echo Python was installed but the py launcher is not visible in this
        echo shell yet. Please:
        echo   1^) close this window
        echo   2^) open a fresh CMD / PowerShell
        echo   3^) re-run install.bat in !SS_DIR!
        pause
        exit /b 0
    )
    set "PYEXE=py -3.12"
    set "PYTAG=3.12"
)

echo.
echo   Using Python %PYTAG%.
echo.

rem ============================================================
rem  4) Venv + pinned dependencies
rem ============================================================

set "VENV=!SS_DIR!\.venv"

if exist "!VENV!\Scripts\python.exe" (
    echo Re-using existing venv at !VENV!
) else (
    echo Creating virtual environment ^(.venv^) ...
    %PYEXE% -m venv "!VENV!"
    if errorlevel 1 (
        echo [ERROR] Could not create the venv.
        pause
        exit /b 1
    )
)

set "VPY=!VENV!\Scripts\python.exe"

echo Upgrading pip ...
"!VPY!" -m pip install --upgrade pip --quiet

echo Installing pinned runtime dependencies from requirements.txt ...
"!VPY!" -m pip install --quiet -r "!SS_DIR!\requirements.txt"
if errorlevel 1 (
    echo.
    echo [ERROR] Dependency install failed.
    if "%PYTAG%" == "3.14" (
        echo   Hint: on Python 3.14 some wheels may still be missing.
        echo   Try Python 3.12 or 3.13 and re-run install.bat.
    )
    pause
    exit /b 1
)

if exist "!VENV!\Scripts\pywin32_postinstall.py" (
    "!VPY!" "!VENV!\Scripts\pywin32_postinstall.py" -install >nul 2>&1
)

echo Verifying install ...
"!VPY!" -c "import psutil, jinja2, win32api; print('ok')" >"%TEMP%\ss_install_check.txt" 2>&1
set /p CHECK=<"%TEMP%\ss_install_check.txt"
del "%TEMP%\ss_install_check.txt" >nul 2>&1

if /i not "!CHECK!" == "ok" (
    echo [ERROR] Import check failed:
    echo   !CHECK!
    pause
    exit /b 1
)

rem ============================================================
rem  5) Summary
rem ============================================================

echo.
echo ============================================================
echo   Installation complete ^(Python %PYTAG%^)
echo ============================================================
echo.
echo   SysSpecter:       !SS_DIR!
echo   Reports go to:    C:\Temp\SysSpecter\Runs\
echo.
echo   Quick start:
echo     cd !SS_DIR!
echo     .\sysspecter-gui.bat               ^(open the GUI^)
echo     .\sysspecter.bat monitor --mode support
echo     .\sysspecter.bat monitor --mode support --phase3   ^(admin for ETW^)
echo     .\build_exe.bat                    ^(package a portable EXE^)
echo.
echo ============================================================
pause
exit /b 0


rem ============================================================
rem  Sub-routine: ask for install path
rem ============================================================
:ask_ss_path
set "SS_DIR="
set /p "SS_DIR=Install path for SysSpecter [C:\SysSpecter]: "
if not defined SS_DIR set "SS_DIR=C:\SysSpecter"
if "!SS_DIR:~-1!" == "\" set "SS_DIR=!SS_DIR:~0,-1!"
exit /b 0


rem ============================================================
rem  Uninstall entry point
rem ============================================================
:uninstall
title SysSpecter - Uninstaller
echo ============================================================
echo   SysSpecter Uninstaller
echo ============================================================
echo.
set "HERE=%~dp0"
if "%HERE:~-1%" == "\" set "HERE=%HERE:~0,-1%"

if not exist "%HERE%\sysspecter.py" (
    echo [ERROR] This does not look like a SysSpecter folder:
    echo   %HERE%
    pause
    exit /b 1
)

echo SysSpecter folder: %HERE%
echo.
echo This will delete the following items from the folder:
echo   - .venv\  (virtual environment)
echo   - build\  (PyInstaller intermediates)
echo   - dist\   (the packaged EXE + artefacts)
echo.
echo Source files (sysspecter.py, sysspecter\, assets\, docs) are KEPT.
echo.
set /p "CONFIRM=Continue? [y/N]: "
if /i not "!CONFIRM!"=="y" (
    echo Aborted.
    pause
    exit /b 0
)

if exist "%HERE%\.venv"  rmdir /S /Q "%HERE%\.venv"
if exist "%HERE%\build"  rmdir /S /Q "%HERE%\build"
if exist "%HERE%\dist"   rmdir /S /Q "%HERE%\dist"

echo.
echo Uninstall complete. Reports under %%TEMP%%\SysSpecter (or your
echo custom output-root) were NOT touched -- delete them manually if
echo you want to reclaim the space.
echo.
pause
exit /b 0
