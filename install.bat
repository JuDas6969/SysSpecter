@echo off
setlocal EnableExtensions EnableDelayedExpansion
title SysSpecter - Installer

set "HERE=%~dp0"
pushd "%HERE%" >nul

echo ============================================================
echo   SysSpecter Installer
echo   See everything. Find the cause.
echo ============================================================
echo.

rem --- 1. Find a usable Python (3.12 preferred, 3.14 fallback) -------------

set "PYEXE="
set "PYTAG="

for %%V in (3.12 3.14 3.13 3.11) do (
    if not defined PYEXE (
        py -%%V -c "import sys" >nul 2>&1
        if !errorlevel! == 0 (
            set "PYEXE=py -%%V"
            set "PYTAG=%%V"
        )
    )
)

if not defined PYEXE (
    echo [FEHLER] Keine passende Python-Version gefunden ^(3.11 / 3.12 / 3.13 / 3.14^).
    echo.
    echo   Installiere Python 3.12 ^(empfohlen^):
    echo     winget install Python.Python.3.12
    echo   oder von https://www.python.org/downloads/
    echo.
    echo   Wichtig beim Installer: "Add python.exe to PATH" anhaken.
    echo.
    popd >nul
    pause
    exit /b 1
)

echo [1/5] Python %PYTAG% gefunden.

rem --- 2. Create / refresh venv -------------------------------------------

if exist "%HERE%.venv\Scripts\python.exe" (
    echo [2/5] Venv existiert bereits - ueberspringe Anlage.
) else (
    echo [2/5] Lege virtuelles Python-Env an ^(.venv^) ...
    %PYEXE% -m venv "%HERE%.venv"
    if errorlevel 1 (
        echo [FEHLER] venv konnte nicht angelegt werden.
        popd >nul
        pause
        exit /b 1
    )
)

set "VPY=%HERE%.venv\Scripts\python.exe"

if not exist "%VPY%" (
    echo [FEHLER] venv unvollstaendig: %VPY% fehlt.
    popd >nul
    pause
    exit /b 1
)

rem --- 3. Install dependencies --------------------------------------------

echo [3/5] Aktualisiere pip ...
"%VPY%" -m pip install --upgrade pip --quiet
if errorlevel 1 (
    echo [WARN] pip-Upgrade fehlgeschlagen - versuche trotzdem weiter.
)

echo [4/5] Installiere Abhaengigkeiten ^(psutil, jinja2, pywin32^) ...
"%VPY%" -m pip install -r "%HERE%requirements.txt"
if errorlevel 1 (
    echo.
    echo [FEHLER] Abhaengigkeiten konnten nicht installiert werden.
    if "%PYTAG%" == "3.14" (
        echo   Tipp: Fuer Python 3.14 gibt es evtl. noch keine pywin32-Wheels.
        echo   Installiere Python 3.12 und starte install.bat erneut.
    )
    popd >nul
    pause
    exit /b 1
)

rem --- 4. pywin32 post-install (best-effort) ------------------------------

set "PWPOST=%HERE%.venv\Scripts\pywin32_postinstall.py"
if exist "%PWPOST%" (
    "%VPY%" "%PWPOST%" -install >nul 2>&1
)

rem --- 5. Smoke test ------------------------------------------------------

echo [5/5] Teste Installation ...
"%VPY%" -c "import psutil, jinja2, win32api; print('ok')" >"%TEMP%\sysspecter_install_check.txt" 2>&1
set /p CHECK=<"%TEMP%\sysspecter_install_check.txt"
del "%TEMP%\sysspecter_install_check.txt" >nul 2>&1

if /i not "%CHECK%" == "ok" (
    echo [FEHLER] Import-Check fehlgeschlagen:
    echo   %CHECK%
    popd >nul
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   Installation abgeschlossen ^(Python %PYTAG%^)
echo ============================================================
echo.
echo   Naechste Schritte:
echo.
echo     .\sysspecter.bat monitor --mode support
echo         Laeuft bis Du stoppst. Ideal fuer "ist langsam"-Analyse.
echo.
echo     .\sysspecter.bat monitor --mode support --phase3
echo         Inkl. GPU, Event-Log und ETW ^(ETW: PowerShell als Admin^).
echo.
echo     .\sysspecter.bat stop
echo         Stoppt die laufende Session aus einem zweiten Fenster.
echo.
echo   Reports landen unter:  C:\Temp\SysSpecter\Runs\
echo.
echo ============================================================

popd >nul
endlocal
pause
