@echo off
setlocal EnableExtensions EnableDelayedExpansion
title SysSpecter - Installer

echo ============================================================
echo   SysSpecter Installer
echo   See everything. Find the cause.
echo ============================================================
echo.
echo   Diese Installation fragt nach:
echo     1^) wo SysSpecter installiert werden soll
echo     2^) wo Python installiert werden soll ^(falls noch nicht da^)
echo.

rem ============================================================
rem  1) SysSpecter-Pfad bestimmen
rem ============================================================

set "HERE=%~dp0"
if "%HERE:~-1%" == "\" set "HERE=%HERE:~0,-1%"

set "IS_REPO=0"
if exist "%HERE%\sysspecter.py" set "IS_REPO=1"

set "SS_DIR="
if "%IS_REPO%" == "1" (
    echo Repository gefunden: %HERE%
    set /p "USE_HERE=In diesem Ordner installieren? [J/n]: "
    if /i "!USE_HERE!" == "n" (
        call :ask_ss_path
    ) else (
        set "SS_DIR=%HERE%"
    )
) else (
    call :ask_ss_path
)

echo.
echo   Installationspfad: !SS_DIR!
echo.

rem ============================================================
rem  2) Repo klonen, falls noetig
rem ============================================================

if not exist "!SS_DIR!\sysspecter.py" (
    where git >nul 2>&1
    if errorlevel 1 (
        echo [FEHLER] Git ist nicht installiert.
        echo.
        echo   Installiere Git fuer Windows:
        echo     winget install Git.Git
        echo   oder von https://git-scm.com/download/win
        echo.
        pause
        exit /b 1
    )

    if not exist "!SS_DIR!" (
        mkdir "!SS_DIR!" 2>nul
    )

    dir /b /a "!SS_DIR!" 2>nul | findstr "." >nul
    if not errorlevel 1 (
        echo [FEHLER] Zielordner ist nicht leer: !SS_DIR!
        echo   Bitte leeren Ordner waehlen oder Inhalt entfernen.
        pause
        exit /b 1
    )

    echo Klone SysSpecter von GitHub nach !SS_DIR! ...
    git clone https://github.com/JuDas6969/SysSpecter.git "!SS_DIR!"
    if errorlevel 1 (
        echo [FEHLER] git clone fehlgeschlagen.
        pause
        exit /b 1
    )
    echo.
)

rem ============================================================
rem  3) Python finden - falls nicht da, anbieten zu installieren
rem ============================================================

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
    echo Python 3.11/3.12/3.13/3.14 wurde nicht gefunden.
    echo.
    set /p "INST_PY=Python 3.12 jetzt per winget installieren? [J/n]: "
    if /i "!INST_PY!" == "n" (
        echo.
        echo   Bitte Python manuell installieren ^(Haken: "Add python.exe to PATH"^):
        echo     https://www.python.org/downloads/release/python-3127/
        echo   Danach install.bat erneut ausfuehren.
        pause
        exit /b 1
    )

    where winget >nul 2>&1
    if errorlevel 1 (
        echo [FEHLER] winget nicht verfuegbar.
        echo   Python manuell installieren: https://www.python.org/downloads/
        pause
        exit /b 1
    )

    set "PY_DIR="
    set /p "PY_DIR=Python-Installationspfad ^(leer = winget-Standard^): "

    if defined PY_DIR (
        echo Installiere Python 3.12 nach !PY_DIR! ...
        winget install --id Python.Python.3.12 --location "!PY_DIR!" --accept-package-agreements --accept-source-agreements --silent
    ) else (
        echo Installiere Python 3.12 ^(Standardpfad^) ...
        winget install --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent
    )
    if errorlevel 1 (
        echo [FEHLER] winget-Installation fehlgeschlagen.
        pause
        exit /b 1
    )

    rem PATH neu einlesen funktioniert im laufenden CMD nicht zuverlaessig,
    rem darum pruefen wir via py-Launcher ^(der ist nach Install sofort da^)
    py -3.12 -c "import sys" >nul 2>&1
    if errorlevel 1 (
        echo.
        echo Python wurde installiert, aber der py-Launcher ist in diesem
        echo Fenster noch nicht aktiv. Bitte:
        echo   1^) Dieses Fenster schliessen
        echo   2^) Neues PowerShell- oder CMD-Fenster oeffnen
        echo   3^) install.bat in !SS_DIR! erneut ausfuehren
        pause
        exit /b 0
    )
    set "PYEXE=py -3.12"
    set "PYTAG=3.12"
)

echo.
echo   Python %PYTAG% wird verwendet.
echo.

rem ============================================================
rem  4) Venv anlegen + Abhaengigkeiten
rem ============================================================

set "VENV=!SS_DIR!\.venv"

if exist "!VENV!\Scripts\python.exe" (
    echo Venv existiert bereits - ueberspringe Anlage.
) else (
    echo Lege virtuelles Python-Env an ^(.venv^) ...
    %PYEXE% -m venv "!VENV!"
    if errorlevel 1 (
        echo [FEHLER] venv konnte nicht angelegt werden.
        pause
        exit /b 1
    )
)

set "VPY=!VENV!\Scripts\python.exe"

echo Aktualisiere pip ...
"!VPY!" -m pip install --upgrade pip --quiet

echo Installiere Abhaengigkeiten ^(psutil, jinja2, pywin32^) ...
"!VPY!" -m pip install -r "!SS_DIR!\requirements.txt"
if errorlevel 1 (
    echo.
    echo [FEHLER] Abhaengigkeiten konnten nicht installiert werden.
    if "%PYTAG%" == "3.14" (
        echo   Tipp: Fuer Python 3.14 sind evtl. noch keine pywin32-Wheels da.
        echo   Installiere Python 3.12 und starte install.bat erneut.
    )
    pause
    exit /b 1
)

if exist "!VENV!\Scripts\pywin32_postinstall.py" (
    "!VPY!" "!VENV!\Scripts\pywin32_postinstall.py" -install >nul 2>&1
)

echo Teste Installation ...
"!VPY!" -c "import psutil, jinja2, win32api; print('ok')" >"%TEMP%\ss_install_check.txt" 2>&1
set /p CHECK=<"%TEMP%\ss_install_check.txt"
del "%TEMP%\ss_install_check.txt" >nul 2>&1

if /i not "!CHECK!" == "ok" (
    echo [FEHLER] Import-Check fehlgeschlagen:
    echo   !CHECK!
    pause
    exit /b 1
)

rem ============================================================
rem  5) Abschlussbanner
rem ============================================================

echo.
echo ============================================================
echo   Installation abgeschlossen ^(Python %PYTAG%^)
echo ============================================================
echo.
echo   SysSpecter:       !SS_DIR!
echo   Reports gehen nach: C:\Temp\SysSpecter\Runs\
echo.
echo   Naechste Schritte:
echo     cd !SS_DIR!
echo     .\sysspecter.bat monitor --mode support
echo         Laeuft bis Du stoppst ^(Ctrl+C oder "sysspecter.bat stop"^).
echo.
echo     .\sysspecter.bat monitor --mode support --phase3
echo         Inkl. GPU, Event-Log, ETW ^(ETW: als Admin starten^).
echo.
echo ============================================================
pause
exit /b 0


rem ============================================================
rem  Unter-Routine: SysSpecter-Pfad abfragen
rem ============================================================
:ask_ss_path
set "SS_DIR="
set /p "SS_DIR=Installationspfad fuer SysSpecter [C:\SysSpecter]: "
if not defined SS_DIR set "SS_DIR=C:\SysSpecter"
rem Trailing backslash entfernen
if "!SS_DIR:~-1!" == "\" set "SS_DIR=!SS_DIR:~0,-1!"
exit /b 0
