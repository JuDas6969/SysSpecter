@echo off
REM Launch the SysSpecter GUI without a stray console window.
REM Uses pythonw.exe from the venv so there is no flicker or extra cmd.
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0sysspecter.py" gui %*
