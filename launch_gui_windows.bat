@echo off
REM ============================================================
REM  P2 Scanner GUI Launcher
REM  Launches p2_gui.py using a windowed Python interpreter
REM  (no console flash). Pass-through args go to p2_gui.py,
REM  e.g.:  launch_gui.bat --config mysite.json
REM ============================================================

REM Switch to the directory this .bat lives in. p2_gui.py needs
REM to be next to p2_scanner.py and the JSON files.
cd /d "%~dp0"

REM Sanity check: make sure the GUI script is here.
if not exist "p2_gui.py" (
    echo ERROR: p2_gui.py not found in %CD%
    echo Place launch_gui.bat in the same folder as p2_gui.py.
    pause
    exit /b 1
)

REM Prefer the py launcher's windowed variant (pyw) — it ships with
REM every modern python.org install on Windows and avoids the
REM black console window that 'python' would leave open behind a
REM tkinter app.
where pyw >nul 2>nul
if %ERRORLEVEL%==0 (
    start "" pyw -3 "p2_gui.py" %*
    exit /b 0
)

REM Fallback: classic pythonw.exe on PATH.
where pythonw >nul 2>nul
if %ERRORLEVEL%==0 (
    start "" pythonw "p2_gui.py" %*
    exit /b 0
)

REM Last-resort fallback: regular python (will leave a console
REM window open, but at least the GUI launches).
where python >nul 2>nul
if %ERRORLEVEL%==0 (
    python "p2_gui.py" %*
    exit /b %ERRORLEVEL%
)

echo ERROR: No Python interpreter found on PATH.
echo Install Python 3.6 or later from https://www.python.org/
echo and make sure "Add Python to PATH" is checked during setup.
pause
exit /b 1
