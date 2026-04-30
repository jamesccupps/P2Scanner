@echo off
REM ============================================================
REM  P2 Scanner GUI Launcher
REM  Launches p2_gui.py using a windowed Python interpreter
REM  (no console flash). Pass-through args go to p2_gui.py,
REM  e.g.:  launch_gui_windows.bat --config mysite.json
REM
REM  IMPORTANT: this .bat file MUST be saved with Windows
REM  CRLF line endings. Unix LF-only line endings will cause
REM  cmd.exe to misparse the file and report "p2_gui.py not
REM  found" even when it's right there. If you see that error,
REM  open the .bat in Notepad and re-save it (Notepad always
REM  writes CRLF), or in your editor of choice change the line
REM  ending mode to CRLF / "Windows (CRLF)".
REM ============================================================

REM Switch to the directory this .bat lives in. p2_gui.py needs
REM to be next to p2_scanner.py and the JSON files.
cd /d "%~dp0"

REM Sanity check: make sure the GUI script is here.
REM Using single-line if-goto rather than parenthesized blocks
REM because parenthesized blocks are the part of cmd.exe most
REM sensitive to line-ending mangling.
if not exist "p2_gui.py" goto :no_gui

REM Prefer the py launcher's windowed variant (pyw) -- it ships with
REM every modern python.org install on Windows and avoids the
REM black console window that 'python' would leave open behind a
REM tkinter app.
where pyw >nul 2>nul
if %ERRORLEVEL%==0 goto :use_pyw

REM Fallback: classic pythonw.exe on PATH.
where pythonw >nul 2>nul
if %ERRORLEVEL%==0 goto :use_pythonw

REM Last-resort fallback: regular python (leaves a console
REM window open, but at least the GUI launches and you can see
REM tracebacks if something goes wrong).
where python >nul 2>nul
if %ERRORLEVEL%==0 goto :use_python

goto :no_python

:use_pyw
start "" pyw -3 "p2_gui.py" %*
exit /b 0

:use_pythonw
start "" pythonw "p2_gui.py" %*
exit /b 0

:use_python
python "p2_gui.py" %*
exit /b %ERRORLEVEL%

:no_gui
echo ERROR: p2_gui.py not found in %CD%
echo Place launch_gui_windows.bat in the same folder as p2_gui.py.
echo.
echo If p2_gui.py IS in this folder and you still see this error,
echo this .bat file probably has Unix line endings. Open it in
echo Notepad and save it again (Notepad writes Windows line
echo endings); that fixes it.
pause
exit /b 1

:no_python
echo ERROR: No Python interpreter found on PATH.
echo Install Python 3.6 or later from https://www.python.org/
echo and make sure "Add Python to PATH" is checked during setup.
pause
exit /b 1
