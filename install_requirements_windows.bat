@echo off
setlocal enabledelayedexpansion
REM ============================================================
REM  P2 Scanner Installer (Windows)
REM ============================================================
REM  Installs everything needed to run the GUI launcher:
REM    [1] Python 3.6+ (via winget, if missing)
REM    [2] Verifies tkinter is available
REM    [3] Optional: tshark (Wireshark CLI) for --sniff mode
REM    [4] Optional: desktop shortcut to the GUI launcher
REM
REM  Auto-detects launch_gui*.bat (handles renamed launchers
REM  like launch_gui_windows.bat).
REM
REM  Safe to re-run. Skips anything already in place.
REM  Does not require admin -- winget runs in user scope.
REM ============================================================

cd /d "%~dp0"

echo.
echo ============================================================
echo   P2 Scanner Setup
echo ============================================================
echo.

REM ---------- Sanity check: are we in the right folder? ----------
if not exist "p2_gui.py" (
    echo ERROR: p2_gui.py not found in %CD%
    echo Place this installer in the same folder as p2_gui.py.
    pause
    exit /b 1
)

REM ============================================================
REM  [1/3] Python
REM ============================================================
echo [1/3] Checking for Python 3.6+ ...

set "PYTHON_OK=0"
set "PYTHON_FOUND="
for %%I in (py pyw python pythonw) do (
    if !PYTHON_OK!==0 (
        where %%I >nul 2>nul
        if !ERRORLEVEL!==0 (
            for /f "delims=" %%V in ('%%I -c "import sys;print(\"OK\" if sys.version_info>=(3,6) else \"OLD\")" 2^>nul') do (
                if "%%V"=="OK" (
                    set "PYTHON_OK=1"
                    set "PYTHON_FOUND=%%I"
                )
            )
        )
    )
)

if !PYTHON_OK!==1 (
    echo       Python is already installed ^(detected: !PYTHON_FOUND!^).
    goto :python_done
)

echo       Python 3.6+ not found. Attempting install via winget ...
echo.

where winget >nul 2>nul
if !ERRORLEVEL! NEQ 0 (
    echo       ERROR: winget is not available on this system.
    echo       Install Python 3.6+ manually from:
    echo           https://www.python.org/downloads/
    echo       Make sure "Add Python to PATH" is checked during setup.
    echo       Then re-run this installer.
    pause
    exit /b 1
)

winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
if !ERRORLEVEL! NEQ 0 (
    echo.
    echo       ERROR: winget install failed.
    echo       Install Python 3.6+ manually from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo.
echo       Python installed. Refreshing PATH for this session ...
REM Pull updated PATH from registry so we don't have to make the
REM user reopen the shell. Best effort -- if it fails, we warn below.
for /f "usebackq tokens=2,*" %%A in (`reg query "HKCU\Environment" /v PATH 2^>nul`) do set "USRPATH=%%B"
for /f "usebackq tokens=2,*" %%A in (`reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul`) do set "SYSPATH=%%B"
if defined SYSPATH set "PATH=!SYSPATH!"
if defined USRPATH set "PATH=!PATH!;!USRPATH!"

REM Re-check after install
set "PYTHON_FOUND="
where py >nul 2>nul && set "PYTHON_FOUND=py"
if not defined PYTHON_FOUND (
    where python >nul 2>nul && set "PYTHON_FOUND=python"
)
if not defined PYTHON_FOUND (
    echo       NOTE: Python installed but not yet on PATH for this shell.
    echo             Close this window and re-run the installer to verify,
    echo             or just open a new shell and run the GUI launcher.
    pause
    exit /b 0
)

:python_done

REM ============================================================
REM  [2/3] tkinter
REM ============================================================
echo.
echo [2/3] Checking for tkinter ...

%PYTHON_FOUND% -c "import tkinter" >nul 2>nul
if !ERRORLEVEL!==0 (
    echo       tkinter is available.
) else (
    echo       WARNING: tkinter is not available for !PYTHON_FOUND!.
    echo       The python.org installer includes tkinter by default.
    echo       Reinstall Python with default options to get it.
    echo       The GUI will not launch without tkinter.
)

REM ============================================================
REM  [3/3] Optional extras
REM ============================================================
echo.
echo [3/3] Optional extras
echo.

REM ---- tshark ----
where tshark >nul 2>nul
if !ERRORLEVEL!==0 (
    echo       tshark is already installed.
) else (
    echo       tshark is used only by --sniff discovery mode.
    set /p "INSTALL_TSHARK=      Install Wireshark/tshark now? (y/N): "
    if /i "!INSTALL_TSHARK!"=="y" (
        where winget >nul 2>nul
        if !ERRORLEVEL!==0 (
            winget install -e --id WiresharkFoundation.Wireshark --accept-source-agreements --accept-package-agreements
        ) else (
            echo       winget not available. Install manually from https://www.wireshark.org/
        )
    )
)

REM ---- desktop shortcut ----
echo.
set /p "MAKE_SHORTCUT=      Create desktop shortcut to the GUI? (y/N): "
if /i "!MAKE_SHORTCUT!"=="y" (
    REM Auto-detect the launcher -- handles renames like launch_gui_windows.bat
    set "LAUNCHER="
    for /f "delims=" %%F in ('dir /b /a-d "launch_gui*.bat" 2^>nul') do (
        if not defined LAUNCHER set "LAUNCHER=%%F"
    )
    if defined LAUNCHER (
        echo       Using launcher: !LAUNCHER!
        powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $desktop = [Environment]::GetFolderPath('Desktop'); $sc = $ws.CreateShortcut((Join-Path $desktop 'P2 Scanner.lnk')); $sc.TargetPath = (Join-Path '%~dp0' '!LAUNCHER!'); $sc.WorkingDirectory = '%~dp0'; $sc.IconLocation = 'imageres.dll,109'; $sc.Save()" >nul 2>nul
        if !ERRORLEVEL!==0 (
            echo       Shortcut created on Desktop: P2 Scanner.lnk
        ) else (
            echo       Could not create shortcut ^(PowerShell unavailable?^).
        )
    ) else (
        echo       No launch_gui*.bat found in %CD% -- skipping shortcut.
        echo       Place a Windows launcher next to this installer first.
    )
)

echo.
echo ============================================================
echo   Setup complete.
echo ============================================================
echo.
REM Show the user which launcher to run, since we know its name now.
set "LAUNCHER_FINAL="
for /f "delims=" %%F in ('dir /b /a-d "launch_gui*.bat" 2^>nul') do (
    if not defined LAUNCHER_FINAL set "LAUNCHER_FINAL=%%F"
)
if defined LAUNCHER_FINAL (
    echo   Run the GUI by double-clicking !LAUNCHER_FINAL!
) else (
    echo   Run the GUI by double-clicking your launch_gui*.bat
)
echo ============================================================
echo.
pause
exit /b 0
