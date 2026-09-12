@echo off
REM Double-click this file to open stig-ai-pipeline in your browser.
cd /d "%~dp0"

if not exist "stigui\" (
  echo Keep Start.bat inside the unzipped folder, next to stigui.
  pause
  exit /b 1
)

if exist "run-hidden.vbs" (
  REM //nologo, and wscript itself has no console, so nothing flashes on screen.
  wscript //nologo "run-hidden.vbs"
  exit /b 0
)

REM run-hidden.vbs missing: fall back to running here directly.
where py >nul 2>nul && (py -m stigui --app & goto done)
where pythonw >nul 2>nul && (start "" pythonw -m stigui --app & goto done)
where python >nul 2>nul && (python -m stigui --app & goto done)
echo Python 3 is not installed.
echo Get it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
start "" "https://www.python.org/downloads/"
pause
exit /b 1
:done
