@echo off
REM Double-click this file to open stig-ai-pipeline in your browser.
cd /d "%~dp0"
where py >nul 2>nul && (py -m stigui & goto done)
where python >nul 2>nul && (python -m stigui & goto done)
echo Python 3 is not installed.
echo Get it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
pause
exit /b 1
:done
pause
