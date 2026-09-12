@echo off
REM Double-click this to produce STIG Checker, the program you hand to other people.
cd /d "%~dp0"
python packaging\build_portable.py
if errorlevel 1 (pause & exit /b 1)
start "" explorer dist
echo.
echo dist\ now holds STIG Checker (under windows\) and STIG-Checker-Windows.zip.
echo The zip is what you send. They unzip it and double-click STIG Checker.
echo.
pause
