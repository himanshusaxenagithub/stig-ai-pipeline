@echo off
REM Double-click this to build the folder you hand to someone else.
REM It puts stig-ai-pipeline-windows\ and a .zip of it into dist\.
cd /d "%~dp0"
python packaging\build_portable.py
echo.
echo The zip in dist\ is what you send people. They unzip it and
echo double-click Start.bat. They do not need Python.
echo.
pause
