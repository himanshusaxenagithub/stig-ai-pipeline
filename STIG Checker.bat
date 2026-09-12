@echo off
REM Same program as Start.bat; friendlier name when someone downloads the GitHub ZIP.
cd /d "%~dp0"
call "%~dp0Start.bat"
exit /b %ERRORLEVEL%
