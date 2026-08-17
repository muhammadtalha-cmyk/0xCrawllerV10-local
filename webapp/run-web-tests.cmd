@echo off
setlocal EnableExtensions
cd /d "%~dp0.."

python -m pytest -q
if errorlevel 1 exit /b %ERRORLEVEL%

echo [COMPLETE] Original scanner and web backend tests passed.
