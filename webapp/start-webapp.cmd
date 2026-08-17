@echo off
setlocal EnableExtensions
cd /d "%~dp0"

start "0xCrawller Backend" cmd /k call "%~dp0backend\start-backend.cmd"
start "0xCrawller Worker" cmd /k call "%~dp0backend\start-worker.cmd"
timeout /t 3 /nobreak >nul
start "0xCrawller Frontend" cmd /k call "%~dp0frontend\start-frontend.cmd"

echo.
echo Backend API: http://localhost:8000/docs
echo Web UI:      http://localhost:3000
echo.
endlocal
