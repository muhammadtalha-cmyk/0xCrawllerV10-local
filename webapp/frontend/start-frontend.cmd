@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if not exist "node_modules" (
  echo [SETUP] Installing frontend dependencies...
  call npm install || exit /b 1
)

if exist ".env.local" (
  echo [INFO] Using .env.local
) else if exist ".env.example" (
  copy /Y ".env.example" ".env.local" >nul
  echo [SETUP] Created .env.local. Verify NEXT_PUBLIC_API_URL if backend is not local.
)

call npm run dev
