@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [SETUP] Creating backend virtual environment...
  py -3 -m venv .venv || exit /b 1
)
call ".venv\Scripts\activate.bat"
python -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
  echo [SETUP] Installing backend dependencies...
  python -m pip install --upgrade pip || exit /b 1
  python -m pip install -r requirements.txt || exit /b 1
)

if exist ".env" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do set "%%A=%%B"
)

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
