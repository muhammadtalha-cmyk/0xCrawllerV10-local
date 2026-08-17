@echo off
setlocal EnableExtensions

REM ============================================================
REM 0xCrawller V9 Asset Validation and Normalization
REM Usage:
REM   run-v9-normalize.cmd sky47.com.pk
REM Optional custom recon root:
REM   run-v9-normalize.cmd sky47.com.pk E:\path\to\recon_runs
REM ============================================================

cd /d "%~dp0"
set "TARGET=%~1"
set "RUN_ROOT=%~2"
set "VENV_ACTIVATE=E:\crawllerPhase2\venv\Scripts\activate.bat"

if "%TARGET%"=="" (
  echo [ERROR] Target domain is required.
  echo Usage: %~nx0 sky47.com.pk
  exit /b 2
)
if "%RUN_ROOT%"=="" set "RUN_ROOT=.\recon_runs"

if exist "%VENV_ACTIVATE%" call "%VENV_ACTIVATE%"

python .\vapt_asset_normalizer_v9.py --target "%TARGET%" --latest-root "%RUN_ROOT%" --overwrite
set "RC=%ERRORLEVEL%"

if "%RC%"=="0" (
  echo [COMPLETE] V9 normalization outputs were written inside the latest run folder.
) else (
  echo [FAILED] V9 exited with code %RC%.
)
exit /b %RC%
