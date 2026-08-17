@echo off
setlocal EnableExtensions

REM ============================================================
REM 0xCrawller V10 Combined Intelligence Report
REM Reads the latest Recon + Normalization + Technology outputs.
REM Usage:
REM   run-v10-combined-report.cmd hiapp.pk
REM Optional custom recon root:
REM   run-v10-combined-report.cmd hiapp.pk E:\path\to\recon_runs
REM ============================================================

cd /d "%~dp0"
set "TARGET=%~1"
set "RUN_ROOT=%~2"
set "VENV_ACTIVATE=E:\crawllerPhase2\venv\Scripts\activate.bat"

if "%TARGET%"=="" (
  echo [ERROR] Target domain is required.
  echo Usage: %~nx0 hiapp.pk
  exit /b 2
)

if "%RUN_ROOT%"=="" set "RUN_ROOT=.\recon_runs"
if exist "%VENV_ACTIVATE%" call "%VENV_ACTIVATE%"

python .\vapt_combined_report_v10.py ^
  --target "%TARGET%" ^
  --latest-root "%RUN_ROOT%" ^
  --overwrite

set "RC=%ERRORLEVEL%"
if "%RC%"=="0" (
  echo [COMPLETE] Open the latest run folder and read combined_vapt_intelligence_report.md
) else (
  echo [FAILED] Combined report generation exited with code %RC%.
)
exit /b %RC%
