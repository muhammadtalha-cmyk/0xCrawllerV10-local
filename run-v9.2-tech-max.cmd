@echo off
setlocal
cd /d "%~dp0"

set "VENV_ACTIVATE=%~dp0.venv\Scripts\activate.bat"
if not exist "%VENV_ACTIVATE%" set "VENV_ACTIVATE=E:\crawllerPhase2\venv\Scripts\activate.bat"
if exist "%VENV_ACTIVATE%" call "%VENV_ACTIVATE%"

if "%~1"=="" (
  echo Usage: run-v9.2-tech-max.cmd domain.com
  exit /b 2
)

python .\vapt_technology_enricher_v9_2.py ^
  --target "%~1" ^
  --latest-root .\recon_runs ^
  --normalize-if-missing ^
  --authorized ^
  --max ^
  --overwrite ^
  --workers 5 ^
  --http-workers 8 ^
  --js-workers 10 ^
  --service-workers 4 ^
  --whatweb-threads 12 ^
  --wappalyzer-next-workers 3 ^
  --wappalyzer-next-balanced-workers 10 ^
  --wappalyzer-next-full-target-cap 30 ^
  --wappalyzer-next-page-timeout 25 ^
  --request-timeout 10 ^
  --lane-timeout 1800

endlocal