@echo off
setlocal EnableExtensions

REM ============================================================
REM Smart Recon V8.5.1 - MAX parallel recursive recon (3 levels)
REM Usage: run-max-v8.5.1-recursive.cmd sky47.com.pk
REM Authorized targets only.
REM ============================================================

set "PROJECT_DIR=E:\crawllerPhase2\0xCrawllerV2\smart_subdomain_pipeline_v8_modular"
set "VENV_ACTIVATE=E:\crawllerPhase2\venv\Scripts\activate.bat"
set "TARGET=%~1"

if "%TARGET%"=="" (
  echo [ERROR] Target domain is required.
  echo Usage: %~nx0 sky47.com.pk
  exit /b 2
)

if exist "%VENV_ACTIVATE%" call "%VENV_ACTIVATE%"
cd /d "%PROJECT_DIR%"

if not exist ".env" (
  echo [ERROR] Missing %PROJECT_DIR%\.env
  exit /b 2
)

for /f "tokens=1,* delims==" %%A in ('findstr /B /C:"SHODAN_API_KEY=" ".env"') do set "SHODAN_VALUE=%%B"
if not defined SHODAN_VALUE (
  echo [ERROR] SHODAN_API_KEY is empty in .env
  exit /b 2
)

echo.
echo ============================================================
echo Smart Recon V8.5.1 MAX recursive profile
echo Target: %TARGET%
echo Recursive depth: 3 descendant levels
echo Parallel recursive workers: 4
echo Shodan passive enrichment: enabled
echo WAFW00F: enabled
echo Naabu candidates + independent Nmap reconciliation: enabled
echo Third-party/CDN direct port scanning: excluded by default
echo ============================================================
echo.

python .\smart_subdomain_pipeline_v8_modular.py ^
  --target "%TARGET%" ^
  --authorized ^
  --max ^
  --workers auto ^
  --timeout 1800 ^
  --dnsx-workers 3 ^
  --dnsx-chunk-size 25000 ^
  --dnsx-threads 50 ^
  --dnsx-rate-limit 100 ^
  --dnsx-retries 2 ^
  --dnsx-chunk-timeout 1800 ^
  --dnsx-retry-failed-chunks 1 ^
  --wildcard-probes 3 ^
  --max-wildcard-zones 50 ^
  --katana-depth 5 ^
  --katana-concurrency 10 ^
  --katana-rate-limit 50 ^
  --katana-duration 10m ^
  --recursive-recon ^
  --recursive-depth 3 ^
  --recursive-workers 4 ^
  --recursive-max-hosts 250 ^
  --recursive-katana-depth 3 ^
  --recursive-katana-duration 2m ^
  --recursive-katana-concurrency 5 ^
  --recursive-katana-rate-limit 20 ^
  --recursive-stage-timeout 900 ^
  --shodan-passive ^
  --env-file .env ^
  --shodan-dorks-file shodan_dorks.json ^
  --shodan-max-query-credits 10 ^
  --shodan-domain-pages 1 ^
  --shodan-max-dorks 12 ^
  --shodan-pages-per-query 1 ^
  --shodan-results-per-query 100 ^
  --shodan-max-host-lookups 100 ^
  --shodan-timeout 20 ^
  --shodan-api-rps 1 ^
  --shodan-cache-ttl-hours 24 ^
  --active-waf ^
  --waf-limit 30 ^
  --waf-request-timeout 7 ^
  --waf-stage-timeout 900 ^
  --port-scan ^
  --port-scan-limit 75 ^
  --naabu-top-ports 1000 ^
  --naabu-rate 100 ^
  --naabu-threads 25 ^
  --naabu-retries 2 ^
  --naabu-socket-timeout 1500 ^
  --port-scan-timeout 1800 ^
  --nmap-service-scan ^
  --nmap-workers 2 ^
  --nmap-host-timeout 5m ^
  --screenshot-limit 50 ^
  --screenshot-timeout 1800

set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo [COMPLETE] Recon finished.
) else if "%RC%"=="3" (
  echo [PARTIAL] Recon completed with incomplete requested coverage.
) else (
  echo [FAILED] Recon exited with code %RC%.
)
echo Results: %PROJECT_DIR%\recon_runs
exit /b %RC%
