@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=testasp.vulnweb.com"

echo [*] Smart Recon V8.3 MAX bounded profile
echo [*] Authorized target: %TARGET%
echo [*] CDN/WAF edges and third-party SaaS are excluded from port scanning by default.

py -3 .\smart_subdomain_pipeline_v8_modular.py --target "%TARGET%" --authorized --max --workers auto --timeout 1800 --dnsx-workers 3 --dnsx-chunk-size 25000 --dnsx-threads 50 --dnsx-rate-limit 100 --dnsx-retries 2 --dnsx-chunk-timeout 1800 --dnsx-retry-failed-chunks 1 --wildcard-probes 3 --max-wildcard-zones 25 --katana-depth 5 --katana-concurrency 10 --katana-rate-limit 50 --katana-duration 10m --active-waf --waf-limit 15 --waf-request-timeout 7 --waf-stage-timeout 900 --port-scan --port-scan-limit 50 --naabu-top-ports 1000 --naabu-rate 100 --naabu-threads 25 --naabu-retries 2 --naabu-socket-timeout 1500 --port-scan-timeout 1800 --nmap-service-scan --nmap-workers 2 --nmap-host-timeout 5m --screenshot-limit 30 --screenshot-timeout 1800

set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo [SUCCESS] Recon completed.
) else if "%RC%"=="3" (
  echo [PARTIAL] Recon completed with partial requested stages.
) else (
  echo [FAILED] Recon exited with code %RC%.
)
exit /b %RC%
