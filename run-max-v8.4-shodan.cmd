@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=hiapp.pk"

py -3 .\smart_subdomain_pipeline_v8_modular.py --target "%TARGET%" --authorized --max --workers auto --timeout 1800 --dnsx-workers 3 --dnsx-chunk-size 25000 --dnsx-threads 50 --dnsx-rate-limit 100 --dnsx-retries 2 --wildcard-probes 3 --max-wildcard-zones 25 --katana-depth 5 --katana-concurrency 10 --katana-rate-limit 50 --katana-duration 10m --shodan-passive --shodan-max-query-credits 10 --shodan-domain-pages 1 --shodan-max-dorks 12 --shodan-pages-per-query 1 --shodan-results-per-query 100 --shodan-max-host-lookups 100 --active-waf --waf-limit 15 --port-scan --port-scan-limit 50 --naabu-top-ports 1000 --naabu-rate 100 --naabu-threads 25 --nmap-service-scan --nmap-workers 2 --screenshot-limit 30

exit /b %ERRORLEVEL%
