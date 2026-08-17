@echo off
setlocal
cd /d "%~dp0"

echo [1/4] Building WhatWeb 0.6.4...
docker build --pull -t 0xcrawller/whatweb:0.6.4 .\tools\whatweb || exit /b 1

echo [2/4] Building Retire.js 5.4.3...
docker build --pull -t 0xcrawller/retirejs:5.4.3 .\tools\retirejs || exit /b 1

echo [3/4] Building Wappalyzer Next 2.0.0 with Chromium...
docker build --pull --build-arg WAPPALYZER_NEXT_VERSION=v2.0.0 -t 0xcrawller/wappalyzer-next:2.0.0 .\tools\wappalyzer-next || exit /b 1

echo [4/4] Pulling official ZGrab2 image...
docker pull ghcr.io/zmap/zgrab2:latest || exit /b 1

echo.
echo V9.2 technology intelligence images are ready.
docker image ls 0xcrawller/whatweb:0.6.4 0xcrawller/retirejs:5.4.3 0xcrawller/wappalyzer-next:2.0.0 ghcr.io/zmap/zgrab2:latest
endlocal
