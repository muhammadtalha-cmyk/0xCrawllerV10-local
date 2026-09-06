@echo off
setlocal
cd /d "%~dp0"

echo [1/4] Building WhatWeb 0.6.4...
docker build --pull -t 0xcrawller/whatweb:0.6.4 .\tools\whatweb || exit /b 1

echo [2/4] Building Retire.js 5.4.3...
docker build --pull -t 0xcrawller/retirejs:5.4.3 .\tools\retirejs || exit /b 1

echo [3/4] Building Wappalyzer Next 2.0.0 with Chromium...
docker build --pull --build-arg WAPPALYZER_NEXT_VERSION=2.0.0 -t 0xcrawller/wappalyzer-next:2.0.0 .\tools\wappalyzer-next || exit /b 1

echo [4/4] Pulling official ZGrab2 image...
docker pull ghcr.io/zmap/zgrab2:latest || exit /b 1

echo [5/5] Initializing Nuclei templates in crawller_nuclei_templates volume...
docker volume inspect crawller_nuclei_templates >nul 2>&1 || docker volume create crawller_nuclei_templates >nul
docker run --rm --entrypoint sh -v crawller_nuclei_templates:/root/nuclei-templates projectdiscovery/nuclei:latest -c "if [ ! -d /root/nuclei-templates/http ]; then echo 'Downloading Nuclei templates archive...' && wget -qO- https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.4.8.tar.gz | tar -xzf - -C /root/nuclei-templates --strip-components=1 && mkdir -p /root/.config/nuclei && cp /root/nuclei-templates/.nuclei-ignore /root/.config/nuclei/ 2>/dev/null || true; else echo 'Nuclei templates already initialized.'; fi" || exit /b 1

echo.
echo Technology intelligence scanner environment is ready.
docker image ls 0xcrawller/whatweb:0.6.4 0xcrawller/retirejs:5.4.3 0xcrawller/wappalyzer-next:2.0.0 ghcr.io/zmap/zgrab2:latest
endlocal
