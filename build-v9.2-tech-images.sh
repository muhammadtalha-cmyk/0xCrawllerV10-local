#!/usr/bin/env bash
# ============================================================
# build-v9.2-tech-images.sh — Build local technology scanner images
# macOS / Linux equivalent of build-v9.2-tech-images.cmd
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FORCE_REBUILD="${1:-}"

# 1. WhatWeb 0.6.4
if [ "$FORCE_REBUILD" = "--force" ] || ! docker image inspect 0xcrawller/whatweb:0.6.4 >/dev/null 2>&1; then
    echo "[1/5] Building WhatWeb 0.6.4..."
    docker build -t 0xcrawller/whatweb:0.6.4 tools/whatweb
else
    echo "[1/5] WhatWeb 0.6.4 image already present."
fi

# 2. Retire.js 5.4.3
if [ "$FORCE_REBUILD" = "--force" ] || ! docker image inspect 0xcrawller/retirejs:5.4.3 >/dev/null 2>&1; then
    echo "[2/5] Building Retire.js 5.4.3..."
    docker build -t 0xcrawller/retirejs:5.4.3 tools/retirejs
else
    echo "[2/5] Retire.js 5.4.3 image already present."
fi

# 3. Wappalyzer Next 2.0.0
if [ "$FORCE_REBUILD" = "--force" ] || ! docker image inspect 0xcrawller/wappalyzer-next:2.0.0 >/dev/null 2>&1; then
    echo "[3/5] Building Wappalyzer Next 2.0.0 with Chromium..."
    docker build --build-arg WAPPALYZER_NEXT_VERSION=2.0.0 -t 0xcrawller/wappalyzer-next:2.0.0 tools/wappalyzer-next
else
    echo "[3/5] Wappalyzer Next 2.0.0 image already present."
fi

# 4. ZGrab2
if [ "$FORCE_REBUILD" = "--force" ] || ! docker image inspect ghcr.io/zmap/zgrab2:latest >/dev/null 2>&1; then
    echo "[4/5] Pulling official ZGrab2 image..."
    docker pull ghcr.io/zmap/zgrab2:latest || true
else
    echo "[4/5] ZGrab2 image already present."
fi

# 5. Nuclei templates cache
echo "[5/5] Checking Nuclei templates cache..."
docker volume inspect crawller_nuclei_templates >/dev/null 2>&1 || docker volume create crawller_nuclei_templates >/dev/null

HAS_TEMPLATES="$(docker run --rm --entrypoint sh -v crawller_nuclei_templates:/root/nuclei-templates projectdiscovery/nuclei:latest -c 'if [ -d /root/nuclei-templates/http ]; then echo "YES"; else echo "NO"; fi' 2>/dev/null || echo "NO")"

if [ "$FORCE_REBUILD" = "--force" ] || [ "$HAS_TEMPLATES" != "YES" ]; then
    echo "[5/5] Initializing Nuclei templates in crawller_nuclei_templates volume..."
    docker run --rm --entrypoint sh -v crawller_nuclei_templates:/root/nuclei-templates projectdiscovery/nuclei:latest -c "
        set -e
        echo '    Downloading official Nuclei templates archive...'
        TEMPLATE_URL='https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.4.8.tar.gz'
        if command -v wget >/dev/null 2>&1; then
            wget -qO- \"\$TEMPLATE_URL\" | tar -xzf - -C /root/nuclei-templates --strip-components=1
        elif command -v curl >/dev/null 2>&1; then
            curl -sSL \"\$TEMPLATE_URL\" | tar -xzf - -C /root/nuclei-templates --strip-components=1
        else
            echo 'Neither wget nor curl found in nuclei container.' >&2
            exit 1
        fi
        mkdir -p /root/.config/nuclei
        cp /root/nuclei-templates/.nuclei-ignore /root/.config/nuclei/ 2>/dev/null || true
        echo '    Nuclei templates initialized successfully.'
    "
else
    echo "[5/5] Nuclei templates already initialized."
fi

# Verification check
echo "[+] Verifying tool executability..."
docker run --rm 0xcrawller/whatweb:0.6.4 --version >/dev/null 2>&1 || { echo "[ERROR] WhatWeb container verification failed." >&2; exit 1; }
docker run --rm 0xcrawller/retirejs:5.4.3 --version >/dev/null 2>&1 || { echo "[ERROR] RetireJS container verification failed." >&2; exit 1; }
docker run --rm 0xcrawller/wappalyzer-next:2.0.0 --help >/dev/null 2>&1 || { echo "[ERROR] Wappalyzer container verification failed." >&2; exit 1; }
docker run --rm -v crawller_nuclei_templates:/root/nuclei-templates projectdiscovery/nuclei:latest -duc -version >/dev/null 2>&1 || { echo "[ERROR] Nuclei container verification failed." >&2; exit 1; }

echo ""
echo "Technology intelligence scanner environment is ready."
