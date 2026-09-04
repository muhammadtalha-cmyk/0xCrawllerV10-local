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
    echo "[1/4] Building WhatWeb 0.6.4..."
    docker build -t 0xcrawller/whatweb:0.6.4 tools/whatweb
else
    echo "[1/4] WhatWeb 0.6.4 image already present."
fi

# 2. Retire.js 5.4.3
if [ "$FORCE_REBUILD" = "--force" ] || ! docker image inspect 0xcrawller/retirejs:5.4.3 >/dev/null 2>&1; then
    echo "[2/4] Building Retire.js 5.4.3..."
    docker build -t 0xcrawller/retirejs:5.4.3 tools/retirejs
else
    echo "[2/4] Retire.js 5.4.3 image already present."
fi

# 3. Wappalyzer Next 2.0.0
if [ "$FORCE_REBUILD" = "--force" ] || ! docker image inspect 0xcrawller/wappalyzer-next:2.0.0 >/dev/null 2>&1; then
    echo "[3/4] Building Wappalyzer Next 2.0.0 with Chromium..."
    docker build --build-arg WAPPALYZER_NEXT_VERSION=v2.0.0 -t 0xcrawller/wappalyzer-next:2.0.0 tools/wappalyzer-next
else
    echo "[3/4] Wappalyzer Next 2.0.0 image already present."
fi

# 4. ZGrab2
if [ "$FORCE_REBUILD" = "--force" ] || ! docker image inspect ghcr.io/zmap/zgrab2:latest >/dev/null 2>&1; then
    echo "[4/4] Pulling official ZGrab2 image..."
    docker pull ghcr.io/zmap/zgrab2:latest || true
else
    echo "[4/4] ZGrab2 image already present."
fi

# 5. Nuclei templates cache
echo "[+] Checking Nuclei templates cache..."
if ! docker run --rm -v crawller_nuclei_templates:/root/nuclei-templates projectdiscovery/nuclei:latest -tv 2>/dev/null | grep -i "v1" >/dev/null 2>&1; then
    echo "[+] Initializing Nuclei templates in crawller_nuclei_templates volume..."
    docker run --rm -v crawller_nuclei_templates:/root/nuclei-templates projectdiscovery/nuclei:latest -ut || true
else
    echo "[+] Nuclei templates already initialized."
fi

echo ""
echo "Technology intelligence scanner environment is ready."
