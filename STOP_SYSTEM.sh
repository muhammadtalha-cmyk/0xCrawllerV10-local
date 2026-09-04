#!/usr/bin/env bash
# ============================================================
# STOP_SYSTEM.sh — Stop the 0xCrawllerV10 Docker stack
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     0xCrawllerV10  ·  Stop System        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

docker compose down

echo ""
echo "[+] All services stopped."
echo "    Data volumes are preserved."
echo "    Run ./START_SYSTEM.sh to restart."
echo ""
