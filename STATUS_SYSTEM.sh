#!/usr/bin/env bash
# ============================================================
# STATUS_SYSTEM.sh — Check status of all 0xCrawllerV10 services
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     0xCrawllerV10  ·  System Status      ║"
echo "╚══════════════════════════════════════════╝"
echo ""

echo "── Container Status ─────────────────────────────────────"
docker compose ps
echo ""

echo "── Backend Health ───────────────────────────────────────"
curl -sf http://localhost:8000/api/health 2>/dev/null | python3 -m json.tool 2>/dev/null \
    || echo "  Backend not reachable (may still be starting)"
echo ""

echo "── Recent Logs (last 30 lines per service) ──────────────"
docker compose logs --tail 30
echo ""
