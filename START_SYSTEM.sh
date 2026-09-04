#!/usr/bin/env bash
# ============================================================
# START_SYSTEM.sh — Start the full 0xCrawllerV10 Docker stack
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     0xCrawllerV10  ·  Start System       ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 1. Environment file ───────────────────────────────────────
if [ ! -f ".env" ]; then
    echo "[SETUP] .env not found — creating from .env.example..."
    cp .env.example .env
fi

# Auto-generate a strong JWT secret if it's still the placeholder or empty
CURRENT_SECRET="$(grep -E '^CRAWLLER_JWT_SECRET=' .env | cut -d'=' -f2- || true)"
if [ -z "$CURRENT_SECRET" ] || [ "$CURRENT_SECRET" = "changeme_generate_with_openssl_rand_hex_32" ]; then
    if command -v openssl &>/dev/null; then
        NEW_SECRET="$(openssl rand -hex 32)"
    elif command -v python3 &>/dev/null; then
        NEW_SECRET="$(python3 -c "import secrets; print(secrets.token_hex(32))")"
    else
        NEW_SECRET="$(date +%s%N | sha256sum | head -c 64)"
    fi
    # Use perl/sed to replace safely across Mac and Linux
    python3 -c "
with open('.env', 'r') as f:
    c = f.read()
import re
c = re.sub(r'CRAWLLER_JWT_SECRET=.*', f'CRAWLLER_JWT_SECRET=$NEW_SECRET', c)
with open('.env', 'w') as f:
    f.write(c)
"
    echo "[SETUP] Generated new secure CRAWLLER_JWT_SECRET in .env"
fi

# ── 2. Docker availability ────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "[ERROR] Docker is not installed or not in PATH."
    echo "        Install Docker Desktop: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "[ERROR] Docker daemon is not running."
    echo "        Start Docker Desktop or the docker service, then retry."
    exit 1
fi

echo "[OK] Docker daemon is running."

# ── 3. Build & start core services ───────────────────────────
echo ""
echo "[+] Building container images and starting services..."
echo ""
docker compose up -d --build

# ── 3b. Verify scanner tool images ───────────────────────────
echo ""
echo "[+] Verifying scanner tool images..."
if [ -f "./build-v9.2-tech-images.sh" ]; then
    ./build-v9.2-tech-images.sh || true
fi

# ── 4. Health verification ───────────────────────────────────
echo ""
echo "[+] Waiting for services to initialize..."

MAX_WAIT=60
WAITED=0
BACKEND_HEALTHY=false

while [ "$WAITED" -lt "$MAX_WAIT" ]; do
    if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
        BACKEND_HEALTHY=true
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
    printf "."
done
echo ""

# ── 5. Status banner ──────────────────────────────────────────
docker compose ps
echo ""

if [ "$BACKEND_HEALTHY" = true ]; then
    echo "╔══════════════════════════════════════════════════╗"
    echo "║  0xCrawllerV10 stack is READY!                   ║"
    echo "║                                                  ║"
    echo "║  Frontend:      http://localhost:3000            ║"
    echo "║  Backend API:   http://localhost:8000/api/health ║"
    echo "║  API Docs:      http://localhost:8000/docs       ║"
    echo "╚══════════════════════════════════════════════════╝"
else
    echo "[WARN] Backend health endpoint not yet responding after ${MAX_WAIT}s."
    echo "       Services may still be starting up. Run ./STATUS_SYSTEM.sh to inspect."
fi

echo ""
echo "  Commands:"
echo "    ./STATUS_SYSTEM.sh   → Check logs and service health"
echo "    ./STOP_SYSTEM.sh     → Stop all services"
echo ""
