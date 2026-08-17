#!/bin/bash
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage:"
    echo "  ./update-backend.sh https://NEW-TUNNEL.trycloudflare.com"
    exit 1
fi

NEW_URL="${1%/}"

case "$NEW_URL" in
    https://*.trycloudflare.com)
        ;;
    *)
        echo "ERROR: URL must be an HTTPS trycloudflare.com URL."
        exit 1
        ;;
esac

python3 - "$NEW_URL" <<'PY'
import json
import sys
from pathlib import Path

new_url = sys.argv[1]
path = Path("wrangler.jsonc")

data = json.loads(path.read_text())
old_url = data.get("vars", {}).get("BACKEND_ORIGIN")

if not old_url:
    raise SystemExit("ERROR: BACKEND_ORIGIN not found in wrangler.jsonc")

data["vars"]["BACKEND_ORIGIN"] = new_url

path.write_text(json.dumps(data, indent=2) + "\n")

print(f"OLD: {old_url}")
print(f"NEW: {new_url}")
PY

echo
echo "Deploying Cloudflare Worker..."
npx wrangler deploy

echo
echo "Testing Worker health..."
curl --fail --silent --show-error \
  https://0xcrawller-api-proxy.scribesync.workers.dev/api/health

echo
echo
echo "SUCCESS: Worker backend origin updated."
