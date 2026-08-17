#!/bin/bash
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "[SETUP] Creating backend virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate

if ! python3 -c "import fastapi, uvicorn" >/dev/null 2>&1; then
  echo "[SETUP] Installing backend dependencies..."
  python3 -m pip install --upgrade pip
  python3 -m pip install -r requirements.txt
fi

if [ -f ".env" ]; then
  # Load env variables from .env if present
  export $(grep -v '^#' .env | xargs)
fi

python3 -m app.worker
