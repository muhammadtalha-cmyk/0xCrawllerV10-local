#!/bin/bash
# Local development startup script for macOS/Linux

# Automatically terminate child processes on exit/ctrl+c
trap "echo 'Stopping all services...'; kill 0" SIGINT SIGTERM EXIT

echo "============================================="
echo "Starting 0xCrawller Services..."
echo "============================================="

# Start Backend
echo "[START] Starting Backend API..."
cd "$(dirname "$0")/backend"
./start-backend.sh &
BACKEND_PID=$!

# Start Worker
echo "[START] Starting Persistent Scan Worker..."
./start-worker.sh &
WORKER_PID=$!

# Start Frontend
echo "[START] Starting Frontend Development Server..."
cd ../frontend
if [ ! -d "node_modules" ]; then
  echo "[SETUP] Installing frontend dependencies..."
  npm install
fi
if [ ! -f ".env.local" ] && [ -f ".env.example" ]; then
  cp .env.example .env.local
  echo "[SETUP] Created .env.local"
fi
npm run dev &
FRONTEND_PID=$!

echo ""
echo "Backend API Docs: http://localhost:8000/docs"
echo "Frontend App:     http://localhost:3000"
echo "Press Ctrl+C to stop all services."
echo "============================================="

wait
