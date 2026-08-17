#!/bin/bash
set -e

echo "Starting 0xCrawllerV10 Production Deployment..."

# 1. Ensure Python 3.10+ is installed
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install Python 3.10+"
    exit 1
fi

# 2. Setup Virtual Environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

echo "Installing dependencies..."
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt

# 3. Create .env template if missing
if [ ! -f ".env" ]; then
    echo "Creating empty .env file. YOU MUST EDIT THIS FILE."
    cat <<EOT >> .env
DATABASE_URL=postgresql://user:password@localhost:5432/db
API_KEY=your_secure_worker_api_key
JWT_SECRET=$(openssl rand -hex 32)
FRONTEND_ORIGINS=https://your-vercel-domain.com
CLOUDINARY_CLOUD_NAME=
CLOUDINARY_API_KEY=
CLOUDINARY_API_SECRET=
EOT
    echo "Please configure .env before starting the services."
fi

# 4. Run Migrations
echo "Running database migrations..."
./.venv/bin/python migrate.py

# 5. Create Systemd Services
echo "Configuring systemd services..."
cat <<EOT > /tmp/aurora-api.service
[Unit]
Description=Aurora FastAPI Backend
After=network.target

[Service]
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
EnvironmentFile=$(pwd)/.env

[Install]
WantedBy=multi-user.target
EOT

cat <<EOT > /tmp/aurora-worker.service
[Unit]
Description=Aurora Scan Worker
After=network.target

[Service]
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/.venv/bin/python worker.py
Restart=always
EnvironmentFile=$(pwd)/.env

[Install]
WantedBy=multi-user.target
EOT

echo "To install systemd services, run:"
echo "sudo cp /tmp/aurora-api.service /etc/systemd/system/"
echo "sudo cp /tmp/aurora-worker.service /etc/systemd/system/"
echo "sudo systemctl daemon-reload"
echo "sudo systemctl enable aurora-api aurora-worker"
echo "sudo systemctl start aurora-api aurora-worker"

echo "Deployment script completed."
