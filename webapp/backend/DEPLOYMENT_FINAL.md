# 0xCrawllerV10 Final Production Deployment Guide

## 1. Prerequisites
- A Linux server (Ubuntu/Debian recommended)
- A Supabase PostgreSQL Database URL
- A Cloudinary Account (Cloud Name, API Key, API Secret)
- Cloudflare Account & Domain

## 2. Backend & Worker Setup (Linux Server)

### Step A: Clone and Configure
Copy the `webapp/backend` directory to your Linux server (e.g. `/opt/0xcrawllerv10/backend`).

```bash
cd /opt/0xcrawllerv10/backend
chmod +x deploy_backend.sh
./deploy_backend.sh
```

The script will fail on purpose if you haven't filled out `.env`. Open it:
```bash
nano .env
```
Ensure these are set:
- `DATABASE_URL=postgresql://user:pass@aws-0-eu-central-1.pooler.supabase.com:6543/postgres`
- `API_KEY=your_secure_worker_api_key`
- `JWT_SECRET=some_random_secret_string`
- `FRONTEND_ORIGINS=https://your-vercel-domain.com`
- `CLOUDINARY_CLOUD_NAME=...`
- `CLOUDINARY_API_KEY=...`
- `CLOUDINARY_API_SECRET=...`

Run the script again to initialize services and migrate the database:
```bash
./deploy_backend.sh
```

### Step B: Enable Systemd Services
The script generates two systemd service files in `/tmp`. Install them:
```bash
sudo cp /tmp/aurora-api.service /etc/systemd/system/
sudo cp /tmp/aurora-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aurora-api aurora-worker
sudo systemctl start aurora-api aurora-worker
```
Verify they are running:
```bash
sudo systemctl status aurora-api
sudo systemctl status aurora-worker
```

### Step C: Bootstrap Admin User
Generate your first admin user so you can log into the frontend:
```bash
./.venv/bin/python create_admin.py "admin" "MySuperSecretPassword123"
```

## 3. Exposing the API via Cloudflare Tunnel

Do **NOT** expose port 8000 directly. Instead, use a Cloudflare Tunnel to expose HTTP and WSS securely.

1. Install `cloudflared` on your Linux server.
2. Login to Cloudflare: `cloudflared tunnel login`
3. Create a tunnel: `cloudflared tunnel create aurora-api`
4. Copy the generated `cloudflared_config.yml` template to `~/.cloudflared/config.yml`.
5. Update `config.yml` with your tunnel UUID and target hostname (e.g., `api.yourdomain.com`).
6. Route DNS: `cloudflared tunnel route dns aurora-api api.yourdomain.com`
7. Start the tunnel as a service: `sudo cloudflared service install`

## 4. Frontend Deployment (Vercel)

1. Connect your GitHub repository (or upload code) to Vercel.
2. Set the Root Directory to `webapp/frontend`.
3. In Vercel's Environment Variables settings, add:
   - Name: `NEXT_PUBLIC_API_URL`
   - Value: `https://api.yourdomain.com` (Match the hostname from Cloudflare)
4. Deploy. Vercel automatically routes Next.js pages and the Cloudflare Tunnel seamlessly forwards the WebSocket and HTTP requests to the isolated Linux Server.

## Hardening Notes
- The database is only accessible by the backend.
- The Scan Worker connects locally to the API using the `API_KEY`. It does not require public ingress.
- Cloudflare Tunnel encrypts traffic edge-to-server. No ports are open to the internet on the Linux machine.
- Localhost fallbacks in the frontend have been audited and resolve gracefully to the `NEXT_PUBLIC_API_URL`.
