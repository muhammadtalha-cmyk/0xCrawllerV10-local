# 0xCrawllerV10 — Docker Deployment Guide

## Quick Start (Any Platform)

```bash
# 1. Clone the repository
git clone <repo-url>
cd 0xCrawllerV10-local

# 2. Create your environment file
cp .env.example .env
# Edit .env and set CRAWLLER_JWT_SECRET (mandatory):
#   openssl rand -hex 32   → paste result into .env

# 3. Start everything
docker compose up -d

# 4. Open the app
# Frontend:   http://localhost:3000
# API Health: http://localhost:8000/api/health
# API Docs:   http://localhost:8000/docs
```

Or use the helper script (does all of the above automatically):
```bash
./START_SYSTEM.sh
```

---

## Requirements

| Requirement           | Version       |
|-----------------------|---------------|
| Docker Desktop / CE   | 24+           |
| Docker Compose        | v2 (built-in) |
| Available RAM         | ≥ 4 GB        |
| Available Disk        | ≥ 20 GB       |

---

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                      Host Machine                     │
│                                                       │
│  ┌──────────────┐   ┌──────────────────────────────┐ │
│  │   postgres   │   │         Docker Daemon         │ │
│  │  port 5432   │   │  (spawns scan tool containers)│ │
│  └──────┬───────┘   └──────────────┬───────────────┘ │
│         │  DATABASE_URL             │ /var/run/docker.sock
│  ┌──────▼───────┐   ┌──────────────▼────────────────┐ │
│  │   backend    │   │           worker              │ │
│  │  FastAPI     │◄──│  python -m app.worker         │ │
│  │  port 8000   │   │  (polls DB, claims scans,     │ │
│  └──────▲───────┘   │   runs run_pipeline.py which  │ │
│         │           │   calls: docker run subfinder, │ │
│  ┌──────┴───────┐   │   amass, httpx, katana…)      │ │
│  │   frontend   │   └───────────────────────────────┘ │
│  │  Next.js     │                                     │
│  │  port 3000   │                                     │
│  └──────────────┘                                     │
└───────────────────────────────────────────────────────┘
```

### Service dependencies (startup order)
```
postgres (healthy)
    └── backend (started)
            └── worker
    └── frontend
```

---

## Platform-Specific Notes

### macOS
```bash
# Ensure Docker Desktop is running, then:
cp .env.example .env
# Set CRAWLLER_JWT_SECRET
docker compose up -d
```

### Windows (Docker Desktop with WSL2)
```powershell
# Run in PowerShell or Git Bash
copy .env.example .env
# Edit .env with Notepad or VS Code
docker compose up -d
```
> Note: On Windows, `${PWD}` in compose resolves correctly with Docker Desktop WSL2 backend.
> If you see path issues, set `COMPOSE_CONVERT_WINDOWS_PATHS=1` in your environment.

### Ubuntu / Fresh Linux VM
```bash
# Install Docker Engine
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Clone and start
git clone <repo-url>
cd 0xCrawllerV10-local
cp .env.example .env
# Set CRAWLLER_JWT_SECRET with: openssl rand -hex 32
docker compose up -d
```

---

## Service Ports

| Service    | Port  | Description                    |
|------------|-------|--------------------------------|
| postgres   | 5432  | PostgreSQL database            |
| backend    | 8000  | FastAPI REST API + WebSockets  |
| frontend   | 3000  | Next.js web interface          |

---

## Environment Variables

See [.env.example](.env.example) for all variables.

| Variable                    | Required | Default                              | Description                          |
|-----------------------------|----------|--------------------------------------|--------------------------------------|
| `POSTGRES_USER`             | No       | `recon`                              | PostgreSQL username                  |
| `POSTGRES_PASSWORD`         | No       | `reconpass`                          | PostgreSQL password                  |
| `POSTGRES_DB`               | No       | `recondb`                            | PostgreSQL database name             |
| `CRAWLLER_JWT_SECRET`       | **Yes**  | —                                    | JWT signing secret (use `openssl rand -hex 32`) |
| `CRAWLLER_FRONTEND_ORIGINS` | No       | `http://localhost:3000`              | Comma-separated CORS origins         |
| `CRAWLLER_API_KEY`          | No       | *(none)*                             | Optional API key for worker→backend  |
| `NEXT_PUBLIC_API_URL`       | No       | `http://localhost:8000`              | Backend URL (browser-side)           |
| `NEXT_PUBLIC_API_KEY`       | No       | *(none)*                             | Optional frontend API key            |
| `SHODAN_API_KEY`            | No       | *(none)*                             | Shodan passive enrichment key        |

---

## Data Persistence

| What                      | Where (Docker Volume)        |
|---------------------------|------------------------------|
| PostgreSQL data           | `crawller_pgdata`            |
| Nuclei security templates | `crawller_nuclei_templates`  |
| Scan results / recon runs | `${PWD}/recon_runs`          |
| Screenshots / artifacts   | `${PWD}/recon_runs/...`      |

All scan output is written to `./recon_runs/<target>-<timestamp>/` on the **host** filesystem (via the bind mount), so it survives container recreation.

---

## How Scanning Works in Docker

The **worker** container:
1. Polls PostgreSQL for queued scans
2. Calls `run_pipeline.py` via `python3 -m app.worker`
3. `run_pipeline.py` invokes `docker run projectdiscovery/subfinder ...` etc.
4. These tool containers are spawned by the **host Docker daemon** (via `/var/run/docker.sock`)
5. Volume paths are resolved on the **host filesystem** — this is why `${PWD}:${PWD}` bind-mount is used at the same absolute path

This preserves the entire existing pipeline without modification.

---

## Helper Scripts

```bash
./START_SYSTEM.sh    # Build and start all services
./STOP_SYSTEM.sh     # Stop all services (data preserved)
./STATUS_SYSTEM.sh   # Show container status + recent logs
```

---

## Auto-Recovery After Reboot

All services are configured with `restart: unless-stopped`.

On systems where Docker is configured to start on boot (default on Linux, configurable on macOS/Windows):
```
Machine reboots
    → Docker daemon starts
    → postgres starts and becomes healthy
    → backend starts
    → worker starts (runs recovery to mark interrupted scans as failed)
    → frontend starts
    → System fully operational
```

To enable Docker auto-start on Ubuntu:
```bash
sudo systemctl enable docker
```

---

## Reset / Uninstall

```bash
# Stop and remove containers (keeps volumes)
docker compose down

# Stop, remove containers AND delete all data volumes
docker compose down -v

# Remove built images as well
docker compose down -v --rmi all
```

---

## Troubleshooting

**Backend fails to start:**
```bash
docker compose logs backend
# Common: CRAWLLER_JWT_SECRET not set
```

**Worker can't connect to Docker:**
```bash
docker compose logs worker
# Common: /var/run/docker.sock not accessible
# Fix: ensure the host user running docker compose has Docker permissions
```

**Frontend build fails:**
```bash
docker compose logs frontend
# Common: Node version or missing devDependencies
```

**Database connection error:**
```bash
docker compose logs postgres
docker compose logs backend
# Check POSTGRES_USER / POSTGRES_PASSWORD match in both services
```

**Port already in use:**
```bash
# Check what's using the port
lsof -i :3000
lsof -i :8000
# Stop the conflicting service or change ports in docker-compose.yml
```
