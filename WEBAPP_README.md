# 0xCrawller Web Orchestrator

This upgrade adds a web application around the existing scanner. It does **not** rewrite the reconnaissance, normalization, technology-enrichment, or combined-report engines.

## Preserved execution chain

1. `run-max-v8.5.1-recursive.cmd <target>`
2. `run-v9-normalize.cmd <target>`
3. `run-v9.2-tech-max.cmd <target>`
4. `run-v10-combined-report.cmd <target>`

The backend invokes these launchers sequentially, streams their output over WebSockets, stores orchestration state in SQLite, and indexes generated reports/screenshots from the existing `recon_runs` directory.

## Added components

- `webapp/backend`: FastAPI API, WebSocket broker, subprocess orchestrator, SQLite state, artifact serving.
- `webapp/frontend`: Next.js web dashboard designed for Vercel deployment.
- `webapp/start-webapp.cmd`: starts both services for local use.


## Prerequisites

- Windows host with the existing 0xCrawller toolchain working from CMD.
- Python 3.11 or newer.
- Node.js 20.9 or newer.
- npm and ngrok for the Vercel/local-backend demo flow.

## First local run on Windows

### 1. Backend configuration

```bat
cd webapp\backend
copy .env.example .env
notepad .env
```

The supplied relative paths work automatically when the folder structure is preserved. Change them only if the scanner is stored elsewhere. Keep:

```env
CRAWLLER_MOCK_SCANNER=false
CRAWLLER_MAX_CONCURRENT_SCANS=1
```

One concurrent scan is the safe default because the original tools write into a shared `recon_runs` tree.

### 2. Frontend configuration

```bat
cd webapp\frontend
copy .env.example .env.local
```

For local use:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### 3. Start everything

From `webapp`:

```bat
start-webapp.cmd
```

Open:

- Web interface: `http://localhost:3000`
- API documentation: `http://localhost:8000/docs`

The first start creates the Python virtual environment and installs Node/Python dependencies.

## Vercel frontend + local scanner through ngrok

The scanner must run on the Windows machine where Subfinder, Amass, BBOT, DNSX, HTTPX, Katana, Gobuster, Naabu/Nmap, Docker tools, and the current `.cmd` launchers are installed.

1. Start the FastAPI backend locally on port `8000` using `webapp\backend\start-backend-prod.cmd`.
2. Start ngrok:

```bat
ngrok http 8000
```

3. Copy the HTTPS ngrok URL, for example `https://example.ngrok.app`.
4. In `webapp/backend/.env`, permit the deployed frontend:

```env
CRAWLLER_FRONTEND_ORIGINS=http://localhost:3000,https://YOUR-PROJECT.vercel.app
```

5. In Vercel, set:

```env
NEXT_PUBLIC_API_URL=https://example.ngrok.app
```

6. Redeploy the frontend.

The same ngrok endpoint carries REST requests and WebSocket progress events.

## Production notes

- Use ngrok for demos/development. For permanent operation, run the backend on a persistent Windows host or VM with HTTPS.
- Keep SQLite for the current single-host deployment. Move to PostgreSQL before multiple backend instances or multiple concurrent operators.
- Configure `CRAWLLER_API_KEY` and `NEXT_PUBLIC_API_KEY` for a basic private demo. For production, replace it with authenticated users and short-lived artifact URLs.
- Do not expose the backend publicly without access control.
- Scan only targets for which explicit authorization exists.

## Web features

- Domain input and authorization confirmation.
- Four-step circular progress visualization.
- Live WebSocket output with polling fallback.
- Current tool detection from scanner stdout.
- Scan cancellation.
- Persistent SQLite scan history.
- Individual Recon, Normalization, Technology, and Combined reports.
- HTTPX screenshot gallery and full-size preview.
- JSON/CSV evidence browser and downloads.
- Responsive desktop/mobile interface.

## Failure behavior

- A failed module stops later modules.
- Recon exit code `3` is accepted as partial coverage, matching the existing launcher behavior.
- Existing files in `recon_runs` are never deleted or overwritten by the web layer.
- If the backend restarts during a scan, the web job is marked interrupted; any scanner output already written remains available on disk.

## Validation completed

```text
100 Python tests passed
- 96 original scanner tests
- 4 new backend tests

Mock API lifecycle passed
- create scan
- run four modules
- stream/store logs
- complete at 100%

Frontend TypeScript/JSX syntax validation passed
```

A full real scan was not executed in the build environment because the original pipeline requires your Windows-installed external tools and credentials.
