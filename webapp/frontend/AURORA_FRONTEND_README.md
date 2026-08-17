# 0xCrawller Aurora Frontend

This folder is a drop-in replacement for the existing `webapp/frontend` directory.

## Preserved functionality

- Existing REST API contract and scan routes
- WebSocket live logs with polling fallback
- Pipeline progress and scan cancellation
- Artifact, report, evidence, and screenshot loading
- Existing FastAPI backend and scanner workflow

## Added frontend experience

- Security intelligence executive overview
- Evidence-based security posture and coverage status
- Real-data metric cards and severity distribution
- Attack-surface relationship visualization
- Asset and provider intelligence
- Technology cards and dynamic stack architecture
- Vulnerability intelligence and findings exploration
- Screenshot intelligence gallery
- Technical evidence report hidden behind an explicit tab

No values are fabricated. Missing evidence is displayed as unavailable or `N/A`.

## Replace and run

1. Back up your current `webapp/frontend` folder.
2. Replace it with this `frontend` folder.
3. Preserve or update `.env.local` if your backend URL is different.
4. From `webapp/frontend`, run:

```bash
npm install
npm run build
npm run dev
```

Default frontend: `http://localhost:3000`
Default backend expected by `.env.local`: `http://localhost:8000`

No additional npm packages are required beyond `package.json`.
