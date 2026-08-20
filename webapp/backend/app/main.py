from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
import httpx
from pydantic import BaseModel, Field

from .config import settings
from .database import Database
from .events import EventBroker
from .orchestrator import Orchestrator
from .auth import require_user, require_admin, auth_router, SECRET_KEY, ALGORITHM
import jwt


db = Database(settings.database_path, settings.database_url)
broker = EventBroker()
orchestrator = Orchestrator(settings, db, broker)


class ScanCreate(BaseModel):
    target: str = Field(min_length=3, max_length=253)
    authorized: bool


async def require_api_key(
    x_api_key: str | None = Header(default=None),
    api_key: str | None = Query(default=None),
) -> None:
    supplied = x_api_key or api_key
    if settings.api_key and supplied != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Decoupled worker architecture: Backend startup does not mark scans as failed.
    yield


app = FastAPI(
    title="0xCrawller Orchestration API",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.frontend_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization", "Cookie"],
)


@app.get("/api/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "project_root": str(settings.project_root),
        "scanner_mode": "mock" if settings.mock_scanner else "cross-platform",
        "database": "postgresql" if settings.database_url else "sqlite",
    }


@app.post(
    "/api/scans",
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_scan(
    payload: ScanCreate,
    current_user: dict = Depends(require_user)
) -> dict[str, object]:
    if not payload.authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must confirm that you are authorized to scan this target.",
        )

    try:
        target = orchestrator.normalize_target(payload.target)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    scan_id = db.create_scan(target, user_id=current_user["id"])
    # The scan is now enqueued in the database; the worker will claim and execute it.

    scan = db.get_scan(scan_id)
    assert scan is not None
    return scan


@app.post(
    "/api/internal/scans/{scan_id}/events",
    dependencies=[Depends(require_api_key)],
)
async def post_scan_event(scan_id: str, event: dict[str, object]) -> dict[str, object]:
    await broker.publish(scan_id, event)
    return {"status": "ok"}


@app.get(
    "/api/scans",
)
async def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict = Depends(require_user),
) -> list[dict[str, object]]:
    user_id = current_user["id"] if current_user["role"] != "ADMIN" else None
    return db.list_scans(limit, user_id=user_id)


@app.get(
    "/api/scans/{scan_id}",
)
async def get_scan(scan_id: str, current_user: dict = Depends(require_user)) -> dict[str, object]:
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("user_id") != current_user["id"] and current_user["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Not authorized to view this scan")
    return scan


@app.post(
    "/api/scans/{scan_id}/cancel",
)
async def cancel_scan(scan_id: str, current_user: dict = Depends(require_user)) -> dict[str, object]:
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("user_id") != current_user["id"] and current_user["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Not authorized to cancel this scan")

    if scan["status"] not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="Scan is not running")

    db.update_scan(scan_id, cancel_requested=True)
    # Publish immediate snapshot indicating cancellation has been requested.
    updated = db.get_scan(scan_id)
    if updated:
        await broker.publish(scan_id, {"type": "scan.cancel_requested", "scan": updated})
    return {"accepted": True}


@app.get(
    "/api/scans/{scan_id}/logs",
)
async def get_logs(
    scan_id: str,
    after_id: int = Query(default=0, ge=0),
    limit: int = Query(default=1000, ge=1, le=5000),
    current_user: dict = Depends(require_user),
) -> list[dict[str, object]]:
    scan = db.get_scan_owner(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("user_id") != current_user["id"] and current_user["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Not authorized to view logs")

    return db.get_logs(scan_id, after_id, limit)


@app.get(
    "/api/scans/{scan_id}/artifacts",
)
async def get_artifacts(
    scan_id: str,
    kind: str | None = None,
    current_user: dict = Depends(require_user),
) -> list[dict[str, object]]:
    scan = db.get_scan_owner(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("user_id") != current_user["id"] and current_user["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Not authorized to view artifacts")

    return db.get_artifacts(scan_id, kind)


def _resolve_artifact(artifact_id: str) -> tuple[dict[str, object], Path | None]:
    artifact = db.get_artifact(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")

    path = (
        settings.project_root / str(artifact["relative_path"])
    ).resolve()

    if settings.project_root not in path.parents or not path.is_file():
        return artifact, None

    return artifact, path


@app.get(
    "/api/artifacts/{artifact_id}",
)
async def download_artifact(
    artifact_id: str,
    download: bool = False,
    current_user: dict = Depends(require_user),
):
    artifact, path = _resolve_artifact(artifact_id)
    scan = db.get_scan_owner(artifact["scan_id"])
    if not scan or (scan.get("user_id") != current_user["id"] and current_user["role"] != "ADMIN"):
        raise HTTPException(status_code=403, detail="Not authorized")

    if not path:
        raise HTTPException(status_code=404, detail="Artifact file is unavailable locally")

    return FileResponse(
        path,
        media_type=str(
            artifact.get("mime_type")
            or "application/octet-stream"
        ),
        filename=path.name if download else None,
        content_disposition_type="attachment" if download else "inline",
    )


@app.get(
    "/api/artifacts/{artifact_id}/text",
)
async def read_artifact_text(
    artifact_id: str,
    current_user: dict = Depends(require_user),
) -> PlainTextResponse:
    artifact, path = _resolve_artifact(artifact_id)
    scan = db.get_scan_owner(artifact["scan_id"])
    if not scan or (scan.get("user_id") != current_user["id"] and current_user["role"] != "ADMIN"):
        raise HTTPException(status_code=403, detail="Not authorized")

    if not path:
        raise HTTPException(status_code=404, detail="Artifact file is unavailable locally")

    if path.suffix.lower() not in {
        ".md", ".txt", ".json", ".jsonl", ".csv", ".mmd"
    }:
        raise HTTPException(
            status_code=415,
            detail="Artifact is not a text document",
        )

    if path.stat().st_size > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Artifact is too large for inline preview",
        )

    return PlainTextResponse(
        path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    )


@app.websocket("/ws/scans/{scan_id}")
async def scan_socket(
    websocket: WebSocket,
    scan_id: str,
    token: str | None = Query(default=None),
) -> None:
    origin = websocket.headers.get("origin", "").rstrip("/")

    if (
        settings.frontend_origins
        and origin
        and origin not in settings.frontend_origins
    ):
        await websocket.close(
            code=1008,
            reason="Origin not allowed",
        )
        return

    user_id = None
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub")
        except:
            pass
    
    if not user_id:
        cookie_token = websocket.cookies.get("access_token")
        if cookie_token and cookie_token.startswith("Bearer "):
            try:
                payload = jwt.decode(cookie_token[7:], SECRET_KEY, algorithms=[ALGORITHM])
                user_id = payload.get("sub")
            except:
                pass

    if not user_id:
        await websocket.close(
            code=1008,
            reason="Not authenticated",
        )
        return

    scan = db.get_scan(scan_id)
    if not scan:
        await websocket.close(
            code=1008,
            reason="Scan not found",
        )
        return

    await websocket.accept()

    queue = await broker.subscribe(scan_id)

    try:
        await websocket.send_json(
            {"type": "snapshot", "scan": scan}
        )

        logs = db.get_logs(scan_id, 0, 500)
        if logs:
            await websocket.send_json(
                {"type": "logs", "logs": logs}
            )

        while True:
            try:
                event = await asyncio.wait_for(
                    queue.get(),
                    timeout=20,
                )
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})

    except WebSocketDisconnect:
        pass
    finally:
        await broker.unsubscribe(scan_id, queue)
