import logging
import mimetypes
from pathlib import Path

import cloudinary
import cloudinary.uploader

from .config import settings
from .database import Database

logger = logging.getLogger("crawller.artifacts")

if settings.cloudinary_cloud_name and settings.cloudinary_api_key and settings.cloudinary_api_secret:
    cloudinary.config(
        cloud_name=settings.cloudinary_cloud_name,
        api_key=settings.cloudinary_api_key,
        api_secret=settings.cloudinary_api_secret,
        secure=True,
    )
    CLOUDINARY_ENABLED = True
else:
    CLOUDINARY_ENABLED = False

ALLOWED_SUFFIXES = {
    ".md", ".json", ".jsonl", ".csv", ".txt", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".mmd"
}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".svg"}
REPORT_NAMES = {
    "final_report.md",
    "asset_normalization_report.md",
    "technology_enrichment_report.md",
    "combined_vapt_intelligence_report.md",
}

def artifact_kind(path: Path) -> str:
    if path.name in REPORT_NAMES or path.suffix.lower() == ".md":
        return "report"
    if path.suffix.lower() in IMAGE_SUFFIXES:
        return "screenshot" if "screenshot" in path.as_posix().lower() else "image"
    if "tool_logs" in path.parts or path.suffix.lower() == ".txt":
        return "log"
    return "data"


def infer_step(path: Path) -> str | None:
    parts = {part.lower() for part in path.parts}
    if "normalization_v9" in parts:
        return "normalization"
    if "technology_enrichment_v9_2" in parts:
        return "technology"
    if path.name == "combined_vapt_intelligence_report.md":
        return "report"
    return "recon"


def index_run_artifacts(db: Database, project_root: Path, scan_id: str, run_dir: Path) -> int:
    project_root = project_root.resolve()
    run_dir = run_dir.resolve()
    if not run_dir.is_dir() or project_root not in run_dir.parents:
        return 0

    candidates: list[Path] = []
    root_names = {
        "final_report.md", "combined_vapt_intelligence_report.md", "summary.json",
        "port_scan_summary.json", "recursive_recon_summary.json", "edge_detection_summary.json",
        "waf_detection.json", "recon_topology.json", "endpoint_classification.json",
    }
    for name in root_names:
        candidate = run_dir / name
        if candidate.is_file():
            candidates.append(candidate)

    for folder_name in ("normalization_v9", "technology_enrichment_v9_2"):
        folder = run_dir / folder_name
        if folder.is_dir():
            candidates.extend(
                path for path in folder.rglob("*")
                if path.is_file() and path.suffix.lower() in ALLOWED_SUFFIXES
            )

    screenshot_folder = run_dir / "httpx_screenshots" / "screenshot"
    if screenshot_folder.is_dir():
        candidates.extend(
            path for path in screenshot_folder.rglob("*")
            if path.is_file() and path.suffix.lower() in IMAGE_SUFFIXES
        )

    seen: set[Path] = set()
    indexed = 0
    for path in candidates:
        resolved = path.resolve()
        if resolved in seen or project_root not in resolved.parents:
            continue
        seen.add(resolved)
        relative = resolved.relative_to(project_root).as_posix()
        mime_type = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
        kind = artifact_kind(resolved.relative_to(run_dir))
        
        cloudinary_url = None
        cloudinary_public_id = None
        
        if CLOUDINARY_ENABLED and (kind in {"report", "screenshot"} or resolved.suffix.lower() in {".json", ".csv"}):
            try:
                res = cloudinary.uploader.upload(
                    str(resolved), 
                    resource_type="auto"
                )
                cloudinary_url = res.get("secure_url")
                cloudinary_public_id = res.get("public_id")
            except Exception as e:
                logger.error(f"Cloudinary upload failed for {resolved.name}: {e}")

        db.upsert_artifact(
            scan_id=scan_id,
            step_key=infer_step(resolved.relative_to(run_dir)),
            kind=kind,
            name=resolved.name,
            relative_path=relative,
            mime_type=mime_type,
            size_bytes=resolved.stat().st_size,
            cloudinary_url=cloudinary_url,
            cloudinary_public_id=cloudinary_public_id,
        )
        indexed += 1
        if indexed >= 5000:
            break
    return indexed
