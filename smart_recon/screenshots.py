"""Screenshot preparation, prioritization, deduplication, and output verification."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .io_utils import count_jsonl_records, read_lines
from .models import ToolResult
from .validation import is_valid_hostname, normalize_hostname

_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp"}


def find_screenshot_files(run_dir: Path) -> list[str]:
    files: list[str] = []
    for path in run_dir.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _IMAGE_SUFFIXES:
            continue
        parts = {part.lower() for part in path.parts}
        if "screenshot" not in parts and "screenshots" not in parts and "httpx_screenshots" not in parts:
            continue
        files.append(str(path.relative_to(run_dir)))
    return sorted(set(files))


def screenshot_host_from_path(relative_path: str) -> str | None:
    parts = Path(relative_path).parts
    for marker in ("screenshot", "screenshots"):
        if marker in parts:
            index = parts.index(marker)
            if index + 1 < len(parts):
                host = normalize_hostname(parts[index + 1])
                if host and is_valid_hostname(host):
                    return host
    return None


def screenshot_hosts_from_files(files: Iterable[str]) -> set[str]:
    return {host for value in files if (host := screenshot_host_from_path(value))}


def screenshot_artifact_summary(run_dir: Path, files: Iterable[str]) -> dict[str, Any]:
    """Summarize artifacts by path, host, and content hash.

    Recursive stages may capture the same host again. Path-level counts remain useful
    for evidence retention, but coverage must be based on unique hosts/content rather
    than total files.
    """
    paths = sorted(set(str(value) for value in files))
    hashes: dict[str, list[str]] = {}
    hosts: set[str] = set()
    unreadable: list[str] = []
    for relative in paths:
        host = screenshot_host_from_path(relative)
        if host:
            hosts.add(host)
        absolute = run_dir / relative
        try:
            digest = hashlib.sha256(absolute.read_bytes()).hexdigest()
        except OSError:
            unreadable.append(relative)
            continue
        hashes.setdefault(digest, []).append(relative)

    representatives = sorted(values[0] for values in hashes.values())
    duplicate_groups = [sorted(values) for values in hashes.values() if len(values) > 1]
    return {
        "total_artifact_files": len(paths),
        "unique_content_images": len(hashes),
        "duplicate_content_artifacts": sum(max(0, len(values) - 1) for values in hashes.values()),
        "duplicate_content_groups": duplicate_groups,
        "unique_hosts_captured": len(hosts),
        "captured_hosts": sorted(hosts),
        "representative_files": representatives,
        "unreadable_files": unreadable,
    }


def _url_host(url: str) -> str:
    try:
        return normalize_hostname(urlsplit(str(url or "")).hostname or "")
    except ValueError:
        return ""


def select_live_urls(
    http_records: list[dict[str, Any]],
    limit: int,
    classified_assets: list[dict[str, Any]] | None = None,
) -> tuple[list[str], dict[str, Any]]:
    priorities = {
        str(asset.get("host") or ""): 0 if asset.get("priority") == "High" else 1
        for asset in (classified_assets or [])
    }
    candidates: list[tuple[int, int, int, str]] = []
    seen_urls: set[str] = set()
    for record in http_records:
        url = str(record.get("url") or "").strip()
        host = normalize_hostname(record.get("host") or record.get("input") or _url_host(url))
        status = record.get("status_code")
        try:
            code = int(status)
            live = 100 <= code < 600
        except (TypeError, ValueError):
            code = 999
            live = False
        if not url or not host or not live or url in seen_urls:
            continue
        seen_urls.add(url)
        status_rank = 0 if 200 <= code < 400 else 1
        scheme_rank = 0 if url.lower().startswith("https://") else 1
        candidates.append((priorities.get(host, 1), status_rank, scheme_rank, url))

    # Keep one best screenshot URL per host. This prevents duplicate HTTP/HTTPS
    # captures while retaining deterministic priority selection.
    selected_by_host: dict[str, tuple[int, int, int, str]] = {}
    for item in sorted(candidates):
        host = _url_host(item[3])
        if host and host not in selected_by_host:
            selected_by_host[host] = item
    eligible = [item[3] for item in sorted(selected_by_host.values())]
    selected = eligible[: max(0, limit)]
    metadata = {
        "eligible_urls": len(eligible),
        "eligible_unique_hosts": len(selected_by_host),
        "selected_urls": len(selected),
        "selected_unique_hosts": len({_url_host(url) for url in selected if _url_host(url)}),
        "skipped_by_limit": max(0, len(eligible) - len(selected)),
        "selection_policy": "One best URL per host; high-priority assets first, then successful/redirecting HTTPS responses, then remaining live responses.",
        "coverage_percent": round((len(selected) / len(eligible) * 100), 2) if eligible else 0.0,
    }
    return selected, metadata


def build_screenshot_status(
    run_dir: Path,
    requested: bool,
    tool_result: ToolResult | None,
    coverage: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    input_count = len(read_lines(run_dir / "live_urls_for_screenshot.txt"))
    json_count = count_jsonl_records(run_dir / "httpx_screenshots.jsonl")
    image_files = find_screenshot_files(run_dir)
    artifact_summary = screenshot_artifact_summary(run_dir, image_files)
    notes: list[str] = []

    if not requested:
        status = "Not Requested"
        notes.append("Screenshot capture was disabled or no live URL was available.")
    elif tool_result is not None and not tool_result.ok:
        status = "Failed"
        notes.append("The httpx screenshot command returned a failure or timed out.")
    elif image_files:
        status = "OK"
        notes.append("Screenshot image files were created for the selected URLs.")
    elif json_count:
        status = "Warning"
        notes.append("Screenshot JSON records exist, but no image files were found.")
    else:
        status = "Failed"
        notes.append("No screenshot JSON records or image files were created.")

    result = {
        "status": status,
        "requested": requested,
        "input_urls": input_count,
        "json_records": json_count,
        "image_files": len(image_files),
        "notes": notes,
        "artifact_summary": artifact_summary,
    }
    result.update(coverage or {})
    return result, image_files
