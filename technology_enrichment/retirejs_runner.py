from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .docker_runner import run_command
from .io_utils import read_json, write_json


def _mount_path(path: Path) -> str:
    return str(path.resolve())


def _safe_filename(host: str, url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()[:20]
    base = Path(url.split("?", 1)[0]).name or "asset.js"
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", base)
    if not base.lower().endswith((".js", ".mjs")):
        base += ".js"
    return f"{host}__{digest}__{base}"[:220]


def _fetch_js(target: dict[str, Any], *, dest: Path, timeout: float, max_bytes: int, user_agent: str) -> dict[str, Any]:
    started = time.monotonic()
    request = Request(target["url"], headers={"User-Agent": user_agent, "Accept": "application/javascript,text/javascript,*/*;q=0.1"})
    try:
        response = urlopen(request, timeout=timeout, context=ssl.create_default_context())
        raw = response.read(max_bytes + 1)
        status = getattr(response, "status", 200)
        content_type = response.headers.get("Content-Type", "")
    except HTTPError as exc:
        raw = exc.read(max_bytes + 1)
        status = exc.code
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
    except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        return {**target, "ok": False, "error": str(exc), "seconds": round(time.monotonic() - started, 3)}
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    if status >= 400:
        return {**target, "ok": False, "status_code": status, "content_type": content_type, "error": f"HTTP {status}", "seconds": round(time.monotonic() - started, 3)}
    filename = _safe_filename(target["host"], target["url"])
    path = dest / filename
    path.write_bytes(raw)
    return {
        **target,
        "ok": True,
        "status_code": status,
        "content_type": content_type,
        "path": str(path),
        "filename": filename,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "truncated": truncated,
        "seconds": round(time.monotonic() - started, 3),
    }


def _walk_retire(value: Any, components: list[dict[str, Any]], source_file: str | None = None) -> None:
    if isinstance(value, dict):
        component = value.get("component") or value.get("componentName") or value.get("name")
        version = value.get("version") or value.get("componentVersion")
        vulnerabilities = value.get("vulnerabilities") or value.get("results") if component else None
        if component and version:
            components.append({
                "name": str(component),
                "version": str(version),
                "source_file": source_file or value.get("file") or value.get("path"),
                "vulnerabilities": vulnerabilities if isinstance(vulnerabilities, list) else [],
                "source": "retirejs",
                "confidence_score": 0.93,
            })
        next_source = str(value.get("file") or value.get("path") or source_file or "") or None
        for nested in value.values():
            _walk_retire(nested, components, next_source)
    elif isinstance(value, list):
        for nested in value:
            _walk_retire(nested, components, source_file)


def parse_retirejs(raw: Any, manifest: list[dict[str, Any]]) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    _walk_retire(raw, components)
    host_by_filename = {str(item.get("filename")): str(item.get("host")) for item in manifest if item.get("filename")}
    url_by_filename = {str(item.get("filename")): str(item.get("url")) for item in manifest if item.get("filename")}
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for component in components:
        source_file = str(component.get("source_file") or "")
        filename = Path(source_file).name if source_file else ""
        component["host"] = host_by_filename.get(filename)
        component["url"] = url_by_filename.get(filename)
        key = (str(component.get("host") or ""), component["name"].lower(), component["version"])
        dedup[key] = component
    return sorted(dedup.values(), key=lambda x: (str(x.get("host") or ""), x["name"].lower(), x["version"]))


def run_retirejs(
    targets: list[dict[str, Any]],
    *,
    output_dir: Path,
    image: str,
    workers: int,
    request_timeout: float,
    max_bytes: int,
    user_agent: str,
    timeout: int,
) -> dict[str, Any]:
    lane_dir = output_dir / "retirejs"
    cache_dir = lane_dir / "js_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    if not targets:
        return {"status": "SKIPPED", "reason": "no_javascript_targets", "records": [], "fetch_manifest": [], "tool": "retirejs"}
    manifest: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(_fetch_js, target, dest=cache_dir, timeout=request_timeout, max_bytes=max_bytes, user_agent=user_agent) for target in targets]
        for future in as_completed(futures):
            manifest.append(future.result())
    manifest.sort(key=lambda x: (str(x.get("host") or ""), str(x.get("url") or "")))
    write_json(lane_dir / "js_fetch_manifest.json", manifest)
    successful = [item for item in manifest if item.get("ok")]
    if not successful:
        return {"status": "FAILED", "reason": "javascript_downloads_failed", "records": [], "fetch_manifest": manifest, "tool": "retirejs"}
    result_file = lane_dir / "retirejs.json"
    command = [
        "docker", "run", "--rm",
        "-v", f"{_mount_path(cache_dir)}:/workspace:ro",
        "-v", f"{_mount_path(lane_dir)}:/out",
        image,
        "--path", "/workspace",
        "--outputformat", "json",
        "--outputpath", "/out/retirejs.json",
        "--exitwith", "0",
    ]
    execution = run_command(command, timeout=timeout)
    raw = read_json(result_file, [])
    if not raw and execution.get("stdout"):
        try:
            raw = json.loads(execution["stdout"])
        except json.JSONDecodeError:
            raw = []
    records = parse_retirejs(raw, successful)
    status = "COMPLETE" if execution.get("ok") else ("PARTIAL" if records else "FAILED")
    return {
        "status": status,
        "tool": "retirejs",
        "image": image,
        "targets": len(targets),
        "downloaded": len(successful),
        "records": records,
        "fetch_manifest": manifest,
        "execution": {key: value for key, value in execution.items() if key not in {"stdout"}},
        "stderr_tail": str(execution.get("stderr") or "")[-4000:],
    }
