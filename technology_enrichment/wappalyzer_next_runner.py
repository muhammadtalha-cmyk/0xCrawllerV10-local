from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .docker_runner import run_command
from .io_utils import read_json


def _mount_path(path: Path) -> str:
    return str(path.resolve())


def _normalise_category(categories: list[str] | None) -> str:
    values = [str(value).strip() for value in (categories or []) if str(value).strip()]
    joined = " ".join(values).lower()
    if "database" in joined:
        return "Database"
    if "message queue" in joined or "message queues" in joined:
        return "Message Queue"
    if "cache" in joined:
        return "Database / Cache"
    if "search" in joined and "engine" in joined:
        return "Search / Database"
    if "web framework" in joined or "javascript framework" in joined:
        return "Web Framework"
    if "cms" in joined or "content management" in joined:
        return "CMS"
    if "programming language" in joined:
        return "Programming Language"
    if "web server" in joined:
        return "Web Server"
    if "javascript librar" in joined:
        return "JavaScript Library"
    if "cdn" in joined or "security" in joined:
        return "CDN / Security Edge"
    return values[0] if values else "Technology"


def parse_wappalyzer_next(raw: Any, *, scan_type: str) -> list[dict[str, Any]]:
    """Parse Wappalyzer Next's URL-keyed JSON output into stable records."""
    if not isinstance(raw, dict):
        return []
    output: list[dict[str, Any]] = []
    for url, detected in raw.items():
        if not isinstance(detected, dict):
            continue
        host = (urlsplit(str(url)).hostname or "").lower()
        technologies: list[dict[str, Any]] = []
        for name, details in detected.items():
            details = details if isinstance(details, dict) else {}
            version = str(details.get("version") or "").strip() or None
            try:
                confidence_pct = max(0.0, min(100.0, float(details.get("confidence") or 0.0)))
            except (TypeError, ValueError):
                confidence_pct = 0.0
            categories = [str(value) for value in (details.get("categories") or [])]
            groups = [str(value) for value in (details.get("groups") or [])]
            category = _normalise_category(categories)
            lower_category = category.lower()
            scope = (
                "application_reference_not_service_confirmation"
                if any(token in lower_category for token in ("database", "queue", "cache", "search"))
                else "web_application"
            )
            technologies.append({
                "name": str(name),
                "version": version,
                "category": category,
                "categories": categories,
                "groups": groups,
                "confidence_score": round(confidence_pct / 100.0, 3),
                "confidence_percent": confidence_pct,
                "source": "wappalyzer_next",
                "scope": scope,
                "evidence_type": f"wappalyzer_next_{scan_type}",
                "value": f"categories={categories}; groups={groups}",
            })
        output.append({
            "target": str(url),
            "host": host,
            "scan_type": scan_type,
            "technologies": sorted(technologies, key=lambda item: item["name"].lower()),
        })
    return sorted(output, key=lambda item: item["target"])


def _run_scan(
    targets: list[dict[str, Any]],
    *,
    lane_dir: Path,
    image: str,
    scan_type: str,
    workers: int,
    page_timeout: int,
    lane_timeout: int,
) -> dict[str, Any]:
    if not targets:
        return {"status": "SKIPPED", "reason": f"no_{scan_type}_targets", "records": [], "targets": 0}
    target_file = lane_dir / f"{scan_type}_targets.txt"
    result_file = lane_dir / f"{scan_type}_results.json"
    target_file.write_text("\n".join(str(item["url"]) for item in targets) + "\n", encoding="utf-8")
    command = [
        "docker", "run", "--rm",
        "--shm-size=1g",
        "-v", f"{_mount_path(lane_dir)}:/work",
        image,
        "-i", f"/work/{target_file.name}",
        "--scan-type", scan_type,
        "-w", str(max(1, min(3 if scan_type == "full" else 20, workers))),
        "-t", str(max(5, min(120, int(page_timeout)))),
        "-oJ", f"/work/{result_file.name}",
    ]
    execution = run_command(command, timeout=lane_timeout)
    raw = read_json(result_file, {})
    if not raw and execution.get("stdout"):
        try:
            raw = json.loads(str(execution["stdout"]))
        except json.JSONDecodeError:
            raw = {}
    records = parse_wappalyzer_next(raw, scan_type=scan_type)
    status = "COMPLETE" if execution.get("ok") else ("PARTIAL" if records else "FAILED")
    return {
        "status": status,
        "targets": len(targets),
        "records": records,
        "scan_type": scan_type,
        "workers": max(1, min(3 if scan_type == "full" else 20, workers)),
        "execution": {key: value for key, value in execution.items() if key != "stdout"},
        "stderr_tail": str(execution.get("stderr") or "")[-4000:],
    }


def run_wappalyzer_next(
    targets: list[dict[str, Any]],
    *,
    output_dir: Path,
    image: str,
    max_mode: bool,
    full_workers: int,
    balanced_workers: int,
    full_target_cap: int,
    page_timeout: int,
    lane_timeout: int,
) -> dict[str, Any]:
    """Run browser-backed fingerprints on priority targets and balanced scans on overflow.

    The full browser lane is deliberately capped because Chromium is memory intensive.
    Other enrichment lanes still run in parallel with this lane.
    """
    lane_dir = output_dir / "wappalyzer_next"
    lane_dir.mkdir(parents=True, exist_ok=True)
    if not targets:
        return {"status": "SKIPPED", "reason": "no_web_targets", "records": [], "targets": 0, "tool": "wappalyzer-next"}

    ordered = sorted(
        targets,
        key=lambda item: (
            not bool(item.get("high_priority")),
            str(item.get("priority") or "Medium").lower() != "high",
            str(item.get("host") or ""),
        ),
    )
    cap = max(1, int(full_target_cap))
    if max_mode:
        full_targets = ordered[:cap]
    else:
        priority = [item for item in ordered if item.get("high_priority") or str(item.get("priority") or "").lower() == "high"]
        full_targets = priority[:cap]
    full_urls = {str(item.get("url")) for item in full_targets}
    balanced_targets = [item for item in ordered if str(item.get("url")) not in full_urls]

    # These two modes are sequential inside one lane to avoid two Chromium-heavy
    # containers competing for RAM. The entire lane runs concurrently with the
    # HTTP, WhatWeb, Retire.js and ZGrab2 lanes.
    full = _run_scan(
        full_targets,
        lane_dir=lane_dir,
        image=image,
        scan_type="full",
        workers=full_workers,
        page_timeout=page_timeout,
        lane_timeout=lane_timeout,
    )
    balanced = _run_scan(
        balanced_targets,
        lane_dir=lane_dir,
        image=image,
        scan_type="balanced",
        workers=balanced_workers,
        page_timeout=page_timeout,
        lane_timeout=lane_timeout,
    )
    records = [*(full.get("records") or []), *(balanced.get("records") or [])]
    statuses = [record.get("status") for record in (full, balanced) if record.get("status") != "SKIPPED"]
    if not statuses:
        status = "SKIPPED"
    elif all(value == "COMPLETE" for value in statuses):
        status = "COMPLETE"
    elif records:
        status = "PARTIAL"
    else:
        status = "FAILED"
    return {
        "status": status,
        "tool": "wappalyzer-next",
        "image": image,
        "targets": len(targets),
        "full_targets": len(full_targets),
        "balanced_targets": len(balanced_targets),
        "records": records,
        "full": full,
        "balanced": balanced,
    }
