from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .docker_runner import run_command
from .io_utils import read_json


def _mount_path(path: Path) -> str:
    return str(path.resolve())


def parse_nuclei_findings(raw_jsonl: str) -> list[dict[str, Any]]:
    """Parse nuclei's `-jsonl` output into a flat, stable finding shape.

    Nuclei findings are vulnerability/template-match evidence, not raw
    technology-version evidence — a CVE template match can *corroborate* a
    version already seen elsewhere (e.g. reconcile.py can cross-reference
    matched CVEs against `technology_inventory` versions during manual
    triage), but it is intentionally NOT auto-merged into the confidence
    scoring in reconcile.py. Silently upgrading confidence from a vuln
    template match risks false corroboration (templates frequently match
    on behavior/response patterns rather than a confirmed exact version).
    """
    findings: list[dict[str, Any]] = []
    for line in (raw_jsonl or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        info = row.get("info") or {}
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        findings.append({
            "template_id": row.get("template-id") or row.get("template_id"),
            "template_name": info.get("name"),
            "severity": str(info.get("severity") or "unknown").upper(),
            "cve": sorted({str(c) for c in cve_ids}) if cve_ids else [],
            "tags": info.get("tags") or [],
            "description": info.get("description"),
            "matched_at": row.get("matched-at") or row.get("matched_at") or row.get("host"),
            "protocol": row.get("type"),
            "host": row.get("host"),
            "curl_command": row.get("curl-command") or row.get("curl_command"),
        })
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in findings:
        key = (str(item.get("host") or ""), str(item.get("template_id") or ""), str(item.get("matched_at") or ""))
        dedup[key] = item
    return sorted(
        dedup.values(),
        key=lambda x: (str(x.get("host") or ""), str(x.get("severity") or ""), str(x.get("template_id") or "")),
    )


def run_nuclei(
    targets: list[dict[str, Any]],
    *,
    output_dir: Path,
    image: str,
    severity: list[str] | None,
    templates: str | None,
    workers: int,
    request_timeout: float,
    timeout: int,
) -> dict[str, Any]:
    lane_dir = output_dir / "nuclei"
    lane_dir.mkdir(parents=True, exist_ok=True)
    target_file = lane_dir / "targets.txt"
    result_file = lane_dir / "nuclei.jsonl"
    target_file.write_text("\n".join(t["url"] for t in targets) + ("\n" if targets else ""), encoding="utf-8")
    if not targets:
        return {"status": "SKIPPED", "reason": "no_web_targets", "findings": [], "tool": "nuclei"}

    command = [
        "docker", "run", "--rm",
        "-v", f"{_mount_path(lane_dir)}:/work",
        "-v", "crawller_nuclei_templates:/root/nuclei-templates",
        image,
        "-l", "/work/targets.txt",
        "-jsonl",
        "-o", "/work/nuclei.jsonl",
        "-silent",
        "-c", str(max(1, workers)),
        # Per-request/template timeout (seconds). This bounds a single
        # template check, NOT the overall lane — the overall wall-clock
        # budget is `timeout` (the lane_timeout passed to run_command
        # below), matching the engine's other Docker lanes.
        "-timeout", str(max(2, int(request_timeout))),
    ]
    if severity:
        command += ["-severity", ",".join(severity)]
    if templates:
        command += ["-t", templates]
    else:
        command += ["-t", "/root/nuclei-templates"]

    execution = run_command(command, timeout=timeout)
    raw_jsonl = result_file.read_text(encoding="utf-8", errors="replace") if result_file.exists() else ""
    if not raw_jsonl and execution.get("stdout"):
        raw_jsonl = execution["stdout"]
    findings = parse_nuclei_findings(raw_jsonl)

    # Empty output with a clean exit is a valid "no findings" outcome, not
    # a failure — same principle applied throughout the other lanes below.
    status = "COMPLETE" if (execution.get("ok") or (not execution.get("timed_out") and execution.get("return_code") in (0, 1))) else (
        "PARTIAL" if findings else "FAILED"
    )
    return {
        "status": status,
        "tool": "nuclei",
        "image": image,
        "targets": len(targets),
        "findings": findings,
        "execution": {key: value for key, value in execution.items() if key not in {"stdout"}},
        "stderr_tail": str(execution.get("stderr") or "")[-4000:],
    }
