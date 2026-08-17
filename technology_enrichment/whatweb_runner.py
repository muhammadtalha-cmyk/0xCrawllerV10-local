from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .docker_runner import run_command
from .io_utils import read_json


def _mount_path(path: Path) -> str:
    return str(path.resolve())


def parse_whatweb_records(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        rows = [raw]
    elif isinstance(raw, list):
        rows = [row for row in raw if isinstance(row, dict)]
    else:
        rows = []
    output: list[dict[str, Any]] = []
    for row in rows:
        target = str(row.get("target") or row.get("url") or "")
        plugins = row.get("plugins") or {}
        if not isinstance(plugins, dict):
            continue
        tech: list[dict[str, Any]] = []
        for name, details in plugins.items():
            details = details if isinstance(details, dict) else {}
            versions = details.get("version") or details.get("versions") or []
            if isinstance(versions, str):
                versions = [versions]
            strings = details.get("string") or details.get("strings") or []
            if isinstance(strings, str):
                strings = [strings]
            versions = [str(v).strip() for v in versions if str(v).strip()]
            if not versions:
                # Some plugins include a version only inside a matched string.
                for value in strings:
                    match = re.search(r"\b([0-9]+(?:\.[0-9A-Za-z_-]+){1,5})\b", str(value))
                    if match:
                        versions.append(match.group(1))
                        break
            tech.append({
                "name": str(name),
                "versions": sorted(set(versions)),
                "strings": [str(v)[:500] for v in strings],
                "source": "whatweb",
                "confidence_score": 0.88 if versions else 0.78,
            })
        output.append({
            "target": target,
            "http_status": row.get("http_status") or row.get("status"),
            "request_config": row.get("request_config"),
            "technologies": tech,
        })
    return output


def run_whatweb(
    targets: list[dict[str, Any]],
    *,
    output_dir: Path,
    image: str,
    threads: int,
    aggression: int,
    timeout: int,
    request_timeout: float,
) -> dict[str, Any]:
    lane_dir = output_dir / "whatweb"
    lane_dir.mkdir(parents=True, exist_ok=True)
    target_file = lane_dir / "targets.txt"
    result_file = lane_dir / "whatweb.json"
    target_file.write_text("\n".join(t["url"] for t in targets) + ("\n" if targets else ""), encoding="utf-8")
    if not targets:
        return {"status": "SKIPPED", "reason": "no_web_targets", "records": [], "tool": "whatweb"}
    command = [
        "docker", "run", "--rm",
        "-v", f"{_mount_path(lane_dir)}:/work",
        image,
        "--input-file=/work/targets.txt",
        "--log-json=/work/whatweb.json",
        f"--aggression={aggression}",
        f"--max-threads={threads}",
        f"--open-timeout={max(2, int(request_timeout))}",
        f"--read-timeout={max(3, int(request_timeout * 2))}",
        "--follow-redirect=same-site",
        "--max-redirects=5",
        "--no-errors",
    ]
    execution = run_command(command, timeout=timeout)
    raw = read_json(result_file, [])
    if not raw and execution.get("stdout"):
        try:
            raw = json.loads(execution["stdout"])
        except json.JSONDecodeError:
            raw = []
    records = parse_whatweb_records(raw)
    status = "COMPLETE" if execution.get("ok") else ("PARTIAL" if records else "FAILED")
    return {
        "status": status,
        "tool": "whatweb",
        "image": image,
        "aggression": aggression,
        "threads": threads,
        "targets": len(targets),
        "records": records,
        "execution": {key: value for key, value in execution.items() if key not in {"stdout"}},
        "stderr_tail": str(execution.get("stderr") or "")[-4000:],
    }
