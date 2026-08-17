from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return default


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return records
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_csv(path: Path, records: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row: dict[str, Any] = {}
            for field in fields:
                value = record.get(field)
                if isinstance(value, (dict, list, tuple, set)):
                    value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                row[field] = "" if value is None else value
            writer.writerow(row)


def latest_run(run_root: Path, target: str) -> Path | None:
    prefix = target.lower().strip().rstrip(".") + "-"
    candidates = [p for p in run_root.iterdir() if p.is_dir() and p.name.lower().startswith(prefix)] if run_root.exists() else []
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.name)
