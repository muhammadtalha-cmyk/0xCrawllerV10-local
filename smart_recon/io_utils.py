"""File, JSON, JSONL, and chunk helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence


def write_lines(path: Path, values: Iterable[str], *, sort_values: bool = True) -> None:
    cleaned = {str(v).strip() for v in values if v and str(v).strip()}
    vals = sorted(cleaned) if sort_values else list(cleaned)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(vals) + ("\n" if vals else ""), encoding="utf-8")


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in read_lines(path):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def count_jsonl_records(path: Path) -> int:
    return len(read_jsonl(path))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=False, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def chunked(values: Sequence[str], size: int) -> Iterator[list[str]]:
    if size <= 0:
        raise ValueError("chunk size must be greater than zero")
    for index in range(0, len(values), size):
        yield list(values[index:index + size])
