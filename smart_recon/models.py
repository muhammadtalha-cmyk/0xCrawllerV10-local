"""Shared data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ToolResult:
    name: str
    ok: bool
    returncode: int
    seconds: float
    stdout_path: Path
    stderr_path: Path
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    timed_out: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.timed_out:
            return "Timed Out"
        if not self.ok:
            return "Failed"
        if self.warnings or self.errors:
            return "Warning"
        return "OK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "ok": self.ok,
            "timed_out": self.timed_out,
            "warning_count": len(self.warnings),
            "warnings_sample": self.warnings[:10],
            "error_count": len(self.errors),
            "errors_sample": self.errors[:10],
            "returncode": self.returncode,
            "seconds": round(self.seconds, 2),
            "stdout_path": str(self.stdout_path),
            "stderr_path": str(self.stderr_path),
            "metadata": self.metadata,
        }
