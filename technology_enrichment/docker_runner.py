from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any


def docker_available() -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    version = (proc.stdout or "").strip()
    return proc.returncode == 0, version or (proc.stderr or "").strip()


def run_command(
    command: list[str],
    *,
    stdin_text: str | None = None,
    timeout: int = 900,
    cwd: Path | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "return_code": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "timed_out": False,
            "seconds": round(time.monotonic() - started, 3),
            "command": command,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "return_code": None,
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            "timed_out": True,
            "seconds": round(time.monotonic() - started, 3),
            "command": command,
        }
    except OSError as exc:
        return {
            "ok": False,
            "return_code": None,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
            "seconds": round(time.monotonic() - started, 3),
            "command": command,
        }


def docker_build(context: Path, tag: str, *, timeout: int = 1800) -> dict[str, Any]:
    return run_command(["docker", "build", "--pull", "-t", tag, str(context)], timeout=timeout)
