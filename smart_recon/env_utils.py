"""Minimal .env loading without third-party dependencies."""

from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: Path, *, override: bool = False) -> dict[str, str]:
    """Load KEY=VALUE pairs from *path* into ``os.environ``.

    Blank lines and comments are ignored. Values may be single- or double-quoted.
    Existing environment variables are preserved unless ``override`` is true.
    """
    loaded: dict[str, str] = {}
    if not path.exists() or not path.is_file():
        return loaded
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        loaded[key] = value
        if override or key not in os.environ:
            os.environ[key] = value
    return loaded
