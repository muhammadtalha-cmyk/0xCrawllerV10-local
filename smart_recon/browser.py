"""Extract in-scope URLs and hosts observed by httpx headless rendering."""

from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlparse

from .validation import is_in_scope_host, is_valid_hostname, normalize_hostname

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk_strings(item)


def extract_browser_observations(
    records: list[dict[str, Any]],
    target: str,
) -> tuple[set[str], set[str]]:
    """Return target-scope URLs and hosts; ignore local browser/container addresses."""
    urls: set[str] = set()
    hosts: set[str] = set()
    for record in records:
        for text in _walk_strings(record):
            candidates = URL_RE.findall(text)
            if text.lower().startswith(("http://", "https://")):
                candidates.append(text.strip())
            for candidate in candidates:
                cleaned = candidate.rstrip(".,);]}>")
                try:
                    parsed = urlparse(cleaned)
                except ValueError:
                    continue
                host = normalize_hostname(parsed.hostname or "")
                if not is_valid_hostname(host) or not is_in_scope_host(host, target):
                    continue
                urls.add(cleaned)
                hosts.add(host)
    return urls, hosts
