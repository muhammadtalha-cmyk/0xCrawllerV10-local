"""Domain, hostname, and URL validation helpers."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_hostname(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def is_valid_hostname(host: str, *, allow_root: bool = True) -> bool:
    value = normalize_hostname(host)
    if not value or len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2 and not allow_root:
        return False
    return all(0 < len(label) <= 63 and LABEL_RE.fullmatch(label) for label in labels)


def is_in_scope_host(host: str, target: str) -> bool:
    host_n = normalize_hostname(host)
    target_n = normalize_hostname(target)
    return host_n == target_n or host_n.endswith("." + target_n)


def normalize_candidate(host: str, target: str) -> str | None:
    value = normalize_hostname(host)
    if not is_valid_hostname(value) or not is_in_scope_host(value, target):
        return None
    return value


def parent_zone_for_host(host: str, target: str) -> str:
    """Return the immediate parent zone, never above target."""
    host_n = normalize_hostname(host)
    target_n = normalize_hostname(target)
    if host_n == target_n:
        return target_n
    labels = host_n.split(".")
    target_labels = target_n.split(".")
    if len(labels) <= len(target_labels) + 1:
        return target_n
    return ".".join(labels[1:])


def normalize_http_url(url: str) -> str | None:
    raw = str(url or "").strip().replace("\\", "/")
    if not raw:
        return None
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    host = normalize_hostname(parsed.hostname or "")
    if not is_valid_hostname(host):
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    port = parsed.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    return urlunsplit((scheme, netloc, path, parsed.query, ""))
