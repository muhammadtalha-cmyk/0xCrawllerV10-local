from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

HOST_RE = re.compile(r"^(?=.{1,253}\.?$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.I)


def normalize_host(value: object) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not text:
        return ""
    if "://" in text:
        text = (urlsplit(text).hostname or "").lower().rstrip(".")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return text


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_host(value: str) -> bool:
    host = normalize_host(value)
    if not host or "%" in host or "\\" in host or "/" in host:
        return False
    if is_ip(host):
        return True
    return bool(HOST_RE.fullmatch(host))


def in_scope(host: str, root: str) -> bool:
    host = normalize_host(host)
    root = normalize_host(root)
    return bool(host and root and (host == root or host.endswith("." + root)))


def normalize_url(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except ValueError:
        return ""
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return ""
    host = normalize_host(parts.hostname)
    if not is_valid_host(host):
        return ""
    port = parts.port
    netloc = host
    if port and not ((parts.scheme.lower() == "http" and port == 80) or (parts.scheme.lower() == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def asset_id(host: str) -> str:
    return f"host:{normalize_host(host)}"


def service_id(host: str, protocol: str, port: int) -> str:
    return f"service:{normalize_host(host)}:{protocol.lower()}:{int(port)}"
