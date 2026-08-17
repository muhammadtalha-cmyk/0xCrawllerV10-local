from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from .identity import normalize_host, normalize_url

STATIC_CATEGORIES = {"CSS/Font Asset", "JavaScript/Static Bundle", "File/Media Endpoint", "Cloudflare/CDN Endpoint"}
SUSPICIOUS_TOKENS = ("/js/chrome", "/types/global", "/types/lazysizes-config")


def normalize_endpoint(record: dict[str, Any], current_http_hosts: set[str]) -> dict[str, Any] | None:
    url = normalize_url(record.get("normalized_url") or record.get("url"))
    if not url:
        return None
    parts = urlsplit(url)
    host = normalize_host(parts.hostname)
    path = parts.path or "/"
    category = str(record.get("category") or "Other Endpoint")
    priority = str(record.get("priority") or "Low")
    suspicious_reasons: list[str] = []
    lower_path = path.lower()
    if "\\" in str(record.get("url") or "") or "%5c" in str(record.get("url") or "").lower():
        suspicious_reasons.append("encoded_or_literal_backslash")
    if lower_path.startswith("/" + host + "/"):
        suspicious_reasons.append("hostname_repeated_inside_path")
    if any(token in lower_path for token in SUSPICIOUS_TOKENS):
        suspicious_reasons.append("javascript_string_misclassified_as_path")
    if re.search(r"/(?:https?|www)[.:/]", lower_path):
        suspicious_reasons.append("embedded_url_in_path")

    if suspicious_reasons:
        state = "SYNTACTICALLY_SUSPICIOUS"
    elif category in STATIC_CATEGORIES:
        state = "STATIC_ASSET"
    elif path == "/" and host in current_http_hosts:
        state = "VALIDATED_ROOT_ENDPOINT"
    else:
        state = "CRAWLER_OBSERVED"
    return {
        "endpoint_id": "url:" + url,
        "url": url,
        "host": host,
        "path": path,
        "query": parts.query,
        "category": category,
        "priority": priority,
        "state": state,
        "requires_http_revalidation": state in {"CRAWLER_OBSERVED", "SYNTACTICALLY_SUSPICIOUS"},
        "suspicious_reasons": suspicious_reasons,
        "source": "endpoint_classification",
    }
