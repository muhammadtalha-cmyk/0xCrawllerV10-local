"""HTTP asset, ownership, CDN/WAF, and endpoint classification."""

from __future__ import annotations

import csv
import posixpath
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from .config import RELEVANT_EXTERNAL_HOST_SUFFIXES, THIRD_PARTY_PROVIDERS
from .edge_detection import extract_passive_edge_evidence
from .parsers import PRIVATE_IP_RE, classify_cname_ownership
from .validation import is_in_scope_host, is_valid_hostname, normalize_hostname

STATIC_EXTENSIONS = {
    ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4", ".pdf", ".zip",
}
JS_EXTENSIONS = {".js", ".mjs", ".cjs"}
CSS_FONT_EXTENSIONS = {".css", ".woff", ".woff2", ".ttf", ".eot", ".otf"}
FILE_MEDIA_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".mp3", ".mp4", ".pdf", ".zip"}
API_SEGMENTS = {"api", "apis", "graphql", "rest", "rpc", "v1", "v2", "v3", "openapi", "swagger"}
ADMIN_SEGMENTS = {"admin", "administrator", "dashboard", "panel", "console", "manage", "management"}
AUTH_SEGMENTS = {"login", "logout", "signin", "sign-in", "signup", "sign-up", "auth", "oauth", "account", "accounts", "user", "users", "session", "sessions"}
BUSINESS_SEGMENTS = {"checkout", "booking", "payment", "payments", "invoice", "invoices", "order", "orders", "review", "import", "export"}
FILE_SEGMENTS = {"upload", "uploads", "download", "downloads", "file", "files", "media", "image", "images", "asset", "assets", "storage"}


def _provider_from_host(host: str) -> str | None:
    normalized = normalize_hostname(host)
    for suffix, provider in THIRD_PARTY_PROVIDERS.items():
        if normalized == suffix or normalized.endswith("." + suffix):
            return provider
    return None


def canonicalize_endpoint_url(url: str) -> str | None:
    """Normalize equivalent URL variants and reject malformed URLs."""
    raw = unquote(str(url or "").strip()).replace("\\", "/")
    if not raw:
        return None
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    host = normalize_hostname(parsed.hostname or "")
    if not host or not is_valid_hostname(host):
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"

    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    had_trailing_slash = path.endswith("/")
    normalized_path = posixpath.normpath(path)
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    if normalized_path == "/.":
        normalized_path = "/"
    if had_trailing_slash and normalized_path != "/":
        normalized_path += "/"

    # Stable query ordering makes equivalent variants deduplicate.
    try:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        normalized_query = urlencode(sorted(query_pairs), doseq=True)
    except ValueError:
        normalized_query = parsed.query

    # Keep URL-safe path characters while removing backslash-derived noise.
    normalized_path = quote(normalized_path, safe="/%:@!$&'()*+,;=-._~")
    return urlunsplit((scheme, netloc, normalized_path, normalized_query, ""))


def is_relevant_endpoint_url(url: str, target: str) -> bool:
    normalized = canonicalize_endpoint_url(url)
    if not normalized:
        return False
    parsed = urlsplit(normalized)
    host = normalize_hostname(parsed.hostname or "")
    if is_in_scope_host(host, target):
        return True
    if PRIVATE_IP_RE.fullmatch(host):
        return True
    return any(host == suffix or host.endswith("." + suffix) for suffix in RELEVANT_EXTERNAL_HOST_SUFFIXES)


def status_bucket(status: Any) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "unreachable_or_unknown"
    if 200 <= code < 300:
        return "2xx_success"
    if 300 <= code < 400:
        return "3xx_redirect"
    if code in {401, 403}:
        return "protected_or_waf"
    if code == 404:
        return "404_not_found"
    if code == 525:
        return "cloudflare_ssl_handshake_error"
    if code == 530:
        return "cloudflare_origin_or_access_error"
    if 500 <= code < 600:
        return "5xx_server_error"
    return "other"


def _edge_response_category(status: Any, title: str, cdn_name: str) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "http_unreachable"
    title_l = title.lower()
    cdn_l = cdn_name.lower()
    if cdn_l == "cloudflare":
        if code == 525:
            return "cloudflare_ssl_handshake_error"
        if code == 530:
            return "cloudflare_origin_or_access_error"
        if code == 403 and ("attention required" in title_l or "cloudflare" in title_l):
            return "cloudflare_waf_or_access_block"
        if code == 200 and "cloudflare access" in title_l:
            return "cloudflare_access_protected"
    if code == 404:
        return "default_404_or_missing_root_route"
    if 200 <= code < 400:
        return "application_live"
    if 500 <= code < 600:
        return "application_or_upstream_error"
    return "other_http_response"


def classify_http_asset(obj: dict[str, Any]) -> dict[str, Any]:
    host = normalize_hostname(obj.get("host") or obj.get("input") or "")
    url = str(obj.get("url") or "")
    title = str(obj.get("title") or "")
    content_type = str(obj.get("content_type") or obj.get("content-type") or "").lower()
    raw_tech = obj.get("tech") or []
    tech = [str(raw_tech)] if isinstance(raw_tech, str) else [str(value) for value in raw_tech]
    status = obj.get("status_code")
    raw_cnames = obj.get("cname") or []
    cname_values = [raw_cnames] if isinstance(raw_cnames, str) else list(raw_cnames)
    cnames = [normalize_hostname(value) for value in cname_values if value]
    cdn_name = str(obj.get("cdn_name") or "").lower()
    labels = host.split(".") if host else []
    left_label = labels[0] if labels else ""
    text = f"{left_label} {url} {title}".lower()
    tech_text = " ".join(item.lower() for item in tech)

    ownership, provider = classify_cname_ownership(cnames)
    if not provider:
        provider = _provider_from_host(host)
        if provider:
            ownership = "third_party_saas"
    if cdn_name in {"cloudflare", "cloudfront", "fastly", "akamai"} and ownership != "third_party_saas":
        ownership = "cdn_edge_or_first_party_frontend"

    category = "Unknown / Needs Review"
    priority = "Medium"
    notes: list[str] = []

    label_tokens = set(re.split(r"[-.]", left_label))
    if label_tokens & ADMIN_SEGMENTS:
        category, priority = "Admin / Management Surface", "High"
        notes += [
            "Verify authentication is enforced on every administrative route.",
            "Check role separation, session timeout, MFA and rate limiting if in scope.",
        ]
    elif label_tokens & API_SEGMENTS or left_label.endswith("-api") or left_label.startswith("api-"):
        category, priority = "Backend / API Surface", "High"
        notes += [
            "Verify API authentication, authorization, CORS policy, method exposure and error handling.",
            "Check object-level access control only with authorized test accounts.",
        ]
    elif label_tokens & {"mail", "email", "otp", "smtp"}:
        category, priority = "Email / OTP / Notification", "Medium"
        notes.append("Review SPF/DKIM/DMARC, OTP throttling, reset flows and notification-link exposure.")
    elif label_tokens & {"file", "files", "upload", "uploads", "storage", "sync", "drive"}:
        category, priority = "File / Storage / Sync", "High"
        notes.append("Check access control, upload restrictions, file validation and direct object access.")
    elif label_tokens & {"chat", "xmpp", "call"}:
        category, priority = "Communication Service", "Medium"
    elif label_tokens & {"dev", "staging", "uat", "qa", "test", "beta"}:
        category, priority = "Non-production Environment", "High"
        notes.append("Confirm this environment is intentionally internet-accessible and access controlled.")

    bucket = status_bucket(status)
    edge_category = _edge_response_category(status, title, cdn_name)
    if bucket == "protected_or_waf":
        notes.append("HTTP status suggests authentication, access control, or WAF protection; verify expected behavior manually.")
    elif bucket == "404_not_found":
        notes.append("The host answered, but the root route was not found.")
    elif bucket in {"5xx_server_error", "cloudflare_ssl_handshake_error", "cloudflare_origin_or_access_error"}:
        priority = "High"
        notes.append("The response indicates an application, origin, routing, or TLS problem that requires manual verification.")

    edge_evidence = extract_passive_edge_evidence(obj)
    cdn_detection = edge_evidence["cdn"]
    waf_detection = edge_evidence["waf"]
    application_provider = provider or edge_evidence.get("application_provider")
    network_provider = edge_evidence.get("network_provider") or cdn_detection.get("provider")
    if application_provider and ownership != "cdn_edge_or_first_party_frontend":
        ownership = "third_party_saas"
    if cdn_detection.get("detected") or waf_detection.get("detected"):
        notes.append("CDN/WAF edge evidence exists; do not treat edge IP ports as confirmed origin exposure.")
    if ownership == "third_party_saas":
        notes.append("Third-party managed service; intrusive testing requires explicit authorization for that provider/service.")

    return {
        "host": host,
        "url": url,
        "status_code": status,
        "status_bucket": bucket,
        "edge_response_category": edge_category,
        "title": title,
        "category": category,
        "priority": priority,
        "content_type": content_type,
        "tech": tech,
        "technologies": edge_evidence["technologies"]["items"],
        "technology_detection": edge_evidence["technologies"],
        "cname": cnames,
        "ownership": ownership,
        "provider": application_provider,
        "application_provider": application_provider,
        "network_provider": network_provider,
        "cdn": bool(obj.get("cdn")),
        "cdn_name": cdn_name or None,
        "cdn_type": obj.get("cdn_type"),
        "cdn_detection": cdn_detection,
        "waf_detection": waf_detection,
        "response_time": obj.get("time") or obj.get("response_time"),
        "review_notes": sorted(set(notes)),
    }


def _path_segments(path: str) -> list[str]:
    return [segment.lower() for segment in path.split("/") if segment]


def classify_endpoint_url(url: str, target: str) -> dict[str, str]:
    normalized = canonicalize_endpoint_url(url)
    if not normalized:
        return {"url": str(url), "normalized_url": "", "host": "", "path": "", "category": "Malformed URL", "priority": "Low"}
    parsed = urlsplit(normalized)
    host = normalize_hostname(parsed.hostname or "")
    path = parsed.path or "/"
    segments = _path_segments(path)
    segment_set = set(segments)
    suffix = Path(path).suffix.lower()
    is_third_party = not is_in_scope_host(host, target)

    category, priority = "Other Endpoint", "Low"
    if is_third_party:
        category, priority = "Third-party Reference", "Low"
    elif suffix in JS_EXTENSIONS or "/_next/static/" in path.lower() or "/static/chunks/" in path.lower():
        category, priority = "JavaScript/Static Bundle", "Medium"
    elif suffix in CSS_FONT_EXTENSIONS:
        category, priority = "CSS/Font Asset", "Low"
    elif suffix in FILE_MEDIA_EXTENSIONS:
        category, priority = "File/Media Endpoint", "Low"
    elif any(segment in API_SEGMENTS for segment in segments) or path.lower().endswith(("/openapi.json", "/swagger.json", "/api-docs")):
        category, priority = "API Endpoint", "High"
    elif any(segment in ADMIN_SEGMENTS for segment in segments):
        category, priority = "Admin/Management Endpoint", "High"
    elif any(segment in AUTH_SEGMENTS for segment in segments):
        category, priority = "Auth/User Endpoint", "High"
    elif any(segment in FILE_SEGMENTS for segment in segments):
        category, priority = "File/Storage Endpoint", "Medium"
    elif any(segment in BUSINESS_SEGMENTS for segment in segments):
        category, priority = "Business Logic Endpoint", "High"
    elif "cdn-cgi" in segment_set:
        category, priority = "Cloudflare/CDN Endpoint", "Low"

    return {
        "url": str(url),
        "normalized_url": normalized,
        "host": host,
        "path": path,
        "category": category,
        "priority": priority,
    }


def summarize_endpoint_categories(urls: Iterable[str], target: str) -> dict[str, Any]:
    raw_unique_urls = sorted({str(url).strip() for url in urls if str(url).strip()})
    normalized_records: dict[str, dict[str, str]] = {}
    malformed: list[str] = []
    external_refs: list[str] = []
    for raw_url in raw_unique_urls:
        normalized = canonicalize_endpoint_url(raw_url)
        if not normalized:
            malformed.append(raw_url)
            continue
        record = classify_endpoint_url(raw_url, target)
        host = record["host"]
        if not is_in_scope_host(host, target):
            external_refs.append(normalized)
            continue
        normalized_records.setdefault(normalized, record)

    records = list(normalized_records.values())
    categories: dict[str, dict[str, Any]] = {}
    for record in records:
        category = record["category"]
        categories.setdefault(category, {"count": 0, "priority": record["priority"], "samples": []})
        categories[category]["count"] += 1
        if len(categories[category]["samples"]) < 8:
            categories[category]["samples"].append(record["normalized_url"])

    openapi_candidates = sorted({
        record["normalized_url"]
        for record in records
        if record["path"].lower().endswith(("openapi.json", "swagger.json", "api-docs"))
    })
    return {
        "total_raw_unique_urls": len(raw_unique_urls),
        "total_normalized_in_scope_urls": len(records),
        "total_unique_urls": len(records),
        "deduplicated_or_filtered_urls": max(0, len(raw_unique_urls) - len(records)),
        "malformed_urls": malformed,
        "external_references": sorted(set(external_refs)),
        "openapi_candidates": openapi_candidates,
        "categories": categories,
        "records": records,
    }


def make_review_csv(path: Path, assets: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "host", "url", "status_code", "title", "category", "priority",
                "edge_response_category", "ownership", "provider", "application_provider",
                "network_provider", "cdn_name",
                "cdn_detected", "cdn_provider", "cdn_confidence",
                "waf_detected", "waf_provider", "waf_confidence", "waf_attribution",
                "waf_active_provider", "waf_outer_edge_provider", "waf_mode",
                "technologies", "review_notes",
            ],
        )
        writer.writeheader()
        for asset in assets:
            writer.writerow({
                "host": asset.get("host", ""),
                "url": asset.get("url", ""),
                "status_code": asset.get("status_code", ""),
                "title": asset.get("title", ""),
                "category": asset.get("category", ""),
                "priority": asset.get("priority", ""),
                "edge_response_category": asset.get("edge_response_category", ""),
                "ownership": asset.get("ownership", ""),
                "provider": asset.get("provider", ""),
                "application_provider": asset.get("application_provider", ""),
                "network_provider": asset.get("network_provider", ""),
                "cdn_name": asset.get("cdn_name", ""),
                "cdn_detected": (asset.get("cdn_detection") or {}).get("detected", False),
                "cdn_provider": (asset.get("cdn_detection") or {}).get("provider", ""),
                "cdn_confidence": (asset.get("cdn_detection") or {}).get("confidence", ""),
                "waf_detected": (asset.get("waf_detection") or {}).get("detected", False),
                "waf_provider": (asset.get("waf_detection") or {}).get("provider", ""),
                "waf_confidence": (asset.get("waf_detection") or {}).get("confidence", ""),
                "waf_attribution": (asset.get("waf_detection") or {}).get("attribution", ""),
                "waf_active_provider": (asset.get("waf_detection") or {}).get("active_provider", ""),
                "waf_outer_edge_provider": (asset.get("waf_detection") or {}).get("outer_edge_provider", ""),
                "waf_mode": (asset.get("waf_detection") or {}).get("mode", ""),
                "technologies": ",".join(asset.get("technologies", []) or []),
                "review_notes": " | ".join(asset.get("review_notes", []) or []),
            })
