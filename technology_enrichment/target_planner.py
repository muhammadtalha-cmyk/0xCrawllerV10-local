from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .io_utils import read_json


@dataclass(frozen=True)
class EnrichmentPlan:
    root_domain: str
    web_targets: list[dict[str, Any]]
    service_targets: list[dict[str, Any]]
    js_targets: list[dict[str, Any]]
    excluded_assets: list[dict[str, Any]]


WEB_ALLOWED_OWNERSHIP = {"first_party_or_unknown", "cdn_edge_or_first_party_frontend"}
NETWORK_ALLOWED_OWNERSHIP = {"first_party_or_unknown"}


def _priority(asset: dict[str, Any]) -> tuple[int, str]:
    types = set(asset.get("asset_types") or [])
    value = 0
    if "admin_or_management_surface" in types:
        value += 100
    if "vpn_or_security_appliance" in types:
        value += 90
    if "api_surface" in types:
        value += 80
    if "wordpress_application" in types:
        value += 60
    if ((asset.get("http") or {}).get("priority") or "").lower() == "high":
        value += 50
    return (-value, str(asset.get("host") or ""))


def _service_module(service: dict[str, Any]) -> str:
    port = int(service.get("port") or 0)
    family = str(service.get("service_family") or "").lower()
    product = str(service.get("product") or "").lower()
    mapping = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
        465: "smtp", 587: "smtp", 993: "imap", 995: "pop3", 1433: "mssql",
        1521: "oracle", 1883: "mqtt", 3306: "mysql", 5432: "postgresql",
        5671: "amqp", 5672: "amqp", 6379: "redis", 8883: "mqtt",
        11211: "memcached", 27017: "mongodb",
    }
    for needle, module in {
        "mysql": "mysql", "postgres": "postgresql", "mongo": "mongodb",
        "redis": "redis", "rabbit": "amqp", "amqp": "amqp", "mqtt": "mqtt",
        "mssql": "mssql", "sql server": "mssql", "oracle": "oracle",
        "memcached": "memcached", "ssh": "ssh", "smtp": "smtp",
        "imap": "imap", "pop3": "pop3", "ftp": "ftp",
    }.items():
        if needle in family or needle in product:
            return module
    return mapping.get(port, "banner")


def build_plan(normalization_dir: Path, *, max_web: int, max_services: int, max_js: int) -> EnrichmentPlan:
    assets = read_json(normalization_dir / "asset_inventory.json", [])
    services = read_json(normalization_dir / "service_inventory.json", [])
    endpoints = read_json(normalization_dir / "endpoint_inventory.json", [])
    if not isinstance(assets, list) or not assets:
        raise ValueError(f"No canonical assets found in {normalization_dir}")
    root = str(assets[0].get("root_domain") or "")
    asset_by_host = {str(a.get("host") or "").lower(): a for a in assets if a.get("host")}

    web_targets: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for asset in sorted(assets, key=_priority):
        host = str(asset.get("host") or "").lower()
        ownership = str((asset.get("ownership") or {}).get("classification") or "")
        policy = asset.get("testing_policy") or {}
        http = asset.get("http") or {}
        url = str(http.get("primary_url") or "")
        if not (url and http.get("live")):
            continue
        if ownership not in WEB_ALLOWED_OWNERSHIP or not policy.get("active_testing_allowed"):
            excluded.append({"host": host, "reason": "ownership_or_policy_blocks_web_enrichment", "ownership": ownership})
            continue
        web_targets.append({
            "asset_id": asset.get("asset_id"),
            "host": host,
            "url": url,
            "ownership": ownership,
            "asset_types": asset.get("asset_types") or [],
            "priority": (http.get("priority") or "Medium"),
            "high_priority": _priority(asset)[0] <= -80,
        })
    web_targets = web_targets[:max_web]
    allowed_web_hosts = {t["host"] for t in web_targets}

    service_targets: list[dict[str, Any]] = []
    for service in services if isinstance(services, list) else []:
        host = str(service.get("host") or "").lower()
        asset = asset_by_host.get(host) or {}
        ownership = str((asset.get("ownership") or {}).get("classification") or "")
        routes = ((asset.get("testing_policy") or {}).get("routes") or {})
        final_status = str(service.get("final_status") or "")
        if ownership not in NETWORK_ALLOWED_OWNERSHIP:
            continue
        if not routes.get("network_service_checks"):
            continue
        if final_status not in {"NMAP_CONFIRMED_OPEN", "HTTP_VALIDATED"}:
            continue
        try:
            port = int(service.get("port"))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        ip = None
        addresses = ((asset.get("dns") or {}).get("a") or [])
        if addresses:
            ip = addresses[0]
        service_targets.append({
            "service_id": service.get("service_id"),
            "asset_id": service.get("asset_id"),
            "host": host,
            "ip": ip,
            "port": port,
            "protocol": service.get("protocol") or "tcp",
            "service_family": service.get("service_family"),
            "existing_product": service.get("product"),
            "existing_version": service.get("version"),
            "zgrab2_module": _service_module(service),
        })
    service_targets = sorted(service_targets, key=lambda x: (x["zgrab2_module"], x["host"], x["port"]))[:max_services]

    js_targets: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for endpoint in endpoints if isinstance(endpoints, list) else []:
        host = str(endpoint.get("host") or "").lower()
        url = str(endpoint.get("url") or "")
        category = str(endpoint.get("category") or "")
        state = str(endpoint.get("state") or "")
        if host not in allowed_web_hosts or not url or url in seen_urls:
            continue
        path = urlsplit(url).path.lower()
        if category != "JavaScript/Static Bundle" and not path.endswith((".js", ".mjs")):
            continue
        if state == "SYNTACTICALLY_SUSPICIOUS" or endpoint.get("requires_http_revalidation"):
            continue
        seen_urls.add(url)
        js_targets.append({"host": host, "url": url, "endpoint_id": endpoint.get("endpoint_id")})
        if len(js_targets) >= max_js:
            break

    return EnrichmentPlan(root, web_targets, service_targets, js_targets, excluded)
