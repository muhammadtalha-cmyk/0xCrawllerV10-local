from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit


CATEGORY_MAP = {
    "wordpress": "CMS", "drupal": "CMS", "joomla": "CMS", "ghost": "CMS",
    "django": "Web Framework", "flask": "Web Framework", "laravel": "Web Framework",
    "ruby on rails": "Web Framework", "rails": "Web Framework", "express": "Web Framework",
    "next.js": "Web Framework", "nuxt.js": "Web Framework", "sveltekit": "Web Framework",
    "spring boot": "Web Framework", "asp.net": "Web Framework", "asp.net mvc": "Web Framework",
    "php": "Programming Language", "python": "Programming Language", "ruby": "Programming Language",
    "node.js": "Runtime", "java": "Runtime", "nginx": "Web Server", "apache": "Web Server",
    "apache http server": "Web Server", "microsoft iis": "Web Server", "openresty": "Web Server",
    "mysql": "Database", "postgresql": "Database", "mongodb": "Database", "redis": "Database / Cache",
    "microsoft sql server": "Database", "oracle database": "Database", "elasticsearch": "Search / Database",
    "rabbitmq": "Message Queue", "apache kafka": "Message Queue", "mqtt": "Message Queue",
    "celery": "Task Queue", "sidekiq": "Task Queue", "jquery": "JavaScript Library",
    "bootstrap": "UI Framework", "lodash": "JavaScript Library", "moment.js": "JavaScript Library",
    "react": "Web Framework", "vue.js": "Web Framework", "angularjs": "Web Framework",
    "cloudflare": "CDN / Security Edge", "azure front door": "CDN / Security Edge",
}

CANONICAL_NAMES = {
    "apache": "Apache HTTP Server", "apache httpd": "Apache HTTP Server", "microsoft-iis": "Microsoft IIS",
    "rails": "Ruby on Rails", "jquery": "jQuery", "vue": "Vue.js", "moment": "Moment.js",
    "wordpress block editor": "WordPress Block Editor", "mysql": "MySQL", "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL", "mongo": "MongoDB", "mssql": "Microsoft SQL Server",
    "sql server": "Microsoft SQL Server", "oracle": "Oracle Database", "rabbitmq": "RabbitMQ",
    "kafka": "Apache Kafka", "redis": "Redis", "elasticsearch": "Elasticsearch",
}

SOURCE_CONFIDENCE = {
    "custom_http_evidence": 0.78,
    "whatweb": 0.82,
    "retirejs": 0.93,
    "zgrab2": 0.90,
    "nmap": 0.86,
    "httpx_wappalyzer": 0.74,
    "wappalyzer_next": 0.90,
}


def canonical_name(name: str) -> str:
    text = re.sub(r"\s+", " ", str(name or "").strip())
    return CANONICAL_NAMES.get(text.lower(), text)


def category_for(name: str, fallback: str | None = None) -> str:
    return CATEGORY_MAP.get(canonical_name(name).lower(), fallback or "Technology")



def scope_for_category(category: str, *, default: str = "web_application") -> str:
    lower = str(category or "").lower()
    if any(token in lower for token in ("database", "queue", "cache", "search")):
        return "application_reference_not_service_confirmation"
    return default

def parse_existing_technology(value: str) -> tuple[str, str | None]:
    text = str(value or "").strip()
    if not text:
        return "", None
    # HTTPX/Wappalyzer normally emits Product:Version.
    if ":" in text:
        name, version = text.rsplit(":", 1)
        if re.fullmatch(r"[0-9][0-9A-Za-z._-]*", version.strip()):
            return canonical_name(name), version.strip()
    return canonical_name(text), None


def confidence_label(score: float) -> str:
    if score >= 0.90:
        return "high"
    if score >= 0.72:
        return "medium"
    return "low"


def _version_status(versions: list[str]) -> str:
    if not versions:
        return "NOT_EXPOSED"
    if len(versions) > 1:
        return "CONFLICTING"
    version = versions[0]
    if any(token in version for token in (">", "<", "*", "x", "X")):
        return "RANGE_INFERRED"
    return "EXACT_OBSERVED"


def _add_observation(store: dict[tuple[str, str], list[dict[str, Any]]], host: str, item: dict[str, Any]) -> None:
    name = canonical_name(item.get("name") or "")
    if not host or not name:
        return
    item = dict(item)
    item["name"] = name
    item["category"] = category_for(name, item.get("category"))
    item["host"] = host
    item["confidence_score"] = float(item.get("confidence_score") or SOURCE_CONFIDENCE.get(str(item.get("source")), 0.60))
    store[(host, name.lower())].append(item)


def reconcile_technology(
    assets: list[dict[str, Any]],
    services: list[dict[str, Any]],
    http_lane: dict[str, Any],
    whatweb_lane: dict[str, Any],
    retire_lane: dict[str, Any],
    zgrab_lane: dict[str, Any],
    wappalyzer_next_lane: dict[str, Any] | None = None,
) -> dict[str, Any]:
    observations: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    asset_by_host = {str(asset.get("host") or "").lower(): asset for asset in assets}

    for asset in assets:
        host = str(asset.get("host") or "").lower()
        for value in asset.get("technologies") or []:
            name, version = parse_existing_technology(str(value))
            if name:
                category = category_for(name)
                _add_observation(observations, host, {
                    "name": name, "version": version, "source": "httpx_wappalyzer",
                    "category": category, "scope": scope_for_category(category),
                    "confidence_score": 0.82 if version else 0.74,
                    "evidence_type": "wappalyzer_dataset", "value": str(value),
                })

    for record in http_lane.get("records") or []:
        host = str(record.get("host") or "").lower()
        for item in record.get("technologies") or []:
            _add_observation(observations, host, item)

    for record in whatweb_lane.get("records") or []:
        host = urlsplit(str(record.get("target") or "")).hostname or ""
        for item in record.get("technologies") or []:
            versions = item.get("versions") or [None]
            for version in versions:
                category = category_for(str(item.get("name") or ""))
                _add_observation(observations, host.lower(), {
                    "name": item.get("name"), "version": version, "source": "whatweb",
                    "category": category, "scope": scope_for_category(category),
                    "confidence_score": item.get("confidence_score"), "evidence_type": "whatweb_plugin",
                    "value": "; ".join(item.get("strings") or [])[:500],
                })

    for record in (wappalyzer_next_lane or {}).get("records") or []:
        host = str(record.get("host") or (urlsplit(str(record.get("target") or "")).hostname or "")).lower()
        for item in record.get("technologies") or []:
            _add_observation(observations, host, {
                "name": item.get("name"),
                "version": item.get("version"),
                "source": "wappalyzer_next",
                "category": item.get("category") or category_for(str(item.get("name") or "")),
                "scope": item.get("scope") or "web_application",
                "confidence_score": item.get("confidence_score") or 0.90,
                "evidence_type": item.get("evidence_type") or "wappalyzer_next_browser_extension",
                "value": item.get("value") or f"categories={item.get('categories')}; groups={item.get('groups')}",
                "scan_type": record.get("scan_type"),
            })

    for item in retire_lane.get("records") or []:
        host = str(item.get("host") or "").lower()
        _add_observation(observations, host, {
            "name": item.get("name"), "version": item.get("version"), "source": "retirejs",
            "category": "JavaScript Library", "scope": "client_side_component",
            "confidence_score": item.get("confidence_score") or 0.93,
            "evidence_type": "javascript_component_scan", "value": item.get("url") or item.get("source_file") or "",
            "vulnerabilities": item.get("vulnerabilities") or [],
        })

    service_by_id = {str(service.get("service_id") or ""): service for service in services}
    for service in services:
        host = str(service.get("host") or "").lower()
        product = service.get("product")
        version = service.get("version")
        if product:
            _add_observation(observations, host, {
                "name": product, "version": version, "source": "nmap", "scope": "network_service",
                "category": category_for(str(product), "Network Service"), "confidence_score": 0.86,
                "evidence_type": "nmap_service_detection", "value": f"{service.get('port')}/{service.get('protocol')}",
                "service_id": service.get("service_id"),
            })

    service_fingerprints: list[dict[str, Any]] = []
    for record in zgrab_lane.get("records") or []:
        service = service_by_id.get(str(record.get("service_id") or "")) or {}
        module = str(record.get("module") or "")
        values = record.get("version_product_fields") or []
        product = None
        version = None
        for field in values:
            lower_field = str(field.get("field") or "").lower()
            value = str(field.get("value") or "")
            if "version" in lower_field and not version:
                version = value
            if any(key in lower_field for key in ("product", "implementation", "software", "server")) and not product:
                product = value
        default_names = {
            "mysql": "MySQL", "postgresql": "PostgreSQL", "mongodb": "MongoDB", "redis": "Redis",
            "amqp": "AMQP / RabbitMQ", "mqtt": "MQTT", "mssql": "Microsoft SQL Server",
            "oracle": "Oracle Database", "memcached": "Memcached", "ssh": "SSH", "smtp": "SMTP",
            "imap": "IMAP", "pop3": "POP3", "ftp": "FTP", "telnet": "Telnet",
        }
        name = product or default_names.get(module)
        host = str(record.get("host") or "").lower()
        if name and record.get("success"):
            _add_observation(observations, host, {
                "name": name, "version": version, "source": "zgrab2", "scope": "network_service",
                "category": category_for(name, "Network Service"), "confidence_score": 0.90,
                "evidence_type": "protocol_handshake", "value": f"module={module}; fields={values[:8]}",
                "service_id": record.get("service_id"),
            })
        service_fingerprints.append({
            "service_id": record.get("service_id"), "asset_id": record.get("asset_id"), "host": host,
            "port": record.get("port"), "protocol": record.get("protocol"), "module": module,
            "status": record.get("status"), "success": record.get("success"),
            "product": product or service.get("product") or default_names.get(module),
            "version": version or service.get("version"), "version_product_fields": values,
            "sources": [source for source in ["zgrab2" if record.get("success") else None, "nmap" if service else None] if source],
        })

    technology_inventory: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for (host, _), items in sorted(observations.items()):
        name = items[0]["name"]
        versions = sorted({str(item.get("version")).strip() for item in items if item.get("version")})
        score = max(float(item.get("confidence_score") or 0) for item in items)
        sources = sorted({str(item.get("source")) for item in items if item.get("source")})
        scopes = sorted({str(item.get("scope") or "unknown") for item in items})
        status = _version_status(versions)
        selected_version = versions[0] if len(versions) == 1 else None
        tech_id = f"technology:{host}:{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}"
        record = {
            "technology_id": tech_id,
            "asset_id": (asset_by_host.get(host) or {}).get("asset_id") or f"host:{host}",
            "host": host,
            "name": name,
            "category": category_for(name, items[0].get("category")),
            "version": selected_version,
            "version_status": status,
            "alternative_versions": versions if len(versions) > 1 else [],
            "confidence": confidence_label(score),
            "confidence_score": round(score, 3),
            "sources": sources,
            "scopes": scopes,
            "evidence_count": len(items),
            "service_confirmed": "network_service" in scopes,
            "application_reference_only": all(scope == "application_reference_not_service_confirmation" for scope in scopes),
        }
        technology_inventory.append(record)
        for index, item in enumerate(items, 1):
            evidence_rows.append({"technology_id": tech_id, "evidence_index": index, **item})
        if status == "CONFLICTING":
            conflicts.append({
                "conflict_id": f"TECH-CONFLICT-{len(conflicts)+1:04d}",
                "host": host, "technology": name, "versions": versions, "sources": sources,
                "reason": "multiple_distinct_versions_observed",
            })

    tech_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in technology_inventory:
        tech_by_host[record["host"]].append(record)
    enriched_assets: list[dict[str, Any]] = []
    for asset in assets:
        enriched = dict(asset)
        host = str(asset.get("host") or "").lower()
        host_tech = sorted(tech_by_host.get(host, []), key=lambda x: (x["category"], x["name"]))
        enriched["schema_version"] = "9.2.0"
        enriched["technology_enrichment"] = {
            "technologies": host_tech,
            "exact_version_count": sum(t["version_status"] == "EXACT_OBSERVED" for t in host_tech),
            "unversioned_count": sum(t["version_status"] == "NOT_EXPOSED" for t in host_tech),
            "conflicting_count": sum(t["version_status"] == "CONFLICTING" for t in host_tech),
            "database_or_queue_evidence": [t for t in host_tech if any(token in t["category"].lower() for token in ("database", "queue", "cache", "search"))],
        }
        enriched_assets.append(enriched)

    fp_by_id = {str(item.get("service_id") or ""): item for item in service_fingerprints if item.get("service_id")}
    enriched_services: list[dict[str, Any]] = []
    for service in services:
        enriched = dict(service)
        enriched["schema_version"] = "9.2.0"
        enriched["technology_fingerprint"] = fp_by_id.get(str(service.get("service_id") or ""))
        enriched_services.append(enriched)

    return {
        "technology_inventory": technology_inventory,
        "technology_evidence": evidence_rows,
        "technology_conflicts": conflicts,
        "service_fingerprints": service_fingerprints,
        "asset_inventory_enriched": enriched_assets,
        "service_inventory_enriched": enriched_services,
    }
