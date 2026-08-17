from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from .endpoint_rules import normalize_endpoint
from .identity import asset_id, in_scope, is_ip, is_valid_host, normalize_host, normalize_url, service_id
from .io_utils import read_json, read_jsonl, write_csv, write_json
from .policy import determine_ownership, route_testing

SCHEMA_VERSION = "9.0.0"


@dataclass
class NormalizationResult:
    output_dir: Path
    summary: dict[str, Any]
    assets: list[dict[str, Any]]
    services: list[dict[str, Any]]
    endpoints: list[dict[str, Any]]
    conflicts: list[dict[str, Any]]
    revalidation_queue: list[dict[str, Any]]
    eligibility: list[dict[str, Any]]
    relationships: list[dict[str, Any]]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _unique_strings(values: list[Any]) -> list[str]:
    return sorted({str(v).strip() for v in values if str(v).strip()})


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _latest_timestamp(values: list[Any]) -> str | None:
    parsed = [dt for dt in (_parse_timestamp(v) for v in values) if dt is not None]
    if not parsed:
        return None
    return max(parsed).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_port_reconciliation(run_dir: Path) -> list[dict[str, Any]]:
    preferred_path = run_dir / "port_candidate_reconciliation.json"
    preferred = read_json(preferred_path, [])
    if preferred_path.exists() and isinstance(preferred, list):
        return preferred
    port_summary = read_json(run_dir / "port_scan_summary.json", {})
    nested = ((port_summary.get("reconciliation") or {}).get("candidate_results") if isinstance(port_summary, dict) else None)
    if isinstance(nested, list):
        return nested
    # Compatibility fallback for pre-V8.5.1 runs.
    naabu = read_json(run_dir / "naabu_ports.json", [])
    if not isinstance(naabu, list):
        naabu = read_jsonl(run_dir / "naabu_ports.jsonl")
    nmap = read_json(run_dir / "nmap_services.json", [])
    nmap = nmap if isinstance(nmap, list) else []
    by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for item in nmap:
        host = normalize_host(item.get("requested_target") or item.get("target") or item.get("hostname"))
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        by_key[(host, port)] = item
    result: list[dict[str, Any]] = []
    for item in naabu:
        host = normalize_host(item.get("host") or item.get("input"))
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if not host or not 1 <= port <= 65535:
            continue
        n = by_key.get((host, port))
        state = str((n or {}).get("state") or "").lower()
        final = "NMAP_CONFIRMED_OPEN" if state == "open" else ("NMAP_NOT_CONFIRMED" if n is not None else "NAABU_CANDIDATE_UNVALIDATED")
        result.append({
            "host": host, "ip": item.get("ip"), "port": port, "protocol": item.get("protocol") or "tcp",
            "candidate_status": "NAABU_CANDIDATE", "final_status": final,
            "nmap_state": state or None, "nmap_service": (n or {}).get("service"),
            "nmap_product": (n or {}).get("product"), "nmap_version": (n or {}).get("version"),
            "source": "compatibility_reconciliation",
        })
    return result


def _classify_asset_types(host: str, http: dict[str, Any] | None, ports: list[dict[str, Any]], endpoints: list[dict[str, Any]], ownership: dict[str, Any], historical_only: bool) -> list[str]:
    types: set[str] = set()
    lower_host = host.lower()
    title = str((http or {}).get("title") or "").lower()
    category = str((http or {}).get("category") or "").lower()
    tech = " ".join(str(v).lower() for v in ((http or {}).get("technologies") or (http or {}).get("tech") or []))
    if ownership.get("classification") == "third_party_saas":
        types.add("third_party_saas")
    if historical_only:
        types.add("historical_asset")
    if http:
        types.add("web_application")
    if "admin" in lower_host or "management" in category or "admin" in category:
        types.add("admin_or_management_surface")
    if lower_host.startswith("api.") or lower_host.startswith("api-") or any(e.get("category") == "API Endpoint" for e in endpoints):
        types.add("api_surface")
    if "vpn" in lower_host or "vpn" in title or "firewall" in title or "fw-" in title:
        types.add("vpn_or_security_appliance")
    if "wordpress" in tech:
        types.add("wordpress_application")
    if ports:
        types.add("network_service_host")
    if not http and not historical_only:
        types.add("dns_only_asset")
    if ownership.get("classification") == "cdn_edge_or_first_party_frontend":
        types.add("cdn_fronted_web")
    return sorted(types)


def _flatten_asset(asset: dict[str, Any]) -> dict[str, Any]:
    dns = asset.get("dns") or {}
    http = asset.get("http") or {}
    own = asset.get("ownership") or {}
    testing = asset.get("testing_policy") or {}
    return {
        "asset_id": asset.get("asset_id"),
        "host": asset.get("host"),
        "root_domain": asset.get("root_domain"),
        "asset_types": asset.get("asset_types"),
        "ownership": own.get("classification"),
        "ownership_confidence": own.get("confidence"),
        "application_provider": own.get("provider"),
        "dns_resolved_current": dns.get("resolved_current"),
        "ipv4": dns.get("a"),
        "ipv6": dns.get("aaaa"),
        "cname": dns.get("cname"),
        "http_live": http.get("live"),
        "primary_url": http.get("primary_url"),
        "http_status": http.get("status_code"),
        "title": http.get("title"),
        "technologies": asset.get("technologies"),
        "cdn_provider": ((asset.get("edge_security") or {}).get("cdn") or {}).get("provider"),
        "waf_provider": ((asset.get("edge_security") or {}).get("waf") or {}).get("provider"),
        "confirmed_open_ports": asset.get("confirmed_open_ports"),
        "freshness_state": (asset.get("freshness") or {}).get("state"),
        "testing_decision": testing.get("decision"),
        "active_testing_allowed": testing.get("active_testing_allowed"),
        "requires_human_approval": testing.get("requires_human_approval"),
        "conflict_count": len(asset.get("conflict_ids") or []),
    }


def normalize_run(run_dir: Path, output_dir: Path, *, overwrite: bool = False) -> NormalizationResult:
    run_dir = run_dir.resolve()
    output_dir = output_dir.resolve()
    if not run_dir.is_dir():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise FileExistsError(f"Output directory is not empty: {output_dir}. Use --overwrite.")
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = read_json(run_dir / "summary.json", {})
    root = normalize_host(summary.get("target") or run_dir.name.split("-")[0])
    if not root or not is_valid_host(root) or is_ip(root):
        raise ValueError("Could not infer a valid root domain from summary.json or run-folder name")
    created_at = summary.get("created_at") or summary.get("generated_at")

    dns_current = read_json(run_dir / "validated_dns_hosts.json", {})
    dns_current = dns_current if isinstance(dns_current, dict) else {}
    historical = read_json(run_dir / "carried_forward_unvalidated.json", {})
    historical = historical if isinstance(historical, dict) else {}
    http_records = read_json(run_dir / "http_review_classification.json", [])
    http_records = http_records if isinstance(http_records, list) else []
    http_by_host = {normalize_host(r.get("host")): r for r in http_records if normalize_host(r.get("host"))}
    raw_http = read_jsonl(run_dir / "httpx_probe.jsonl") + read_jsonl(run_dir / "httpx_root_probe.jsonl")
    raw_http_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in raw_http:
        host = normalize_host(record.get("host") or record.get("input") or record.get("url"))
        if host:
            raw_http_by_host[host].append(record)

    endpoint_doc = read_json(run_dir / "endpoint_classification.json", {})
    endpoint_raw = endpoint_doc.get("records", []) if isinstance(endpoint_doc, dict) else []
    current_http_hosts = set(http_by_host)
    endpoints = [e for r in endpoint_raw if isinstance(r, dict) and (e := normalize_endpoint(r, current_http_hosts)) is not None]
    endpoints_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for endpoint in endpoints:
        endpoints_by_host[endpoint["host"]].append(endpoint)

    port_reconciliation = _load_port_reconciliation(run_dir)
    ports_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in port_reconciliation:
        host = normalize_host(record.get("host"))
        try:
            port = int(record.get("port"))
        except (TypeError, ValueError):
            continue
        if host and 1 <= port <= 65535:
            normalized = dict(record)
            normalized["host"] = host
            normalized["port"] = port
            normalized["protocol"] = str(record.get("protocol") or "tcp").lower()
            ports_by_host[host].append(normalized)

    topology = read_json(run_dir / "recon_topology.json", {})
    nodes = topology.get("nodes", {}) if isinstance(topology, dict) else {}
    edges = topology.get("edges", []) if isinstance(topology, dict) else []
    nodes = nodes if isinstance(nodes, dict) else {}
    edges = edges if isinstance(edges, list) else []

    candidate_manifest = read_jsonl(run_dir / "candidate_manifest.jsonl")
    discovery_sources: dict[str, set[str]] = defaultdict(set)
    for record in candidate_manifest:
        host = normalize_host(record.get("candidate"))
        if host:
            discovery_sources[host].add(str(record.get("source") or "candidate_manifest"))
    for host, node in nodes.items():
        h = normalize_host(host)
        for source in _as_list((node or {}).get("sources")):
            discovery_sources[h].add(str(source))

    shodan_assets = read_json(run_dir / "shodan_assets.json", {})
    shodan_assets = shodan_assets if isinstance(shodan_assets, dict) else {}
    shodan_services = read_jsonl(run_dir / "shodan_services.jsonl")
    shodan_services_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for service in shodan_services:
        ip = str(service.get("ip") or "").strip()
        if ip:
            shodan_services_by_ip[ip].append(service)

    screenshot_status = read_json(run_dir / "screenshot_status.json", {})
    screenshot_records = read_jsonl(run_dir / "httpx_screenshots.jsonl")
    screenshot_hosts = {normalize_host(r.get("host") or r.get("input") or r.get("url")) for r in screenshot_records}
    screenshot_hosts.discard("")

    authoritative_hosts: set[str] = {root}
    authoritative_hosts.update(normalize_host(h) for h in dns_current)
    authoritative_hosts.update(normalize_host(h) for h in historical)
    authoritative_hosts.update(http_by_host)
    authoritative_hosts.update(ports_by_host)
    authoritative_hosts.update(endpoints_by_host)

    def topology_edge_supports_child(edge: dict[str, Any], child: str) -> bool:
        if child in authoritative_hosts:
            return True
        evidence = str(edge.get("evidence") or "").strip()
        if not evidence:
            return False
        parsed_hosts: set[str] = set()
        try:
            outer = urlsplit(evidence)
            if outer.hostname:
                parsed_hosts.add(normalize_host(outer.hostname))
            for _, raw_value in parse_qsl(outer.query, keep_blank_values=True):
                decoded = unquote(raw_value)
                if decoded.lower().startswith(("http://", "https://")):
                    nested = urlsplit(decoded)
                    if nested.hostname:
                        parsed_hosts.add(normalize_host(nested.hostname))
        except ValueError:
            return False
        return child in parsed_hosts

    host_set: set[str] = set(authoritative_hosts)
    for edge in edges:
        parent = normalize_host(edge.get("parent"))
        child = normalize_host(edge.get("child"))
        if parent in authoritative_hosts:
            host_set.add(parent)
        if child and topology_edge_supports_child(edge, child):
            host_set.add(child)
    host_set = {h for h in host_set if h and is_valid_host(h) and in_scope(h, root)}

    conflicts: list[dict[str, Any]] = []
    conflict_counter = 0
    revalidation_queue: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    eligibility: list[dict[str, Any]] = []

    def add_conflict(host: str, kind: str, severity: str, description: str, evidence: dict[str, Any]) -> str:
        nonlocal conflict_counter
        conflict_counter += 1
        cid = f"C-{conflict_counter:04d}"
        conflicts.append({"conflict_id": cid, "asset_id": asset_id(host), "host": host, "type": kind, "severity": severity, "description": description, "evidence": evidence})
        return cid

    for host in sorted(host_set):
        dns = dns_current.get(host) or {}
        old_dns = historical.get(host) or {}
        http = http_by_host.get(host)
        raw_http_host = raw_http_by_host.get(host, [])
        host_ports = sorted(ports_by_host.get(host, []), key=lambda r: (r.get("protocol", "tcp"), r.get("port", 0)))
        host_endpoints = endpoints_by_host.get(host, [])
        current_dns_validated = bool(dns and (dns.get("a") or dns.get("aaaa") or dns.get("cname")))
        root_current = host == root and bool(summary.get("canonical_target_reachable"))
        has_current_http = bool(http) or bool(raw_http_host) or root_current
        historical_only = bool(old_dns) and not current_dns_validated and not has_current_http

        ownership = determine_ownership(host=host, root=root, dns=dns or old_dns, http=http, historical_only=historical_only)
        conflict_ids: list[str] = []
        if historical_only:
            conflict_ids.append(add_conflict(host, "historical_not_currently_validated", "medium", "The host was observed in a previous run but has no current DNS or HTTP validation.", {"historical_record": old_dns.get("previous_run_dir"), "needs_revalidation": True}))
            revalidation_queue.append({"queue_id": f"R-{len(revalidation_queue)+1:04d}", "asset_id": asset_id(host), "host": host, "reason": "historical_not_currently_validated", "priority": "High", "recommended_action": "Repeat DNS validation, then HTTP probing only if DNS resolves."})

        edge = (http or {}).get("cdn_detection") or {}
        waf = (http or {}).get("waf_detection") or {}
        if waf.get("attribution") == "conflicting_or_multi_layer" or len(_as_list(waf.get("providers"))) > 1:
            conflict_ids.append(add_conflict(host, "multi_layer_edge_attribution", "low", "Multiple edge or WAF providers were observed; preserve all evidence rather than selecting one silently.", {"providers": waf.get("providers"), "provider": waf.get("provider"), "evidence": waf.get("evidence")}))

        for port_record in host_ports:
            final_status = str(port_record.get("final_status") or "")
            if final_status in {"NMAP_NOT_CONFIRMED", "NMAP_FAILED", "NMAP_NOT_RUN", "NAABU_CANDIDATE_UNVALIDATED"}:
                conflict_ids.append(add_conflict(host, "port_validation_conflict", "medium", f"Port {port_record['port']}/{port_record['protocol']} was reported as a candidate but was not independently confirmed open.", {"port_record": port_record}))
                revalidation_queue.append({"queue_id": f"R-{len(revalidation_queue)+1:04d}", "asset_id": asset_id(host), "host": host, "reason": "port_not_confirmed", "priority": "High", "recommended_action": f"Recheck {port_record['protocol']}/{port_record['port']} using bounded service validation."})

        suspicious = [e for e in host_endpoints if e.get("state") == "SYNTACTICALLY_SUSPICIOUS"]
        if suspicious:
            conflict_ids.append(add_conflict(host, "suspicious_crawler_endpoints", "low", "One or more crawler-derived URLs appear syntactically malformed or derived from JavaScript strings.", {"count": len(suspicious), "samples": suspicious[:10]}))
            revalidation_queue.append({"queue_id": f"R-{len(revalidation_queue)+1:04d}", "asset_id": asset_id(host), "host": host, "reason": "suspicious_endpoints", "priority": "Medium", "recommended_action": "HTTP-revalidate only the suspicious URLs before vulnerability routing.", "endpoint_ids": [e["endpoint_id"] for e in suspicious]})

        addresses = _unique_strings(_as_list(dns.get("a")) + _as_list(dns.get("aaaa")))
        old_addresses = _unique_strings(_as_list(old_dns.get("a")) + _as_list(old_dns.get("aaaa")))
        cnames = _unique_strings(_as_list(dns.get("cname")) if dns else _as_list(old_dns.get("cname")))
        for ip in addresses:
            relationships.append({"relationship_id": f"rel:{host}:resolves_to:{ip}", "source_asset": asset_id(host), "relationship": "resolves_to", "target_asset": f"ip:{ip}", "current": True, "evidence_source": "dnsx"})
        for cname in cnames:
            relationships.append({"relationship_id": f"rel:{host}:cname:{cname}", "source_asset": asset_id(host), "relationship": "cname_delegates_to", "target_asset": f"host:{cname}", "current": bool(dns), "evidence_source": "dnsx"})

        http_services: list[dict[str, Any]] = []
        if http:
            url = normalize_url(http.get("url"))
            if url:
                parts = urlsplit(url)
                port = parts.port or (443 if parts.scheme == "https" else 80)
                http_services.append({"url": url, "scheme": parts.scheme, "port": port, "status_code": http.get("status_code"), "status_bucket": http.get("status_bucket"), "title": http.get("title"), "content_type": http.get("content_type"), "webserver": http.get("webserver"), "response_time": http.get("response_time"), "actively_validated": True, "source": "http_review_classification"})
        elif root_current:
            canonical = summary.get("canonical_target") or {}
            url = normalize_url(canonical.get("url"))
            evidence = canonical.get("evidence") or {}
            if url:
                parts = urlsplit(url)
                http_services.append({"url": url, "scheme": parts.scheme, "port": parts.port or (443 if parts.scheme == "https" else 80), "status_code": evidence.get("status_code"), "title": evidence.get("title"), "content_type": evidence.get("content_type"), "webserver": evidence.get("webserver"), "actively_validated": True, "source": "canonical_target"})

        technologies = _unique_strings(_as_list((http or {}).get("technologies")) + _as_list((http or {}).get("tech")))
        asset_types = _classify_asset_types(host, http, host_ports, host_endpoints, ownership, historical_only)
        confirmed_port_records = [p for p in host_ports if p.get("final_status") == "NMAP_CONFIRMED_OPEN"]
        testing = route_testing(ownership=ownership, has_http=bool(http_services), current_dns=current_dns_validated or root_current, confirmed_ports=bool(confirmed_port_records), asset_types=asset_types, waf=waf)
        eligibility.append({"asset_id": asset_id(host), "host": host, **testing})

        shodan_observations: list[dict[str, Any]] = []
        for ip in addresses + old_addresses:
            aggregate = shodan_assets.get(ip)
            if isinstance(aggregate, dict):
                shodan_observations.append(aggregate)
            shodan_observations.extend(shodan_services_by_ip.get(ip, []))

        for hsvc in http_services:
            sid = service_id(host, "tcp", int(hsvc["port"]))
            services.append({"service_id": sid, "asset_id": asset_id(host), "host": host, "protocol": "tcp", "port": int(hsvc["port"]), "service_family": hsvc["scheme"], "final_status": "HTTP_VALIDATED", "current": True, "product": hsvc.get("webserver"), "version": None, "observations": [hsvc]})
        for p in host_ports:
            sid = service_id(host, p.get("protocol") or "tcp", int(p["port"]))
            services.append({"service_id": sid, "asset_id": asset_id(host), "host": host, "protocol": p.get("protocol") or "tcp", "port": int(p["port"]), "service_family": p.get("nmap_service") or p.get("service"), "final_status": p.get("final_status"), "current": p.get("final_status") == "NMAP_CONFIRMED_OPEN", "product": p.get("nmap_product"), "version": p.get("nmap_version"), "observations": [p]})

        timestamps = [dns.get("timestamp"), old_dns.get("timestamp"), created_at]
        timestamps += [r.get("timestamp") for r in raw_http_host]
        timestamps += [o.get("last_seen") for o in shodan_observations if isinstance(o, dict)]
        freshness_state = "current_validated" if (current_dns_validated or has_current_http or confirmed_port_records) else ("historical_unresolved" if historical_only else "passive_or_unresolved")

        asset = {
            "schema_version": SCHEMA_VERSION,
            "asset_id": asset_id(host),
            "host": host,
            "root_domain": root,
            "asset_types": asset_types,
            "scope": {"hostname_in_scope": in_scope(host, root), "authorized_root": root, "authorization_basis": "user_supplied_authorized_recon_run", "active_testing_allowed": testing["active_testing_allowed"], "decision": testing["decision"]},
            "ownership": ownership,
            "dns": {"resolved_current": current_dns_validated, "validation_state": dns.get("validation_state") or ("previous_run_unvalidated" if historical_only else None), "a": _unique_strings(_as_list(dns.get("a"))), "aaaa": _unique_strings(_as_list(dns.get("aaaa"))), "cname": cnames, "historical_addresses": old_addresses, "wildcard_like": bool(dns.get("wildcard_like") or old_dns.get("wildcard_like")), "timestamp": dns.get("timestamp")},
            "http": {"live": bool(http_services), "primary_url": http_services[0]["url"] if http_services else None, "status_code": http_services[0].get("status_code") if http_services else None, "title": http_services[0].get("title") if http_services else None, "category": (http or {}).get("category"), "priority": (http or {}).get("priority"), "services": http_services},
            "technologies": technologies,
            "edge_security": {"cdn": edge, "waf": waf},
            "ports": host_ports,
            "confirmed_open_ports": sorted({int(p["port"]) for p in confirmed_port_records}),
            "passive_observations": {"shodan": {"available": bool(shodan_observations), "records": shodan_observations, "evidence_type": "passive_potentially_historical"}},
            "endpoints": {"count": len(host_endpoints), "states": dict(Counter(e["state"] for e in host_endpoints)), "categories": dict(Counter(e["category"] for e in host_endpoints)), "high_priority_count": sum(1 for e in host_endpoints if e.get("priority") == "High")},
            "screenshots": {"captured": host in screenshot_hosts, "run_summary": screenshot_status if host in screenshot_hosts else None},
            "discovery": {"sources": sorted(discovery_sources.get(host) or set((nodes.get(host) or {}).get("sources") or [])), "topology_level": (nodes.get(host) or {}).get("level")},
            "freshness": {"state": freshness_state, "validated_in_current_run": freshness_state == "current_validated", "carried_forward": bool(old_dns), "requires_revalidation": historical_only or bool(suspicious), "last_observed_at": _latest_timestamp(timestamps)},
            "testing_policy": testing,
            "conflict_ids": conflict_ids,
        }
        assets.append(asset)

    # Preserve topology edges only when both endpoints are valid in-scope assets.
    valid_asset_ids = {a["asset_id"] for a in assets}
    for edge in edges:
        parent = normalize_host(edge.get("parent"))
        child = normalize_host(edge.get("child"))
        if asset_id(parent) in valid_asset_ids and asset_id(child) in valid_asset_ids:
            relationships.append({"relationship_id": "rel-topology:" + hashlib.sha1(json.dumps(edge, sort_keys=True).encode()).hexdigest()[:16], "source_asset": asset_id(parent), "relationship": "discovered", "target_asset": asset_id(child), "current": True, "evidence_source": edge.get("source"), "level": edge.get("level"), "evidence": edge.get("evidence")})

    # Merge duplicate service IDs while preserving observations and strongest status.
    status_rank = {"NMAP_CONFIRMED_OPEN": 5, "HTTP_VALIDATED": 4, "NAABU_CANDIDATE_UNVALIDATED": 3, "NMAP_NOT_CONFIRMED": 2, "NMAP_FAILED": 1, None: 0}
    merged_services: dict[str, dict[str, Any]] = {}
    for svc in services:
        existing = merged_services.get(svc["service_id"])
        if not existing:
            merged_services[svc["service_id"]] = svc
            continue
        existing["observations"].extend(svc.get("observations") or [])
        if status_rank.get(svc.get("final_status"), 0) > status_rank.get(existing.get("final_status"), 0):
            for key in ("final_status", "current", "service_family", "product", "version"):
                if svc.get(key) is not None:
                    existing[key] = svc.get(key)
    services = sorted(merged_services.values(), key=lambda s: (s["host"], s["protocol"], s["port"]))

    summary_out = {
        "schema_version": SCHEMA_VERSION,
        "engine": "0xCrawller V9 Asset Validation and Normalization",
        "source_run": str(run_dir),
        "source_program_version": summary.get("program_version"),
        "target": root,
        "normalized_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "counts": {
            "assets": len(assets),
            "current_validated_assets": sum(1 for a in assets if a["freshness"]["state"] == "current_validated"),
            "historical_unresolved_assets": sum(1 for a in assets if a["freshness"]["state"] == "historical_unresolved"),
            "third_party_assets": sum(1 for a in assets if a["ownership"]["classification"] == "third_party_saas"),
            "active_testing_allowed_assets": sum(1 for a in assets if a["testing_policy"]["active_testing_allowed"]),
            "services": len(services),
            "confirmed_open_services": sum(1 for s in services if s["final_status"] in {"NMAP_CONFIRMED_OPEN", "HTTP_VALIDATED"}),
            "endpoints": len(endpoints),
            "suspicious_endpoints": sum(1 for e in endpoints if e["state"] == "SYNTACTICALLY_SUSPICIOUS"),
            "conflicts": len(conflicts),
            "revalidation_items": len(revalidation_queue),
            "relationships": len(relationships),
        },
        "quality_gates": {
            "invalid_hosts_excluded": True,
            "invalid_ports_excluded": True,
            "passive_evidence_separated": True,
            "third_party_active_testing_blocked": True,
            "cdn_network_scanning_blocked": True,
            "scanner_eligibility_generated": True,
        },
    }

    write_json(output_dir / "asset_inventory.json", assets)
    write_csv(output_dir / "asset_inventory.csv", [_flatten_asset(a) for a in assets], ["asset_id", "host", "root_domain", "asset_types", "ownership", "ownership_confidence", "application_provider", "dns_resolved_current", "ipv4", "ipv6", "cname", "http_live", "primary_url", "http_status", "title", "technologies", "cdn_provider", "waf_provider", "confirmed_open_ports", "freshness_state", "testing_decision", "active_testing_allowed", "requires_human_approval", "conflict_count"])
    write_json(output_dir / "service_inventory.json", services)
    write_csv(output_dir / "service_inventory.csv", services, ["service_id", "asset_id", "host", "protocol", "port", "service_family", "final_status", "current", "product", "version", "observations"])
    write_json(output_dir / "endpoint_inventory.json", endpoints)
    write_csv(output_dir / "endpoint_inventory.csv", endpoints, ["endpoint_id", "url", "host", "path", "query", "category", "priority", "state", "requires_http_revalidation", "suspicious_reasons", "source"])
    write_json(output_dir / "asset_relationships.json", relationships)
    write_json(output_dir / "asset_conflicts.json", conflicts)
    write_json(output_dir / "asset_revalidation_queue.json", revalidation_queue)
    write_json(output_dir / "testing_eligibility.json", eligibility)
    write_json(output_dir / "normalization_summary.json", summary_out)
    from .reporting import render_report
    (output_dir / "asset_normalization_report.md").write_text(render_report(summary_out, assets, services, endpoints, conflicts, revalidation_queue, eligibility), encoding="utf-8")
    return NormalizationResult(output_dir, summary_out, assets, services, endpoints, conflicts, revalidation_queue, eligibility, relationships)
