"""Controlled active port enumeration and service validation.

The stage is opt-in and requires the pipeline's existing ``--authorized`` flag.
Naabu performs bounded TCP CONNECT enumeration. Optional Nmap validation scans
only ports that Naabu already reported open; NSE scripts, OS detection, UDP, and
full-port scanning are not enabled implicitly.
"""

from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .config import NMAP_IMAGE, THIRD_PARTY_PROVIDERS
from .io_utils import read_lines, write_jsonl
from .parsers import classify_cname_ownership
from .validation import is_valid_hostname, normalize_hostname

NMAP_DOCKERFILE = """FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT [\"nmap\"]
"""


def prepare_nmap_build_context(run_dir: Path) -> Path:
    context = run_dir / "support" / "nmap_image"
    context.mkdir(parents=True, exist_ok=True)
    (context / "Dockerfile").write_text(NMAP_DOCKERFILE, encoding="utf-8")
    return context


def _third_party_from_cnames(cnames: Iterable[str]) -> str | None:
    for cname in cnames:
        normalized = normalize_hostname(cname)
        for suffix, provider in THIRD_PARTY_PROVIDERS.items():
            if normalized == suffix or normalized.endswith("." + suffix):
                return provider
    return None


def select_port_scan_targets(
    validated_dns: dict[str, dict[str, Any]],
    classified_assets: list[dict[str, Any]],
    *,
    root_target: str,
    limit: int,
    include_cdn: bool = False,
    include_third_party: bool = False,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Select bounded active-scan targets with DNS ownership taking precedence.

    A target-owned DNS label can delegate to a third-party service. Therefore,
    CNAME ownership is evaluated before HTTP classification. A missing HTTPX
    record must never downgrade explicit third-party DNS evidence to
    ``first_party_or_unknown``.
    """
    root = normalize_hostname(root_target)
    assets_by_host: dict[str, dict[str, Any]] = {}
    for asset in classified_assets:
        host = normalize_hostname(asset.get("host") or "")
        if host:
            assets_by_host.setdefault(host, asset)

    candidates = sorted(set(validated_dns) | set(assets_by_host) | {root})
    manifest: list[dict[str, Any]] = []
    eligible: list[tuple[int, str]] = []

    edge_waf_providers = {
        "cloudflare", "akamai", "akamai kona site defender", "aws waf",
        "imperva", "sucuri", "microsoft azure front door", "azure front door",
        "fastly", "f5 big-ip", "fortinet fortiweb",
    }

    for host in candidates:
        if not host or not is_valid_hostname(host):
            continue
        dns_record = validated_dns.get(host, {})
        raw_cnames = dns_record.get("cname") or []
        cnames = [raw_cnames] if isinstance(raw_cnames, str) else list(raw_cnames)
        cnames = [normalize_hostname(value) for value in cnames if value]
        asset = assets_by_host.get(host, {})

        dns_ownership, dns_provider = classify_cname_ownership(cnames)
        dns_provider = dns_provider or _third_party_from_cnames(cnames)
        asset_ownership = str(asset.get("ownership") or "first_party_or_unknown")
        asset_provider = asset.get("application_provider") or asset.get("provider")

        # Strict ownership precedence: DNS delegation > HTTP classification.
        if dns_ownership == "third_party_saas" or dns_provider:
            ownership = "third_party_saas"
            application_provider = dns_provider or asset_provider
            ownership_source = "dns_cname"
        elif asset_ownership == "third_party_saas" or asset_provider:
            ownership = "third_party_saas"
            application_provider = asset_provider
            ownership_source = "http_classification"
        elif asset_ownership == "cdn_edge_or_first_party_frontend":
            ownership = asset_ownership
            application_provider = None
            ownership_source = "http_edge_classification"
        else:
            ownership = "first_party_or_unknown"
            application_provider = None
            ownership_source = "in_scope_dns_or_http"

        cdn = asset.get("cdn_detection") or {}
        waf = asset.get("waf_detection") or {}
        cdn_detected = bool(cdn.get("detected")) or ownership == "cdn_edge_or_first_party_frontend"
        waf_provider = str(waf.get("provider") or "").strip()
        waf_provider_tokens = {part.strip().lower() for part in waf_provider.split("/") if part.strip()}
        waf_edge_detected = bool(waf.get("detected")) and bool(waf_provider_tokens & edge_waf_providers)
        edge_detected = cdn_detected or waf_edge_detected
        third_party = ownership == "third_party_saas"

        has_dns_address = bool(dns_record.get("a") or dns_record.get("aaaa"))
        has_http_evidence = bool(asset)
        in_scope_first_party_candidate = (
            host == root
            or host.endswith("." + root)
        ) and (has_dns_address or has_http_evidence) and not cnames

        selected = True
        reason = "eligible_first_party_candidate"
        if third_party and not include_third_party:
            selected = False
            reason = "excluded_third_party_dns_or_saas"
        elif edge_detected and not include_cdn:
            selected = False
            reason = "excluded_cdn_or_security_edge"
        elif not in_scope_first_party_candidate and ownership == "first_party_or_unknown":
            selected = False
            reason = "excluded_unresolved_ownership"

        try:
            status = int(asset.get("status_code") or 0)
        except (TypeError, ValueError):
            status = 0
        priority = str(asset.get("priority") or "Medium")
        rank = 0 if priority == "High" else (1 if status else 2)
        if selected:
            eligible.append((rank, host))

        manifest.append({
            "host": host,
            "selected": selected,
            "reason": reason,
            "ownership": ownership,
            "ownership_source": ownership_source,
            "application_provider": application_provider,
            "network_provider": asset.get("network_provider") or cdn.get("provider"),
            "cdn_detected": cdn_detected,
            "cdn_provider": cdn.get("provider"),
            "waf_detected": bool(waf.get("detected")),
            "waf_provider": waf.get("provider"),
            "waf_attribution": waf.get("attribution"),
            "status_code": status or None,
            "priority": priority,
            "a": dns_record.get("a") or [],
            "aaaa": dns_record.get("aaaa") or [],
            "cname": cnames,
        })

    selected_hosts = [host for _, host in sorted(eligible)[: max(0, int(limit))]]
    selected_set = set(selected_hosts)
    for item in manifest:
        if item["selected"] and item["host"] not in selected_set:
            item["selected"] = False
            item["reason"] = "excluded_by_target_limit"
    return selected_hosts, manifest


def write_port_target_manifest_csv(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "host", "selected", "reason", "ownership", "ownership_source", "application_provider",
        "network_provider", "cdn_detected", "cdn_provider", "waf_detected",
        "waf_provider", "waf_attribution", "status_code", "priority", "a", "aaaa", "cname",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in records:
            row = dict(item)
            for key in ("a", "aaaa", "cname"):
                row[key] = ",".join(str(value) for value in (row.get(key) or []))
            writer.writerow({key: row.get(key, "") for key in fields})


def parse_naabu_jsonl(path: Path, *, rejected_path: Path | None = None) -> list[dict[str, Any]]:
    """Parse Naabu JSONL into normalized candidate records.

    Naabu can occasionally emit a placeholder record with port ``0`` when a
    target produced no valid port result. Those records are evidence of a
    parser/tool edge case, not open ports, and must never reach Nmap.
    """
    records: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for line_number, line in enumerate(read_lines(path), start=1):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            rejected.append({
                "line_number": line_number,
                "reason": "invalid_json",
                "raw_line": line[:1000],
            })
            continue
        if not isinstance(obj, dict):
            rejected.append({
                "line_number": line_number,
                "reason": "record_not_object",
                "raw_record": obj,
            })
            continue
        raw_host = str(obj.get("host") or obj.get("input") or obj.get("ip") or "").strip()
        host = normalize_hostname(raw_host) if not re.fullmatch(r"[0-9a-fA-F:.]+", raw_host) else raw_host
        ip = str(obj.get("ip") or "").strip()
        try:
            port = int(obj.get("port"))
        except (TypeError, ValueError):
            rejected.append({
                "line_number": line_number,
                "reason": "invalid_port_type",
                "host": host or raw_host,
                "raw_record": obj,
            })
            continue
        if not 1 <= port <= 65535:
            rejected.append({
                "line_number": line_number,
                "reason": "invalid_port_range",
                "host": host or raw_host,
                "port": port,
                "raw_record": obj,
            })
            continue
        if not host:
            rejected.append({
                "line_number": line_number,
                "reason": "missing_host",
                "port": port,
                "raw_record": obj,
            })
            continue
        protocol = str(obj.get("protocol") or "tcp").lower().strip() or "tcp"
        if protocol != "tcp":
            rejected.append({
                "line_number": line_number,
                "reason": "unsupported_protocol",
                "host": host,
                "port": port,
                "protocol": protocol,
                "raw_record": obj,
            })
            continue
        key = (host, ip, port, protocol)
        if key in seen:
            continue
        seen.add(key)
        records.append({
            "host": host,
            "ip": ip or None,
            "port": port,
            "protocol": protocol,
            "tls": bool(obj.get("tls")),
            "service": obj.get("service") or obj.get("service_name"),
            "source": "naabu_active_connect_candidate",
            "candidate_status": "NAABU_CANDIDATE",
        })
    if rejected_path is not None:
        write_jsonl(rejected_path, rejected)
    return sorted(records, key=lambda item: (str(item["host"]), int(item["port"]), str(item["protocol"])))


def write_naabu_csv(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["host", "ip", "port", "protocol", "tls", "service", "source", "candidate_status"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in records:
            writer.writerow({key: item.get(key, "") for key in fields})


def group_open_ports(records: Iterable[dict[str, Any]]) -> dict[str, list[int]]:
    """Group valid Naabu candidate ports by host.

    The historical function name is retained for compatibility. The returned
    values are candidates until independently confirmed by Nmap.
    """
    grouped: dict[str, set[int]] = defaultdict(set)
    for item in records:
        host = str(item.get("host") or "").strip()
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if host and 1 <= port <= 65535:
            grouped[host].add(port)
    return {host: sorted(ports) for host, ports in sorted(grouped.items())}


def safe_output_stem(host: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", host).strip(".-")[:120] or "target"


def parse_nmap_xml(path: Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    records: list[dict[str, Any]] = []
    for host_node in root.findall("host"):
        address_node = host_node.find("address")
        address = address_node.get("addr") if address_node is not None else None
        hostname_nodes = host_node.findall("hostnames/hostname")
        hostname = next((node.get("name") for node in hostname_nodes if node.get("name")), None)
        host_status_node = host_node.find("status")
        host_status = host_status_node.get("state") if host_status_node is not None else None
        for port_node in host_node.findall("ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            try:
                port = int(port_node.get("portid") or 0)
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            record = {
                "target": hostname or address,
                "hostname": hostname,
                "ip": address,
                "host_status": host_status,
                "port": port,
                "protocol": port_node.get("protocol") or "tcp",
                "state": state_node.get("state") if state_node is not None else None,
                "reason": state_node.get("reason") if state_node is not None else None,
                "service": service_node.get("name") if service_node is not None else None,
                "product": service_node.get("product") if service_node is not None else None,
                "version": service_node.get("version") if service_node is not None else None,
                "extrainfo": service_node.get("extrainfo") if service_node is not None else None,
                "tunnel": service_node.get("tunnel") if service_node is not None else None,
                "method": service_node.get("method") if service_node is not None else None,
                "confidence": service_node.get("conf") if service_node is not None else None,
                "source_file": path.name,
                "source": "nmap_service_validation",
            }
            records.append(record)
    return records


def parse_nmap_directory(directory: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if directory.exists():
        for path in sorted(directory.glob("*.xml")):
            records.extend(parse_nmap_xml(path))
    return sorted(records, key=lambda item: (str(item.get("target") or ""), int(item.get("port") or 0)))


def write_nmap_csv(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "target", "hostname", "ip", "host_status", "port", "protocol", "state", "reason",
        "service", "product", "version", "extrainfo", "tunnel", "method",
        "confidence", "source_file", "source",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in records:
            writer.writerow({key: item.get(key, "") for key in fields})


def reconcile_port_candidates(
    *,
    naabu_records: list[dict[str, Any]],
    nmap_records: list[dict[str, Any]],
    nmap_results: Iterable[Any],
    nmap_requested: bool,
) -> list[dict[str, Any]]:
    """Reconcile Naabu candidates with bounded Nmap validation evidence."""
    tasks_by_host: dict[str, Any] = {}
    for result in nmap_results:
        metadata = getattr(result, "metadata", {}) or {}
        host = normalize_hostname(metadata.get("target") or "")
        if host:
            tasks_by_host[host] = result

    nmap_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for record in nmap_records:
        host = normalize_hostname(record.get("requested_target") or record.get("target") or record.get("hostname") or "")
        try:
            port = int(record.get("port"))
        except (TypeError, ValueError):
            continue
        if host and 1 <= port <= 65535:
            nmap_by_key[(host, port)] = record

    reconciled: list[dict[str, Any]] = []
    for candidate in naabu_records:
        host = normalize_hostname(candidate.get("host") or "")
        port = int(candidate.get("port") or 0)
        row = dict(candidate)
        row.update({
            "nmap_requested": bool(nmap_requested),
            "nmap_state": None,
            "nmap_reason": None,
            "nmap_service": None,
            "nmap_product": None,
            "nmap_version": None,
        })
        if not nmap_requested:
            final_status = "NAABU_CANDIDATE_UNVALIDATED"
        else:
            task = tasks_by_host.get(host)
            nmap_record = nmap_by_key.get((host, port))
            if task is None:
                final_status = "NMAP_NOT_RUN"
            elif not bool(getattr(task, "ok", False)):
                final_status = "NMAP_FAILED"
            elif nmap_record is None:
                final_status = "NMAP_NOT_CONFIRMED"
                row["nmap_state"] = "not_reported"
            else:
                state = str(nmap_record.get("state") or "unknown").lower()
                row.update({
                    "nmap_state": state,
                    "nmap_reason": nmap_record.get("reason"),
                    "nmap_service": nmap_record.get("service"),
                    "nmap_product": nmap_record.get("product"),
                    "nmap_version": nmap_record.get("version"),
                })
                final_status = "NMAP_CONFIRMED_OPEN" if state == "open" else "NMAP_NOT_CONFIRMED"
        row["final_status"] = final_status
        reconciled.append(row)
    return sorted(reconciled, key=lambda item: (str(item.get("host") or ""), int(item.get("port") or 0)))


def write_port_reconciliation_csv(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "host", "ip", "port", "protocol", "candidate_status", "final_status",
        "nmap_requested", "nmap_state", "nmap_reason", "nmap_service",
        "nmap_product", "nmap_version", "source",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in records:
            writer.writerow({key: item.get(key, "") for key in fields})


def summarize_port_scan(
    *,
    requested: bool,
    targets: list[str],
    target_manifest: list[dict[str, Any]],
    naabu_records: list[dict[str, Any]],
    naabu_rejected_records: list[dict[str, Any]],
    naabu_ok: bool | None,
    nmap_requested: bool,
    nmap_records: list[dict[str, Any]],
    nmap_tasks: int,
    nmap_completed: int,
    reconciliation: list[dict[str, Any]],
) -> dict[str, Any]:
    grouped = group_open_ports(naabu_records)
    status_counts: dict[str, int] = defaultdict(int)
    for item in reconciliation:
        status_counts[str(item.get("final_status") or "UNKNOWN")] += 1
    confirmed = [item for item in reconciliation if item.get("final_status") == "NMAP_CONFIRMED_OPEN"]
    confirmed_by_host = group_open_ports(confirmed)
    return {
        "requested": requested,
        "method": "Naabu TCP CONNECT candidate enumeration; optional Nmap TCP connect recheck and light service/version validation on valid Naabu candidates",
        "safety_policy": {
            "cdn_excluded_by_default": True,
            "third_party_excluded_by_default": True,
            "invalid_ports_rejected": True,
            "nmap_scripts_enabled": False,
            "os_detection_enabled": False,
            "udp_enabled": False,
        },
        "targets": {
            "candidates": len(target_manifest),
            "selected": len(targets),
            "excluded": sum(1 for item in target_manifest if not item.get("selected")),
            "selected_hosts": targets,
        },
        "naabu": {
            "tool_ok": naabu_ok,
            "records": len(naabu_records),
            "candidate_records": len(naabu_records),
            "hosts_with_candidates": len(grouped),
            "candidate_ports_total": sum(len(ports) for ports in grouped.values()),
            "ports_by_host": grouped,
            "rejected_records": len(naabu_rejected_records),
            # Backward-compatible aliases; these are candidates, not final confirmation.
            "hosts_with_open_ports": len(grouped),
            "open_ports_total": sum(len(ports) for ports in grouped.values()),
        },
        "nmap": {
            "requested": nmap_requested,
            "tasks": nmap_tasks,
            "completed": nmap_completed,
            "records": len(nmap_records),
            "confirmed_open_records": len(confirmed),
            "confirmed_ports_by_host": confirmed_by_host,
        },
        "reconciliation": {
            "records": len(reconciliation),
            "status_counts": dict(sorted(status_counts.items())),
            "confirmed_open": len(confirmed),
            "not_confirmed": status_counts.get("NMAP_NOT_CONFIRMED", 0),
            "nmap_failed": status_counts.get("NMAP_FAILED", 0),
            "nmap_not_run": status_counts.get("NMAP_NOT_RUN", 0),
            "unvalidated": status_counts.get("NAABU_CANDIDATE_UNVALIDATED", 0),
            "candidate_results": reconciliation,
        },
    }
