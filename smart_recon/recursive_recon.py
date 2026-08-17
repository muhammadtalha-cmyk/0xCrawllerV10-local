"""Bounded recursive, evidence-aware recon expansion for Smart Recon V8.5.1.

The canonical root is level 0. Existing validated first-party web applications
are treated as level 1. Each level is crawled in parallel; newly observed
in-scope hostnames are DNS-validated, HTTP-probed, classified, and become the
next level. The implementation hard-caps descendant depth at three.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .browser import extract_browser_observations
from .classification import classify_http_asset
from .commands import (
    build_dnsx_command,
    build_httpx_file_command,
    build_httpx_screenshot_file_command,
    build_katana_command,
)
from .io_utils import read_jsonl, read_lines, write_json, write_jsonl, write_lines
from .parsers import extract_in_scope_hosts_from_url, get_answer_signature, merge_dns_records, parse_dnsx_jsonl
from .runtime import run_cmd, run_parallel
from .screenshots import find_screenshot_files, screenshot_hosts_from_files
from .shodan_passive import run_shodan_incremental_host_enrichment
from .validation import is_in_scope_host, normalize_hostname, parent_zone_for_host


def _safe_stem(value: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("._-") or "host"
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]
    return f"{clean[:70]}_{digest}"


def _status_code(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _best_assets_by_host(classified_assets: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    ranked: dict[str, tuple[tuple[int, int, int, str], dict[str, Any]]] = {}
    for asset in classified_assets:
        host = normalize_hostname(asset.get("host") or "")
        if not host:
            continue
        status = _status_code(asset.get("status_code"))
        url = str(asset.get("url") or "")
        score = (
            0 if 200 <= status < 400 else 1,
            0 if url.startswith("https://") else 1,
            0 if status else 1,
            url,
        )
        if host not in ranked or score < ranked[host][0]:
            ranked[host] = (score, asset)
    return {host: item[1] for host, item in ranked.items()}


def _eligible_asset(asset: dict[str, Any], target: str) -> bool:
    host = normalize_hostname(asset.get("host") or "")
    if not host or host == target or not is_in_scope_host(host, target):
        return False
    if str(asset.get("ownership") or "") == "third_party_saas":
        return False
    status = _status_code(asset.get("status_code"))
    if not 100 <= status < 600:
        return False
    url = str(asset.get("url") or "")
    return url.startswith(("http://", "https://"))


def _merge_http_records(existing: list[dict[str, Any]], incoming: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for record in [*existing, *list(incoming)]:
        host = normalize_hostname(record.get("host") or record.get("input") or "")
        url = str(record.get("url") or "")
        status = _status_code(record.get("status_code"))
        if not host or status <= 0:
            continue
        merged[(host, url)] = record
    return list(merged.values())


def _merge_classified(existing: list[dict[str, Any]], incoming: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for asset in [*existing, *list(incoming)]:
        host = normalize_hostname(asset.get("host") or "")
        url = str(asset.get("url") or "")
        if host:
            merged[(host, url)] = asset
    result = list(merged.values())
    result.sort(
        key=lambda item: (
            item.get("priority") != "High",
            item.get("ownership") == "third_party_saas",
            str(item.get("category") or ""),
            str(item.get("host") or ""),
        )
    )
    return result


def _wildcard_zones(hosts: Iterable[str], target: str, limit: int = 50) -> list[str]:
    zones = {target}
    for host in hosts:
        normalized = normalize_hostname(host)
        if not normalized or not is_in_scope_host(normalized, target):
            continue
        zone = parent_zone_for_host(normalized, target)
        zones.add(zone)
        if zone != target:
            zones.add(parent_zone_for_host(zone, target))
    return sorted(zones, key=lambda value: (value.count("."), value))[: max(1, limit)]


def _refresh_wildcard_signatures(
    *,
    target: str,
    new_hosts: set[str],
    existing_signatures: dict[str, str],
    run_dir: Path,
    logs_dir: Path,
    args: Any,
    level_label: str,
) -> tuple[dict[str, str], list[Any]]:
    signatures = dict(existing_signatures)
    zones = [zone for zone in _wildcard_zones(new_hosts, target, args.max_wildcard_zones) if zone not in signatures]
    if not zones:
        return signatures, []
    probe_to_zone: dict[str, str] = {}
    for zone in zones:
        for index in range(max(2, int(args.wildcard_probes))):
            digest = hashlib.sha1(f"{level_label}:{zone}:{index}".encode("utf-8")).hexdigest()[:18]
            probe_to_zone[f"x{digest}.{zone}"] = zone
    input_file = f"recursive/{level_label}/wildcard_tests.txt"
    output_file = f"recursive/{level_label}/wildcard_tests.jsonl"
    write_lines(run_dir / input_file, probe_to_zone)
    command = build_dnsx_command(
        run_dir,
        input_file=input_file,
        output_file=output_file,
        threads=min(int(args.dnsx_threads), 30),
        rate_limit=min(int(args.dnsx_rate_limit), 50),
        retries=int(args.dnsx_retries),
    )
    result = run_cmd(
        f"dnsx_recursive_wildcards_{level_label}",
        command,
        logs_dir,
        min(int(args.dnsx_chunk_timeout), 600),
    )
    records = parse_dnsx_jsonl(run_dir / output_file)
    for zone in zones:
        answers = [records[probe] for probe, probe_zone in probe_to_zone.items() if probe_zone == zone and probe in records]
        answer_signatures = [get_answer_signature(record) for record in answers]
        counts = Counter(answer_signatures)
        signature, count = counts.most_common(1)[0] if counts else ("", 0)
        if signature and count >= 2:
            signatures[zone] = signature
    return signatures, [result]


def _apply_wildcard(
    records: dict[str, dict[str, Any]],
    signatures: dict[str, str],
    target: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    accepted: dict[str, dict[str, Any]] = {}
    suspected: dict[str, dict[str, Any]] = {}
    for host, record in records.items():
        zone = parent_zone_for_host(host, target)
        wildcard_like = bool(signatures.get(zone) and signatures[zone] == get_answer_signature(record))
        record["wildcard_like"] = wildcard_like
        record["wildcard_zone"] = zone if wildcard_like else None
        if wildcard_like:
            record["validation_state"] = "wildcard_suspected_recursive"
            suspected[host] = record
        else:
            record.setdefault("validation_state", "dns_resolved" if record.get("a") or record.get("aaaa") else "cname_only")
            record["source_pipeline"] = "recursive_recon"
            accepted[host] = record
    return accepted, suspected


def _validate_and_probe(
    *,
    hosts: set[str],
    level_label: str,
    target: str,
    run_dir: Path,
    logs_dir: Path,
    args: Any,
    wildcard_signatures: dict[str, str],
) -> dict[str, Any]:
    if not hosts:
        return {
            "dns": {}, "wildcard": {}, "http_records": [], "classified": [],
            "tool_results": [], "wildcard_signatures": wildcard_signatures,
        }
    level_dir = run_dir / "recursive" / level_label
    level_dir.mkdir(parents=True, exist_ok=True)
    input_file = f"recursive/{level_label}/hosts_to_validate.txt"
    dns_output = f"recursive/{level_label}/dnsx.jsonl"
    write_lines(run_dir / input_file, hosts)
    dns_result = run_cmd(
        f"dnsx_recursive_{level_label}",
        build_dnsx_command(
            run_dir,
            input_file=input_file,
            output_file=dns_output,
            threads=min(int(args.dnsx_threads), 50),
            rate_limit=min(int(args.dnsx_rate_limit), 100),
            retries=int(args.dnsx_retries),
        ),
        logs_dir,
        min(int(args.dnsx_chunk_timeout), 1200),
    )
    raw_dns = parse_dnsx_jsonl(run_dir / dns_output)
    signatures, wildcard_results = _refresh_wildcard_signatures(
        target=target,
        new_hosts=set(raw_dns),
        existing_signatures=wildcard_signatures,
        run_dir=run_dir,
        logs_dir=logs_dir,
        args=args,
        level_label=level_label,
    )
    accepted_dns, wildcard = _apply_wildcard(raw_dns, signatures, target)
    validated_file = f"recursive/{level_label}/validated_hosts.txt"
    write_lines(run_dir / validated_file, accepted_dns)
    http_records: list[dict[str, Any]] = []
    classified: list[dict[str, Any]] = []
    http_results: list[Any] = []
    if accepted_dns:
        http_output = f"recursive/{level_label}/httpx.jsonl"
        http_result = run_cmd(
            f"httpx_recursive_{level_label}",
            build_httpx_file_command(run_dir, input_file=validated_file, output_file=http_output),
            logs_dir,
            min(int(args.timeout), 1200),
        )
        http_results.append(http_result)
        http_records = read_jsonl(run_dir / http_output)
        classified = [classify_http_asset(record) for record in http_records if _status_code(record.get("status_code")) > 0]
    write_json(run_dir / f"recursive/{level_label}/validated_hosts.json", accepted_dns)
    write_json(run_dir / f"recursive/{level_label}/wildcard_suspected.json", wildcard)
    write_json(run_dir / f"recursive/{level_label}/classified_assets.json", classified)
    return {
        "dns": accepted_dns,
        "wildcard": wildcard,
        "http_records": http_records,
        "classified": classified,
        "tool_results": [dns_result, *wildcard_results, *http_results],
        "wildcard_signatures": signatures,
    }


def _add_edge(
    edges: list[dict[str, Any]],
    *,
    parent: str,
    child: str,
    source: str,
    level: int,
    evidence: str | None = None,
) -> None:
    if not parent or not child or parent == child:
        return
    row = {"parent": parent, "child": child, "source": source, "level": level}
    if evidence:
        row["evidence"] = evidence
    key = (parent, child, source, level)
    if key not in {(item["parent"], item["child"], item["source"], item["level"]) for item in edges}:
        edges.append(row)


def _cluster_assets(
    *,
    target: str,
    validated_dns: dict[str, dict[str, Any]],
    classified_assets: list[dict[str, Any]],
    boundary_hosts: set[str],
    wildcard_hosts: set[str],
) -> dict[str, list[str]]:
    by_host = _best_assets_by_host(classified_assets)
    clusters: dict[str, list[str]] = defaultdict(list)
    all_hosts = set(validated_dns) | set(by_host) | set(boundary_hosts) | set(wildcard_hosts)
    for host in sorted(all_hosts):
        if host in boundary_hosts:
            cluster = "max_depth_boundary"
        elif host in wildcard_hosts:
            cluster = "wildcard_suspected"
        else:
            asset = by_host.get(host)
            if not asset:
                cluster = "dns_only"
            elif str(asset.get("ownership") or "") == "third_party_saas":
                cluster = "third_party_saas"
            elif bool((asset.get("cdn_detection") or {}).get("detected")):
                cluster = "first_party_cdn_fronted"
            elif bool((asset.get("waf_detection") or {}).get("detected")):
                cluster = "first_party_waf_detected"
            elif _status_code(asset.get("status_code")) > 0:
                cluster = "first_party_direct_web"
            else:
                cluster = "unclassified"
        clusters[cluster].append(host)
    if target not in clusters["root"]:
        clusters["root"].append(target)
    return dict(sorted((name, sorted(set(values))) for name, values in clusters.items()))


def _write_mindmap(
    *,
    target: str,
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    path: Path,
    max_nodes: int = 150,
) -> str:
    selected_hosts = {target}
    for edge in sorted(edges, key=lambda item: (int(item.get("level") or 99), item.get("parent", ""), item.get("child", ""))):
        if len(selected_hosts) >= max_nodes:
            break
        selected_hosts.add(str(edge.get("parent") or ""))
        selected_hosts.add(str(edge.get("child") or ""))
    node_ids = {host: f"N{index}" for index, host in enumerate(sorted(selected_hosts)) if host}
    lines = ["flowchart TD"]
    for host, node_id in node_ids.items():
        node = nodes.get(host) or {}
        level = node.get("level", "?")
        ownership = str(node.get("ownership") or "unclassified")
        label = f"{host}\\nL{level} | {ownership}".replace('"', "'")
        lines.append(f'  {node_id}["{label}"]')
    for edge in edges:
        parent = str(edge.get("parent") or "")
        child = str(edge.get("child") or "")
        if parent not in node_ids or child not in node_ids:
            continue
        source = str(edge.get("source") or "discovery").replace('"', "'")
        lines.append(f"  {node_ids[parent]} -->|{source}| {node_ids[child]}")
    content = "\n".join(lines) + "\n"
    path.write_text(content, encoding="utf-8")
    return content


def run_recursive_recon(
    *,
    target: str,
    run_dir: Path,
    logs_dir: Path,
    args: Any,
    validated_dns: dict[str, dict[str, Any]],
    http_records: list[dict[str, Any]],
    classified_assets: list[dict[str, Any]],
    initial_urls: list[str],
    seed_hosts: Iterable[str],
    wildcard_signatures: dict[str, str],
    shodan_context: dict[str, Any],
    shodan_summary: dict[str, Any],
) -> dict[str, Any]:
    enabled = bool(args.recursive_recon or args.max or args.exhaustive)
    max_depth = min(3, max(1, int(args.recursive_depth)))
    max_hosts = max(1, int(args.recursive_max_hosts))
    recursive_root = run_dir / "recursive"
    recursive_root.mkdir(parents=True, exist_ok=True)
    if not enabled:
        summary = {
            "requested": False,
            "status": "NOT_REQUESTED",
            "max_depth": max_depth,
            "levels_completed": 0,
            "hosts_crawled": 0,
            "new_hosts_validated": 0,
            "boundary_hosts": [],
        }
        write_json(run_dir / "recursive_recon_summary.json", summary)
        return {
            "summary": summary,
            "validated_dns": validated_dns,
            "http_records": http_records,
            "classified_assets": classified_assets,
            "all_urls": sorted(set(initial_urls)),
            "tool_results": [],
            "required_names": set(),
            "wildcard_signatures": wildcard_signatures,
            "shodan_summary": shodan_summary,
            "recursive_screenshot_files": [],
        }

    all_urls = set(initial_urls)
    tool_results: list[Any] = []
    required_names: set[str] = set()
    wildcard_suspected: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    nodes: dict[str, dict[str, Any]] = {
        target: {"host": target, "level": 0, "sources": ["canonical_root"], "ownership": "authorized_root"}
    }
    host_levels: dict[str, int] = {target: 0}
    crawled_hosts: set[str] = {target}
    seen_hosts: set[str] = {target, *validated_dns.keys()}
    boundary_hosts: set[str] = set()
    recursive_screenshot_files: list[str] = []
    captured_screenshot_hosts = screenshot_hosts_from_files(find_screenshot_files(run_dir))
    recursive_screenshot_skipped_existing = 0
    level_summaries: list[dict[str, Any]] = []
    looked_up_ips = set(shodan_summary.get("looked_up_ips") or [])
    recursive_shodan_errors: list[str] = []
    recursive_shodan_completed = 0
    recursive_shodan_no_data = 0

    # Seed Shodan/browser/passive hosts that were discovered after the initial DNS pass.
    pending_seed = {
        normalize_hostname(host) for host in seed_hosts
        if normalize_hostname(host) and is_in_scope_host(normalize_hostname(host), target)
    } - set(validated_dns) - {target}
    if pending_seed:
        seed_result = _validate_and_probe(
            hosts=pending_seed,
            level_label="seed",
            target=target,
            run_dir=run_dir,
            logs_dir=logs_dir,
            args=args,
            wildcard_signatures=wildcard_signatures,
        )
        tool_results.extend(seed_result["tool_results"])
        required_names.update(result.name for result in seed_result["tool_results"] if result.name.startswith(("dnsx_recursive", "httpx_recursive")))
        wildcard_signatures = seed_result["wildcard_signatures"]
        validated_dns = merge_dns_records(validated_dns, seed_result["dns"])
        wildcard_suspected.update(seed_result["wildcard"])
        http_records = _merge_http_records(http_records, seed_result["http_records"])
        classified_assets = _merge_classified(classified_assets, seed_result["classified"])
        for host in seed_result["dns"]:
            host_levels.setdefault(host, 1)
            seen_hosts.add(host)
            _add_edge(edges, parent=target, child=host, source="late_passive_seed", level=1)

    # Existing validated live applications are level-1 children of the root.
    best_assets = _best_assets_by_host(classified_assets)
    for host, asset in best_assets.items():
        if host == target or not is_in_scope_host(host, target):
            continue
        host_levels.setdefault(host, 1)
        nodes.setdefault(host, {"host": host, "level": 1, "sources": ["initial_inventory"]})
        _add_edge(edges, parent=target, child=host, source="initial_inventory", level=1)

    current_targets = [
        asset for host, asset in _best_assets_by_host(classified_assets).items()
        if _eligible_asset(asset, target) and host not in crawled_hosts
    ]
    current_targets.sort(key=lambda asset: (asset.get("priority") != "High", str(asset.get("host") or "")))

    total_crawled = 0
    total_new_validated = 0
    total_discovered = 0
    truncated = False

    for level in range(1, max_depth + 1):
        remaining_capacity = max_hosts - total_crawled
        if remaining_capacity <= 0:
            truncated = bool(current_targets)
            break
        targets = current_targets[:remaining_capacity]
        if len(current_targets) > len(targets):
            truncated = True
        if not targets:
            break

        level_label = f"level_{level:02d}"
        level_dir = recursive_root / level_label
        level_dir.mkdir(parents=True, exist_ok=True)
        tasks: list[tuple[str, list[str], str | None, dict[str, object]]] = []
        target_by_output: dict[str, str] = {}
        crawl_urls_by_host: dict[str, str] = {}
        for asset in targets:
            host = normalize_hostname(asset.get("host") or "")
            url = str(asset.get("url") or "").rstrip("/")
            if not host or not url:
                continue
            stem = _safe_stem(host)
            output_file = f"recursive/{level_label}/katana_{stem}.txt"
            target_by_output[output_file] = host
            crawl_urls_by_host[host] = url
            task_name = f"katana_recursive_l{level}_{stem}"[:90]
            tasks.append((
                task_name,
                build_katana_command(
                    url,
                    run_dir,
                    max_mode=True,
                    depth=max(1, int(args.recursive_katana_depth)),
                    concurrency=max(1, int(args.recursive_katana_concurrency)),
                    rate_limit=max(1, int(args.recursive_katana_rate_limit)),
                    crawl_duration=str(args.recursive_katana_duration),
                    output_file=output_file,
                ),
                None,
                {"recursive_level": level, "host": host, "url": url},
            ))
        if not tasks:
            break
        crawl_results = run_parallel(
            tasks,
            logs_dir,
            max(60, int(args.recursive_stage_timeout)),
            max(1, int(args.recursive_workers)),
        )
        tool_results.extend(crawl_results)
        required_names.update(result.name for result in crawl_results)
        total_crawled += len(tasks)
        crawled_hosts.update(crawl_urls_by_host)

        discovered_by_parent: dict[str, set[str]] = defaultdict(set)
        level_urls: set[str] = set()
        for output_file, parent in target_by_output.items():
            urls = set(read_lines(run_dir / output_file))
            level_urls |= urls
            for url in urls:
                for host in extract_in_scope_hosts_from_url(url, target):
                    normalized = normalize_hostname(host)
                    if normalized and normalized != parent and is_in_scope_host(normalized, target):
                        discovered_by_parent[parent].add(normalized)
                        _add_edge(
                            edges,
                            parent=parent,
                            child=normalized,
                            source="katana_recursive",
                            level=level + 1,
                            evidence=url[:500],
                        )
        all_urls |= level_urls

        # Browser-rendered discovery for every recursive level, in one bounded batch.
        level_live_urls = sorted(set(crawl_urls_by_host.values()))
        browser_hosts: set[str] = set()
        uncaptured_level_urls: list[str] = []
        for value in level_live_urls:
            try:
                screenshot_host = normalize_hostname(urlsplit(value).hostname or "")
            except ValueError:
                screenshot_host = ""
            if screenshot_host and screenshot_host in captured_screenshot_hosts:
                recursive_screenshot_skipped_existing += 1
                continue
            uncaptured_level_urls.append(value)
        if uncaptured_level_urls and not args.no_screenshots:
            screenshot_input = f"recursive/{level_label}/screenshot_urls.txt"
            screenshot_output = f"recursive/{level_label}/screenshots.jsonl"
            screenshot_dir = f"recursive/{level_label}/screenshots"
            write_lines(run_dir / screenshot_input, uncaptured_level_urls)
            screenshot_result = run_cmd(
                f"httpx_recursive_screenshot_l{level}",
                build_httpx_screenshot_file_command(
                    run_dir,
                    input_file=screenshot_input,
                    output_file=screenshot_output,
                    screenshot_dir=screenshot_dir,
                ),
                logs_dir,
                min(int(args.screenshot_timeout), int(args.recursive_stage_timeout)),
            )
            tool_results.append(screenshot_result)
            screenshot_records = read_jsonl(run_dir / screenshot_output)
            browser_urls, browser_hosts_all = extract_browser_observations(screenshot_records, target)
            all_urls |= set(browser_urls)
            browser_hosts = {host for host in browser_hosts_all if host != target}
            new_screenshot_files = [
                str(path.relative_to(run_dir)) for path in (run_dir / screenshot_dir).rglob("*.png")
            ]
            recursive_screenshot_files.extend(new_screenshot_files)
            captured_screenshot_hosts |= screenshot_hosts_from_files(new_screenshot_files)
            for child in browser_hosts:
                parent = target
                _add_edge(edges, parent=parent, child=child, source="browser_recursive", level=level + 1)

        # Passive Shodan host lookups for the hosts processed at this level.
        shodan_incremental = run_shodan_incremental_host_enrichment(
            target=target,
            run_dir=run_dir,
            context=shodan_context,
            args=args,
            validated_dns=validated_dns,
            classified_assets=classified_assets,
            hosts=set(crawl_urls_by_host),
            already_looked_up_ips=looked_up_ips,
            level_label=level_label,
        )
        looked_up_ips |= set(shodan_incremental.get("looked_up_ips") or [])
        recursive_shodan_errors.extend(str(value) for value in (shodan_incremental.get("errors") or []))
        recursive_shodan_completed += int(shodan_incremental.get("completed") or 0)
        recursive_shodan_no_data += int(shodan_incremental.get("no_data") or 0)
        shodan_hosts = set(shodan_incremental.get("discovered_hosts") or [])
        for child in shodan_hosts:
            _add_edge(edges, parent=target, child=child, source="shodan_recursive", level=level + 1)

        discovered_candidates = set(browser_hosts) | set(shodan_hosts)
        for values in discovered_by_parent.values():
            discovered_candidates |= values
        discovered_candidates = {
            normalize_hostname(host) for host in discovered_candidates
            if normalize_hostname(host) and is_in_scope_host(normalize_hostname(host), target)
        } - {target}
        total_discovered += len(discovered_candidates)

        if level >= max_depth:
            boundary_hosts |= discovered_candidates - seen_hosts
            for host in boundary_hosts:
                host_levels.setdefault(host, max_depth + 1)
            level_summaries.append({
                "level": level,
                "crawl_targets": sorted(crawl_urls_by_host),
                "crawl_target_count": len(crawl_urls_by_host),
                "urls_observed": len(level_urls),
                "new_hosts_observed": len(discovered_candidates - seen_hosts),
                "new_hosts_validated": 0,
                "next_level_targets": 0,
                "max_depth_boundary": True,
                "shodan": shodan_incremental,
            })
            break

        new_hosts = discovered_candidates - seen_hosts
        if not new_hosts:
            level_summaries.append({
                "level": level,
                "crawl_targets": sorted(crawl_urls_by_host),
                "crawl_target_count": len(crawl_urls_by_host),
                "urls_observed": len(level_urls),
                "new_hosts_observed": 0,
                "new_hosts_validated": 0,
                "next_level_targets": 0,
                "max_depth_boundary": False,
                "shodan": shodan_incremental,
            })
            current_targets = []
            continue

        validation = _validate_and_probe(
            hosts=new_hosts,
            level_label=f"discovered_from_{level_label}",
            target=target,
            run_dir=run_dir,
            logs_dir=logs_dir,
            args=args,
            wildcard_signatures=wildcard_signatures,
        )
        tool_results.extend(validation["tool_results"])
        required_names.update(result.name for result in validation["tool_results"] if result.name.startswith(("dnsx_recursive", "httpx_recursive")))
        wildcard_signatures = validation["wildcard_signatures"]
        validated_dns = merge_dns_records(validated_dns, validation["dns"])
        wildcard_suspected.update(validation["wildcard"])
        http_records = _merge_http_records(http_records, validation["http_records"])
        classified_assets = _merge_classified(classified_assets, validation["classified"])
        seen_hosts |= new_hosts
        total_new_validated += len(validation["dns"])
        for host in validation["dns"]:
            host_levels.setdefault(host, level + 1)

        current_targets = [
            asset for host, asset in _best_assets_by_host(validation["classified"]).items()
            if _eligible_asset(asset, target) and host not in crawled_hosts
        ]
        current_targets.sort(key=lambda asset: (asset.get("priority") != "High", str(asset.get("host") or "")))
        level_summaries.append({
            "level": level,
            "crawl_targets": sorted(crawl_urls_by_host),
            "crawl_target_count": len(crawl_urls_by_host),
            "urls_observed": len(level_urls),
            "new_hosts_observed": len(new_hosts),
            "new_hosts_validated": len(validation["dns"]),
            "wildcard_suspected": len(validation["wildcard"]),
            "next_level_targets": len(current_targets),
            "max_depth_boundary": False,
            "shodan": shodan_incremental,
        })

    best_assets = _best_assets_by_host(classified_assets)
    for host in set(validated_dns) | set(best_assets) | boundary_hosts | set(wildcard_suspected):
        asset = best_assets.get(host) or {}
        node = nodes.setdefault(host, {"host": host, "sources": []})
        node["level"] = host_levels.get(host, max_depth + 1 if host in boundary_hosts else 1)
        node["dns_state"] = (validated_dns.get(host) or wildcard_suspected.get(host) or {}).get("validation_state")
        node["http_status"] = asset.get("status_code")
        node["url"] = asset.get("url")
        node["ownership"] = asset.get("ownership") or ("max_depth_boundary" if host in boundary_hosts else "unclassified")
        node["application_provider"] = asset.get("application_provider")
        node["network_provider"] = asset.get("network_provider")
        node["category"] = asset.get("category")

    clusters = _cluster_assets(
        target=target,
        validated_dns=validated_dns,
        classified_assets=classified_assets,
        boundary_hosts=boundary_hosts,
        wildcard_hosts=set(wildcard_suspected),
    )
    topology = {
        "root": target,
        "max_depth": max_depth,
        "nodes": dict(sorted(nodes.items())),
        "edges": sorted(edges, key=lambda item: (int(item.get("level") or 99), item.get("parent", ""), item.get("child", ""), item.get("source", ""))),
    }
    write_json(run_dir / "recon_topology.json", topology)
    write_json(run_dir / "recon_clusters.json", clusters)
    mindmap = _write_mindmap(
        target=target,
        edges=topology["edges"],
        nodes=topology["nodes"],
        path=run_dir / "recon_mindmap.mmd",
    )
    write_lines(run_dir / "recursive_urls_all.txt", all_urls)
    write_json(run_dir / "recursive_hosts_by_level.json", {
        str(level): sorted(host for host, host_level in host_levels.items() if host_level == level)
        for level in range(0, max_depth + 2)
    })
    write_json(run_dir / "recursive_wildcard_suspected.json", wildcard_suspected)

    failed = [result.name for result in tool_results if result.name in required_names and not result.ok]
    status = "PARTIAL" if failed or truncated else "COMPLETE"
    summary = {
        "requested": True,
        "status": status,
        "max_depth": max_depth,
        "max_hosts": max_hosts,
        "parallel_workers": int(args.recursive_workers),
        "levels_completed": len(level_summaries),
        "levels": level_summaries,
        "hosts_crawled": total_crawled,
        "hosts_discovered": total_discovered,
        "new_hosts_validated": total_new_validated,
        "boundary_hosts": sorted(boundary_hosts),
        "boundary_host_count": len(boundary_hosts),
        "truncated_by_host_cap": truncated,
        "failed_required_stages": sorted(failed),
        "url_count": len(all_urls),
        "cluster_counts": {name: len(values) for name, values in clusters.items()},
        "clusters_file": "recon_clusters.json",
        "topology_file": "recon_topology.json",
        "mindmap_file": "recon_mindmap.mmd",
        "mindmap_mermaid": mindmap,
        "recursive_screenshot_files": sorted(set(recursive_screenshot_files)),
        "recursive_screenshot_count": len(set(recursive_screenshot_files)),
        "recursive_screenshot_skipped_existing_hosts": recursive_screenshot_skipped_existing,
    }
    write_json(run_dir / "recursive_recon_summary.json", summary)

    # Update Shodan aggregate summary with recursive host enrichment outputs.
    aggregate_services = read_jsonl(run_dir / "shodan_services.jsonl")
    aggregate_lookups = read_jsonl(run_dir / "shodan_host_lookups.jsonl")
    aggregate_no_data = read_jsonl(run_dir / "shodan_host_no_data.jsonl")
    aggregate_discovered = set(read_lines(run_dir / "shodan_discovered_hosts.txt"))
    updated_shodan = dict(shodan_summary)
    combined_shodan_errors = list(dict.fromkeys([
        *[str(value) for value in (shodan_summary.get("errors") or [])],
        *recursive_shodan_errors,
    ]))
    try:
        aggregate_assets = json.loads((run_dir / "shodan_assets.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        aggregate_assets = {}
    try:
        aggregate_vulnerabilities = json.loads((run_dir / "shodan_vulnerabilities.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        aggregate_vulnerabilities = []
    updated_shodan.update({
        "status": "PARTIAL" if combined_shodan_errors else str(shodan_summary.get("status") or "COMPLETE"),
        "errors": combined_shodan_errors,
        "host_lookups_completed": len(aggregate_lookups),
        "host_lookups_no_data": len(aggregate_no_data),
        "services_collected": len(aggregate_services),
        "assets_enriched": len(aggregate_assets) if isinstance(aggregate_assets, dict) else 0,
        "unique_vulnerabilities_observed": len(aggregate_vulnerabilities) if isinstance(aggregate_vulnerabilities, list) else 0,
        "discovered_hosts": sorted(aggregate_discovered),
        "looked_up_ips": sorted(looked_up_ips),
        "recursive_enrichment_enabled": True,
        "recursive_enrichment": {
            "completed": recursive_shodan_completed,
            "no_data": recursive_shodan_no_data,
            "errors": recursive_shodan_errors,
        },
    })
    write_json(run_dir / "shodan_summary.json", updated_shodan)

    return {
        "summary": summary,
        "validated_dns": validated_dns,
        "http_records": http_records,
        "classified_assets": classified_assets,
        "all_urls": sorted(all_urls),
        "tool_results": tool_results,
        "required_names": required_names,
        "wildcard_signatures": wildcard_signatures,
        "shodan_summary": updated_shodan,
        "recursive_screenshot_files": sorted(set(recursive_screenshot_files)),
        "wildcard_suspected": wildcard_suspected,
    }


def refresh_recursive_topology(
    *,
    target: str,
    run_dir: Path,
    validated_dns: dict[str, dict[str, Any]],
    classified_assets: list[dict[str, Any]],
    recursive_summary: dict[str, Any],
) -> dict[str, Any]:
    """Refresh topology node labels/clusters after final active WAF evidence."""
    try:
        topology = json.loads((run_dir / "recon_topology.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return recursive_summary
    nodes = topology.get("nodes") if isinstance(topology, dict) else {}
    edges = topology.get("edges") if isinstance(topology, dict) else []
    if not isinstance(nodes, dict) or not isinstance(edges, list):
        return recursive_summary
    best_assets = _best_assets_by_host(classified_assets)
    for host, asset in best_assets.items():
        node = nodes.setdefault(host, {"host": host, "level": 1, "sources": []})
        node["http_status"] = asset.get("status_code")
        node["url"] = asset.get("url")
        node["ownership"] = asset.get("ownership") or node.get("ownership")
        node["application_provider"] = asset.get("application_provider")
        node["network_provider"] = asset.get("network_provider")
        node["category"] = asset.get("category")
        node["waf_provider"] = (asset.get("waf_detection") or {}).get("provider")
        node["cdn_provider"] = (asset.get("cdn_detection") or {}).get("provider")
    boundary_hosts = set(recursive_summary.get("boundary_hosts") or [])
    try:
        wildcard_data = json.loads((run_dir / "recursive_wildcard_suspected.json").read_text(encoding="utf-8"))
        wildcard_hosts = set(wildcard_data) if isinstance(wildcard_data, dict) else set()
    except (OSError, json.JSONDecodeError):
        wildcard_hosts = set()
    clusters = _cluster_assets(
        target=target,
        validated_dns=validated_dns,
        classified_assets=classified_assets,
        boundary_hosts=boundary_hosts,
        wildcard_hosts=wildcard_hosts,
    )
    topology["nodes"] = dict(sorted(nodes.items()))
    write_json(run_dir / "recon_topology.json", topology)
    write_json(run_dir / "recon_clusters.json", clusters)
    mindmap = _write_mindmap(
        target=target,
        edges=edges,
        nodes=nodes,
        path=run_dir / "recon_mindmap.mmd",
    )
    updated = dict(recursive_summary)
    updated["cluster_counts"] = {name: len(values) for name, values in clusters.items()}
    updated["mindmap_mermaid"] = mindmap
    write_json(run_dir / "recursive_recon_summary.json", updated)
    return updated
