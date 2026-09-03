"""High-level orchestration for Smart Recon V8.5.1.

The workflow is intentionally stage-specific: recursive tools are not blindly
cloned, while independent list workloads are sharded and resumable.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import random
import shutil
import string
import sys
from argparse import Namespace
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .browser import extract_browser_observations
from .classification import classify_http_asset, make_review_csv, summarize_endpoint_categories
from .commands import (
    build_commands,
    build_dnsx_command,
    build_katana_command,
    build_wafw00f_command,
    build_naabu_command,
    build_nmap_command,
    normalize_katana_config,
)
from .config import (
    COMMON_WORDS,
    DEFAULT_MAX_CANDIDATE_LIMIT,
    DEFAULT_NORMAL_CANDIDATE_LIMIT,
    IMAGES,
    NAABU_IMAGE,
    NMAP_IMAGE,
)
from .edge_detection import (
    WAFW00F_IMAGE,
    merge_active_waf_results,
    parse_wafw00f_json,
    prepare_wafw00f_build_context,
    select_waf_targets,
    summarize_edge_detection,
    write_waf_csv,
)
from .io_utils import chunked, read_jsonl, read_lines, write_json, write_jsonl, write_lines
from .keywords import (
    filter_keywords_with_details,
    generate_candidate_records,
    keyword_tokens_from_url,
    split_to_words,
)
from .parsers import (
    collect_bbot_dns_records,
    collect_bbot_subdomains,
    extract_domains_from_text,
    extract_internal_ip_leaks_from_http_records,
    extract_internal_ip_leaks_from_lines,
    get_answer_signature,
    load_previous_confirmed,
    merge_dns_records,
    parse_dnsx_jsonl,
    parse_gobuster,
    parse_gobuster_records,
)
from .portscan import (
    group_open_ports,
    parse_naabu_jsonl,
    reconcile_port_candidates,
    parse_nmap_directory,
    prepare_nmap_build_context,
    safe_output_stem,
    select_port_scan_targets,
    summarize_port_scan,
    write_naabu_csv,
    write_nmap_csv,
    write_port_reconciliation_csv,
    write_port_target_manifest_csv,
)
from .reporting import make_report_md, write_confirmed_csv
from .recursive_recon import refresh_recursive_topology, run_recursive_recon
from .shodan_passive import (
    prepare_shodan_context,
    run_shodan_discovery,
    run_shodan_host_enrichment,
)
from .runtime import (
    docker_available,
    docker_image_exists,
    ensure_images,
    ensure_local_image,
    inspect_tool_images,
    now_stamp,
    resolve_auto_workers,
    run_cmd,
    run_parallel,
    sanitize_domain,
)
from .screenshots import build_screenshot_status, screenshot_artifact_summary, select_live_urls
from .validation import (
    is_in_scope_host,
    is_valid_hostname,
    normalize_candidate,
    normalize_hostname,
    parent_zone_for_host,
)


def _random_label() -> str:
    return "x" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(18))


def _prepare_run(args: Namespace) -> tuple[str, Path, Path, int, int, dict[str, bool]]:
    if not args.authorized:
        print(
            "[REFUSED] Add --authorized and only run against domains you own or are explicitly permitted to test.",
            file=sys.stderr,
        )
        raise PermissionError("authorization acknowledgement missing")
    if not docker_available():
        raise RuntimeError("Docker was not found in PATH. Install or start Docker Desktop first.")

    target = sanitize_domain(args.target)
    output_root = Path(args.output_root)
    run_dir = output_root / f"{target}-{now_stamp()}"
    logs_dir = run_dir / "tool_logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "bbot_home").mkdir(parents=True, exist_ok=True)

    workers = resolve_auto_workers(args.workers, max_requested=args.max or args.exhaustive)
    pull_workers = min(workers, len(IMAGES))
    print(f"[+] Target: {target}")
    print(f"[+] Output: {run_dir.resolve()}")
    print(f"[+] Workers: cpu_count={os.cpu_count() or 2}, selected={workers}, pull_workers={pull_workers}")
    image_status = ensure_images(IMAGES, logs_dir, pull_missing=not args.no_pull, workers=pull_workers)
    missing = [name for name, ok in image_status.items() if not ok]
    if missing:
        print(f"[WARN] Missing images: {', '.join(missing)}")
    return target, run_dir, logs_dir, workers, pull_workers, image_status


def _choose_canonical_url(records: list[dict[str, Any]], target: str) -> tuple[str, dict[str, Any]]:
    candidates: list[tuple[int, int, str, dict[str, Any]]] = []
    for record in records:
        values = [
            record.get("final_url"),
            record.get("url"),
            record.get("location"),
        ]
        for value in values:
            url = str(value or "").strip()
            if not url.startswith(("http://", "https://")):
                continue
            try:
                host = normalize_hostname(urlsplit(url).hostname or "")
            except ValueError:
                continue
            if not is_valid_hostname(host) or not is_in_scope_host(host, target):
                continue
            try:
                status = int(record.get("status_code") or 999)
            except (TypeError, ValueError):
                status = 999
            scheme_rank = 0 if url.startswith("https://") else 1
            status_rank = 0 if 200 <= status < 500 else 1
            candidates.append((scheme_rank, status_rank, url, record))
    if candidates:
        _, _, url, record = sorted(candidates, key=lambda item: (item[0], item[1], item[2]))[0]
        return url.rstrip("/"), record
    return f"https://{target}", {"fallback": True, "reason": "root probe produced no usable in-scope URL"}


def _merge_keyword_evidence(
    destination: dict[str, dict[str, Any]],
    incoming: dict[str, dict[str, Any]],
    *,
    score_boost: int = 0,
) -> None:
    for keyword, item in incoming.items():
        candidate = dict(item)
        candidate["score"] = min(100, int(candidate.get("score", 0)) + score_boost)
        candidate.setdefault("sources", [candidate.get("source")])
        candidate["occurrences"] = int(candidate.get("occurrences", 1))
        candidate["contexts"] = [candidate.get("context")] if candidate.get("context") else []
        current = destination.get(keyword)
        if current is None:
            destination[keyword] = candidate
            continue
        source_values = list(dict.fromkeys((current.get("sources") or []) + (candidate.get("sources") or [])))
        occurrence_count = int(current.get("occurrences", 1)) + int(candidate.get("occurrences", 1))
        contexts = list(dict.fromkeys((current.get("contexts") or []) + (candidate.get("contexts") or [])))[:10]
        if int(candidate.get("score", 0)) > int(current.get("score", 0)):
            candidate["sources"] = source_values
            candidate["occurrences"] = occurrence_count
            candidate["contexts"] = contexts
            destination[keyword] = candidate
        else:
            current["sources"] = source_values
            current["occurrences"] = occurrence_count
            current["contexts"] = contexts


def _candidate_limit(args: Namespace) -> int | None:
    if args.max_candidates is not None:
        return max(1, int(args.max_candidates))
    if args.exhaustive:
        return None
    return DEFAULT_MAX_CANDIDATE_LIMIT if args.max else DEFAULT_NORMAL_CANDIDATE_LIMIT


def _write_candidate_manifest(run_dir: Path, records: dict[str, dict[str, Any]]) -> None:
    ordered = sorted(records.values(), key=lambda item: (item["tier"], -item["score"], item["candidate"]))
    write_jsonl(run_dir / "candidate_manifest.jsonl", ordered)
    csv_path = run_dir / "candidate_manifest.csv"
    lines = ["candidate,tier,score,source,keyword"]
    for item in ordered:
        fields = [
            str(item.get("candidate", "")),
            str(item.get("tier", "")),
            str(item.get("score", "")),
            str(item.get("source", "")).replace(",", ";"),
            str(item.get("keyword") or "").replace(",", ";"),
        ]
        lines.append(",".join(fields))
    csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def partition_dns_candidates(records: dict[str, dict[str, Any]]) -> tuple[set[str], list[str]]:
    priority = {host for host, record in records.items() if int(record.get("tier", 9)) <= 1}
    bulk = sorted(set(records) - priority)
    return priority, bulk


def calculate_dns_coverage(
    input_total: int,
    chunk_rows: list[dict[str, Any]],
    *,
    workers: int,
    chunk_size: int,
    threads: int,
    rate_limit: int,
) -> dict[str, Any]:
    completed_input = sum(int(row.get("input_count", 0)) for row in chunk_rows if row.get("ok"))
    return {
        "input_total": input_total,
        "completed_input": completed_input,
        "coverage_percent": round((completed_input / input_total * 100), 2) if input_total else 100.0,
        "chunks_total": len(chunk_rows),
        "chunks_completed": sum(1 for row in chunk_rows if row.get("ok")),
        "chunks_failed": sum(1 for row in chunk_rows if not row.get("ok")),
        "complete": all(bool(row.get("ok")) for row in chunk_rows),
        "workers": max(1, workers),
        "chunk_size": max(1, chunk_size),
        "threads_per_worker": max(1, threads),
        "rate_limit_per_worker": max(1, rate_limit),
        "effective_rate_limit": max(1, workers) * max(1, rate_limit),
    }


def _run_dnsx_shards(
    *,
    run_dir: Path,
    logs_dir: Path,
    candidates: list[str],
    args: Namespace,
) -> tuple[list[Any], dict[str, Any], dict[str, dict[str, Any]]]:
    chunks_root = run_dir / "dnsx_chunks"
    input_root = chunks_root / "inputs"
    result_root = chunks_root / "results"
    input_root.mkdir(parents=True, exist_ok=True)
    result_root.mkdir(parents=True, exist_ok=True)

    tasks: list[tuple[str, list[str], None, dict[str, object]]] = []
    chunk_rows: list[dict[str, Any]] = []
    for index, values in enumerate(chunked(candidates, max(1, args.dnsx_chunk_size)), start=1):
        input_rel = f"dnsx_chunks/inputs/chunk_{index:04d}.txt"
        output_rel = f"dnsx_chunks/results/chunk_{index:04d}.jsonl"
        write_lines(run_dir / input_rel, values)
        name = f"dnsx_chunk_{index:04d}"
        command = build_dnsx_command(
            run_dir,
            input_file=input_rel,
            output_file=output_rel,
            threads=args.dnsx_threads,
            rate_limit=args.dnsx_rate_limit,
            retries=args.dnsx_retries,
        )
        metadata = {
            "chunk_index": index,
            "input_count": len(values),
            "input_file": input_rel,
            "output_file": output_rel,
        }
        tasks.append((name, command, None, metadata))
        chunk_rows.append({**metadata, "status": "pending", "attempts": 0})

    print(
        f"[+] DNSX bulk: {len(candidates)} candidates, {len(tasks)} chunks, "
        f"{max(1, args.dnsx_workers)} concurrent workers"
    )
    results = run_parallel(tasks, logs_dir, args.dnsx_chunk_timeout, max(1, args.dnsx_workers))

    final_by_index = {int(result.metadata.get("chunk_index", 0)): result for result in results}
    for retry_number in range(1, max(0, args.dnsx_retry_failed_chunks) + 1):
        failed_indices = [index for index, result in final_by_index.items() if not result.ok]
        if not failed_indices:
            break
        retry_tasks = []
        for index in failed_indices:
            row = chunk_rows[index - 1]
            command = build_dnsx_command(
                run_dir,
                input_file=str(row["input_file"]),
                output_file=str(row["output_file"]),
                threads=max(10, args.dnsx_threads // 2),
                rate_limit=max(10, args.dnsx_rate_limit // 2),
                retries=args.dnsx_retries,
            )
            retry_tasks.append((
                f"dnsx_chunk_{index:04d}_retry{retry_number}",
                command,
                None,
                {
                    "chunk_index": index,
                    "input_count": row["input_count"],
                    "input_file": row["input_file"],
                    "output_file": row["output_file"],
                    "retry_number": retry_number,
                },
            ))
        retry_results = run_parallel(
            retry_tasks,
            logs_dir,
            args.dnsx_chunk_timeout,
            max(1, min(args.dnsx_workers, len(retry_tasks))),
        )
        results.extend(retry_results)
        for result in retry_results:
            final_by_index[int(result.metadata.get("chunk_index", 0))] = result

    merged: dict[str, dict[str, Any]] = {}
    for row in chunk_rows:
        index = int(row["chunk_index"])
        result = final_by_index.get(index)
        row["attempts"] = sum(1 for item in results if int(item.metadata.get("chunk_index", 0)) == index)
        row["status"] = result.status if result else "Missing Result"
        row["ok"] = bool(result and result.ok)
        row["timed_out"] = bool(result and result.timed_out)
        row["seconds"] = round(result.seconds, 2) if result else None
        path = run_dir / str(row["output_file"])
        merged.update(parse_dnsx_jsonl(path))

    coverage = calculate_dns_coverage(
        len(candidates),
        chunk_rows,
        workers=args.dnsx_workers,
        chunk_size=args.dnsx_chunk_size,
        threads=args.dnsx_threads,
        rate_limit=args.dnsx_rate_limit,
    )
    write_json(run_dir / "dnsx_chunk_manifest.json", {"coverage": coverage, "chunks": chunk_rows})
    return results, coverage, merged


def _wildcard_zones(hosts: Iterable[str], target: str, limit: int) -> list[str]:
    zones = {target}
    for host in hosts:
        normalized = normalize_hostname(host)
        if not is_in_scope_host(normalized, target):
            continue
        zone = parent_zone_for_host(normalized, target)
        zones.add(zone)
        # Include one higher nested parent when applicable.
        if zone != target:
            zones.add(parent_zone_for_host(zone, target))
    return sorted(zones, key=lambda value: (value.count("."), value))[: max(1, limit)]


def _run_wildcard_checks(
    *,
    target: str,
    hosts: Iterable[str],
    run_dir: Path,
    logs_dir: Path,
    args: Namespace,
) -> tuple[Any, dict[str, Any], dict[str, str]]:
    zones = _wildcard_zones(hosts, target, args.max_wildcard_zones)
    probe_to_zone: dict[str, str] = {}
    for zone in zones:
        for _ in range(max(2, args.wildcard_probes)):
            probe = f"{_random_label()}.{zone}"
            probe_to_zone[probe] = zone
    write_lines(run_dir / "wildcard_tests.txt", probe_to_zone)
    command = build_dnsx_command(
        run_dir,
        input_file="wildcard_tests.txt",
        output_file="wildcard_tests.jsonl",
        threads=min(args.dnsx_threads, 30),
        rate_limit=min(args.dnsx_rate_limit, 50),
        retries=args.dnsx_retries,
    )
    result = run_cmd("dnsx_wildcards", command, logs_dir, min(args.timeout, 600))
    records = parse_dnsx_jsonl(run_dir / "wildcard_tests.jsonl")

    zone_signatures: dict[str, str] = {}
    zone_info: dict[str, Any] = {}
    for zone in zones:
        probes = [host for host, probe_zone in probe_to_zone.items() if probe_zone == zone]
        answered = [records[host] for host in probes if host in records]
        signatures = [get_answer_signature(record) for record in answered]
        counts = Counter(signatures)
        signature, count = counts.most_common(1)[0] if counts else ("", 0)
        wildcard = bool(signature and count >= 2)
        if wildcard:
            zone_signatures[zone] = signature
        zone_info[zone] = {
            "probes": probes,
            "answers": len(answered),
            "matching_signature_count": count,
            "has_wildcard_answer": wildcard,
            "signature": signature or None,
            "sample_answer": answered[0] if answered else None,
        }
    wildcard_info = {
        "probe_count": len(probe_to_zone),
        "zones_tested": len(zones),
        "zones": zone_info,
        "tool_status": result.status,
    }
    write_json(run_dir / "wildcard_check.json", wildcard_info)
    return result, wildcard_info, zone_signatures


def _apply_wildcard_state(
    records: dict[str, dict[str, Any]],
    zone_signatures: dict[str, str],
    target: str,
    exact_hosts: set[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    validated: dict[str, dict[str, Any]] = {}
    wildcard_suspected: dict[str, dict[str, Any]] = {}
    for host, record in records.items():
        zone = parent_zone_for_host(host, target)
        signature = get_answer_signature(record)
        wildcard_like = bool(zone_signatures.get(zone) and zone_signatures[zone] == signature)
        record["wildcard_like"] = wildcard_like
        record["wildcard_zone"] = zone if wildcard_like else None
        if wildcard_like:
            record["validation_state"] = "wildcard_suspected_exact" if host in exact_hosts else "wildcard_suspected"
            wildcard_suspected[host] = record
            if host in exact_hosts:
                validated[host] = record
        else:
            record.setdefault("validation_state", "dns_resolved" if (record.get("a") or record.get("aaaa")) else "cname_only")
            validated[host] = record
    return validated, wildcard_suspected


def _required_failures(tool_results: list[Any], required_names: set[str]) -> list[str]:
    return sorted({result.name for result in tool_results if result.name in required_names and not result.ok})


def determine_run_health(
    *,
    failed_required: list[str],
    dns_complete: bool,
    canonical_reachable: bool,
    passive_discovery_ok: bool,
) -> str:
    """Apply report health semantics independently of the number of child hosts."""
    if not canonical_reachable and not passive_discovery_ok:
        return "FAILED"
    if failed_required or not dns_complete:
        return "PARTIAL"
    return "COMPLETE"


def _root_probe_is_reachable(records: list[dict[str, Any]], target: str) -> bool:
    for record in records:
        try:
            status = int(record.get("status_code"))
        except (TypeError, ValueError):
            continue
        host = normalize_hostname(record.get("host") or record.get("input") or "")
        if 100 <= status < 600 and is_in_scope_host(host, target):
            return True
    return False


def merge_http_review_records(*sources: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge root/child HTTP results and exclude failed status-0 probes."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for source in sources:
        for record in source:
            try:
                status = int(record.get("status_code"))
            except (TypeError, ValueError):
                continue
            if status <= 0:
                continue
            host = normalize_hostname(record.get("host") or record.get("input") or "")
            url = str(record.get("url") or "").strip()
            merged[(host, url)] = record
    return list(merged.values())


def _write_command_manifest(run_dir: Path, tool_results: list[Any]) -> None:
    rows = []
    for result in tool_results:
        argv = result.metadata.get("command_argv")
        if not argv:
            continue
        rows.append({
            "stage": result.name,
            "argv": argv,
            "copyable": result.metadata.get("command_copyable"),
            "container_name": result.metadata.get("container_name"),
            "returncode": result.returncode,
            "timed_out": result.timed_out,
        })
    write_json(run_dir / "command_manifest.json", {"commands": rows, "secrets_redacted": True})


def run_pipeline(args: Namespace) -> int:
    try:
        target, run_dir, logs_dir, workers, pull_workers, image_status = _prepare_run(args)
    except PermissionError:
        return 2
    except (RuntimeError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    output_root = Path(args.output_root)
    project_root = Path(__file__).resolve().parent.parent
    shodan_context = prepare_shodan_context(project_root=project_root, output_root=output_root, args=args)
    tool_results: list[Any] = []
    required_names: set[str] = set()

    waf_image_ready = False
    if args.active_waf:
        build_context = prepare_wafw00f_build_context(run_dir)
        try:
            build_result = ensure_local_image(
                image=WAFW00F_IMAGE,
                context_dir=build_context,
                logs_dir=logs_dir,
                timeout=max(300, min(args.waf_stage_timeout, 1800)),
                build_name="docker_build_wafw00f",
            )
        except (OSError, RuntimeError) as exc:
            build_result = None
            print(f"[WARN] Could not prepare WAFW00F image: {exc}")
        if build_result is not None:
            tool_results.append(build_result)
        waf_image_ready = docker_image_exists(WAFW00F_IMAGE)
        image_status["wafw00f"] = waf_image_ready
        if not waf_image_ready:
            print("[WARN] Active WAF detection requested, but the local WAFW00F image is unavailable.")

    port_scan_requested = bool(args.port_scan or args.nmap_service_scan)
    naabu_image_ready = False
    nmap_image_ready = False
    if port_scan_requested:
        optional_status = ensure_images(
            {"naabu": NAABU_IMAGE},
            logs_dir,
            pull_missing=not args.no_pull,
            workers=1,
        )
        naabu_image_ready = bool(optional_status.get("naabu"))
        image_status["naabu"] = naabu_image_ready
        if not naabu_image_ready:
            print("[WARN] Port scan requested, but the Naabu image is unavailable.")

    if args.nmap_service_scan:
        nmap_context = prepare_nmap_build_context(run_dir)
        try:
            nmap_build_result = ensure_local_image(
                image=NMAP_IMAGE,
                context_dir=nmap_context,
                logs_dir=logs_dir,
                timeout=max(600, min(args.port_scan_timeout, 1800)),
                build_name="docker_build_nmap",
            )
        except (OSError, RuntimeError) as exc:
            nmap_build_result = None
            print(f"[WARN] Could not prepare Nmap image: {exc}")
        if nmap_build_result is not None:
            tool_results.append(nmap_build_result)
        nmap_image_ready = docker_image_exists(NMAP_IMAGE)
        image_status["nmap"] = nmap_image_ready
        if not nmap_image_ready:
            print("[WARN] Nmap service validation requested, but the local Nmap image is unavailable.")

    version_images = dict(IMAGES)
    if args.active_waf:
        version_images["wafw00f"] = WAFW00F_IMAGE
    if port_scan_requested:
        version_images["naabu"] = NAABU_IMAGE
    if args.nmap_service_scan:
        version_images["nmap"] = NMAP_IMAGE
    tool_versions = inspect_tool_images(version_images)
    write_json(run_dir / "tool_versions.json", tool_versions)

    previous_records: dict[str, dict[str, Any]] = {}
    previous_hosts: set[str] = set()
    if not args.no_carry_forward:
        previous_records, previous_hosts = load_previous_confirmed(target, output_root, run_dir)
    write_lines(run_dir / "previous_validated_hosts.txt", previous_hosts)

    user_word_lines: list[str] = []
    if args.wordlist:
        wordlist_path = Path(args.wordlist)
        if wordlist_path.exists():
            user_word_lines = read_lines(wordlist_path)
        else:
            print(f"[WARN] Wordlist not found: {wordlist_path}")
    write_lines(run_dir / "base_wordlist.txt", set(COMMON_WORDS) | set(user_word_lines))

    deep_mode = bool(args.max or args.exhaustive)
    commands = build_commands(target, run_dir, deep_mode, amass_active=(args.amass_active or args.exhaustive))

    # Stage 1: independent passive/base discovery. Katana is intentionally not duplicated here.
    stage1: list[tuple[str, list[str], str | None]] = []
    if not args.skip_subfinder:
        stage1.append(("subfinder", commands["subfinder"], None))
        required_names.add("subfinder")
    if not args.skip_amass:
        stage1.append(("amass", commands["amass"], None))
        required_names.add("amass")
    if not args.skip_gobuster:
        stage1.append(("gobuster_base", commands["gobuster_base"], None))
        required_names.add("gobuster_base")
    if not args.skip_bbot:
        stage1.append(("bbot", commands["bbot"], None))
        required_names.add("bbot")

    print(f"[+] Stage 1: running {len(stage1)} independent discovery tools")
    stage1_results = run_parallel(stage1, logs_dir, args.timeout, workers)
    tool_results.extend(stage1_results)

    # Canonical root selection and one bounded Katana crawl.
    write_lines(run_dir / "root_probe_input.txt", [target])
    root_probe_result = run_cmd("httpx_root_probe", commands["httpx_root_probe"], logs_dir, min(args.timeout, 300))
    tool_results.append(root_probe_result)
    required_names.add("httpx_root_probe")
    root_probe_records = read_jsonl(run_dir / "httpx_root_probe.jsonl")
    canonical_url, canonical_evidence = _choose_canonical_url(root_probe_records, target)
    write_json(run_dir / "canonical_target.json", {"canonical_url": canonical_url, "evidence": canonical_evidence})

    katana_urls: list[str] = []
    katana_config: dict[str, Any] = {"requested": {"enabled": False}, "effective": {"enabled": False}, "notes": []}
    if not args.skip_katana:
        depth = args.katana_depth if args.katana_depth is not None else (5 if deep_mode else 3)
        katana_config = normalize_katana_config(
            depth=max(1, depth),
            crawl_duration=args.katana_duration,
            known_files="all",
        )
        katana_config["requested"]["enabled"] = True
        katana_config["effective"]["enabled"] = True
        katana_config["effective"].update({
            "concurrency": max(1, args.katana_concurrency),
            "rate_limit": max(1, args.katana_rate_limit),
            "javascript_crawl": True,
            "ignore_query_params": True,
        })
        write_lines(run_dir / "katana_urls.txt", [])
        katana_command = build_katana_command(
            canonical_url,
            run_dir,
            max_mode=deep_mode,
            depth=max(1, depth),
            concurrency=max(1, args.katana_concurrency),
            rate_limit=max(1, args.katana_rate_limit),
            crawl_duration=args.katana_duration,
        )
        katana_result = run_cmd("katana_canonical", katana_command, logs_dir, args.timeout)
        tool_results.append(katana_result)
        required_names.add("katana_canonical")
        katana_urls = sorted(set(read_lines(run_dir / "katana_urls.txt")))
    else:
        write_lines(run_dir / "katana_urls.txt", [])

    # Parse exact discoveries.
    raw_subdomains: set[str] = set()
    raw_subdomains |= {
        normalize_hostname(value)
        for value in read_lines(run_dir / "subfinder_subdomains.txt")
        if normalize_candidate(value, target)
    }
    amass_stdout = logs_dir / "amass.stdout.txt"
    if amass_stdout.exists():
        raw_subdomains |= extract_domains_from_text(amass_stdout.read_text(encoding="utf-8", errors="replace"), target)
    raw_subdomains |= parse_gobuster(run_dir / "gobuster_base.txt", target)
    raw_subdomains |= collect_bbot_subdomains(run_dir / "bbot_home", target)
    for url in katana_urls:
        raw_subdomains |= extract_domains_from_text(url, target)

    shodan_discovery = run_shodan_discovery(
        target=target,
        run_dir=run_dir,
        context=shodan_context,
        args=args,
    )
    raw_subdomains |= set(shodan_discovery.get("discovered_hosts") or [])
    raw_subdomains.discard(target)
    raw_subdomains = {host for host in raw_subdomains if normalize_candidate(host, target)}
    write_lines(run_dir / "subdomains_all_raw.txt", raw_subdomains)

    # Build evidence-aware keywords and retain rejected values for auditability.
    keyword_evidence: dict[str, dict[str, Any]] = {}
    rejected_keywords: list[dict[str, Any]] = []

    accepted, rejected = filter_keywords_with_details(user_word_lines, source="user_wordlist")
    _merge_keyword_evidence(keyword_evidence, accepted, score_boost=20)
    rejected_keywords.extend(rejected)

    for host in sorted(raw_subdomains):
        prefix = host[: -len(target)].strip(".")
        accepted, rejected = filter_keywords_with_details(
            split_to_words(prefix), source="exact_subdomain_label", context=host
        )
        _merge_keyword_evidence(keyword_evidence, accepted, score_boost=18)
        rejected_keywords.extend(rejected)

    for url in katana_urls:
        accepted, rejected = filter_keywords_with_details(
            keyword_tokens_from_url(url, target), source="katana_url", context=url
        )
        _merge_keyword_evidence(keyword_evidence, accepted)
        rejected_keywords.extend(rejected)

    # URL-derived one-off tokens are usually slugs, hashes, campaign IDs, or bundle artifacts.
    # Preserve trusted user/exact-host words, curated words, and repeated target-derived words.
    curated_words = set(COMMON_WORDS)
    for keyword, evidence in list(keyword_evidence.items()):
        sources = set(str(value) for value in (evidence.get("sources") or []))
        trusted = bool(sources & {"user_wordlist", "exact_subdomain_label"})
        occurrences = int(evidence.get("occurrences", 1))
        if len(keyword) <= 5:
            minimum_occurrences = 5
        elif len(keyword) <= 8:
            minimum_occurrences = 3
        else:
            minimum_occurrences = 2
        katana_only = sources == {"katana_url"}
        consonant_heavy = not any(ch in "aeiou" for ch in keyword)
        if not trusted and keyword not in curated_words and katana_only and consonant_heavy:
            rejected_keywords.append({
                "original": keyword,
                "keyword": keyword,
                "accepted": False,
                "reason": "katana_consonant_heavy_token",
                "source": "katana_url",
                "occurrences": occurrences,
            })
            del keyword_evidence[keyword]
            continue
        if not trusted and keyword not in curated_words and occurrences < minimum_occurrences:
            rejected_keywords.append({
                "original": keyword,
                "keyword": keyword,
                "accepted": False,
                "reason": "insufficient_target_frequency",
                "source": ",".join(sorted(sources)),
                "occurrences": occurrences,
            })
            del keyword_evidence[keyword]
            continue
        evidence["score"] = min(100, int(evidence.get("score", 0)) + min(15, max(0, occurrences - 1) * 3))

    write_json(run_dir / "keyword_evidence.json", keyword_evidence)
    write_json(run_dir / "rejected_keywords.json", rejected_keywords)
    write_lines(run_dir / "extracted_keywords.txt", keyword_evidence)

    candidate_records, candidate_stats = generate_candidate_records(
        target,
        keyword_evidence,
        exact_hosts=raw_subdomains,
        previous_hosts=previous_hosts,
        max_mode=deep_mode,
        exhaustive=args.exhaustive,
        candidate_limit=_candidate_limit(args),
    )
    _write_candidate_manifest(run_dir, candidate_records)
    candidates = set(candidate_records)
    priority_candidates, bulk_candidates = partition_dns_candidates(candidate_records)
    write_lines(run_dir / "priority_candidates.txt", priority_candidates)
    write_lines(run_dir / "bulk_candidates.txt", bulk_candidates)
    write_lines(run_dir / "all_candidates.txt", candidates)
    write_lines(run_dir / "custom_wordlist.txt", keyword_evidence)
    print(
        f"[+] Stage 2: {len(candidates)} bounded candidates from {len(keyword_evidence)} accepted keywords "
        f"({len(rejected_keywords)} rejected tokens)"
    )

    # Priority DNS first; bulk DNS is sharded across a fixed worker pool.
    priority_command = build_dnsx_command(
        run_dir,
        input_file="priority_candidates.txt",
        output_file="dnsx_priority.jsonl",
        threads=min(args.dnsx_threads, 50),
        rate_limit=min(args.dnsx_rate_limit, 100),
        retries=args.dnsx_retries,
    )
    priority_result = run_cmd("dnsx_priority", priority_command, logs_dir, args.dnsx_chunk_timeout)
    tool_results.append(priority_result)
    required_names.add("dnsx_priority")
    priority_dns = parse_dnsx_jsonl(run_dir / "dnsx_priority.jsonl")

    bulk_results: list[Any] = []
    if bulk_candidates:
        bulk_results, dns_coverage, bulk_dns = _run_dnsx_shards(
            run_dir=run_dir,
            logs_dir=logs_dir,
            candidates=bulk_candidates,
            args=args,
        )
        tool_results.extend(bulk_results)
    else:
        dns_coverage = {
            "input_total": 0,
            "completed_input": 0,
            "coverage_percent": 100.0,
            "chunks_total": 0,
            "chunks_completed": 0,
            "chunks_failed": 0,
            "complete": True,
            "workers": args.dnsx_workers,
            "chunk_size": args.dnsx_chunk_size,
            "threads_per_worker": args.dnsx_threads,
            "rate_limit_per_worker": args.dnsx_rate_limit,
            "effective_rate_limit": args.dnsx_workers * args.dnsx_rate_limit,
        }
        bulk_dns = {}

    # Filtered Gobuster custom pass; validate only newly discovered names, never rerun all DNS candidates.
    custom_dns: dict[str, dict[str, Any]] = {}
    if not args.skip_gobuster and keyword_evidence:
        gobuster_custom_result = run_cmd("gobuster_custom", commands["gobuster_custom"], logs_dir, args.timeout)
        tool_results.append(gobuster_custom_result)
        required_names.add("gobuster_custom")
        custom_hosts = parse_gobuster(run_dir / "gobuster_custom.txt", target)
        new_custom_hosts = sorted(custom_hosts - set(priority_dns) - set(bulk_dns))
        write_lines(run_dir / "gobuster_new_hosts_to_validate.txt", new_custom_hosts)
        if new_custom_hosts:
            custom_command = build_dnsx_command(
                run_dir,
                input_file="gobuster_new_hosts_to_validate.txt",
                output_file="dnsx_gobuster_new.jsonl",
                threads=min(args.dnsx_threads, 30),
                rate_limit=min(args.dnsx_rate_limit, 50),
                retries=args.dnsx_retries,
            )
            custom_result = run_cmd("dnsx_gobuster_new", custom_command, logs_dir, min(args.dnsx_chunk_timeout, 900))
            tool_results.append(custom_result)
            custom_dns = parse_dnsx_jsonl(run_dir / "dnsx_gobuster_new.jsonl")

    supplemental_gobuster = merge_dns_records(
        parse_gobuster_records(run_dir / "gobuster_base.txt", target),
        parse_gobuster_records(run_dir / "gobuster_custom.txt", target),
    )
    supplemental_gobuster = {
        host: record for host, record in supplemental_gobuster.items()
        if record.get("a") or record.get("aaaa") or record.get("cname")
    }
    supplemental_bbot = collect_bbot_dns_records(run_dir / "bbot_home", target)
    all_dns = merge_dns_records(priority_dns, bulk_dns, custom_dns, supplemental_gobuster, supplemental_bbot)
    all_dns.pop(target, None)

    wildcard_result, wildcard_info, zone_signatures = _run_wildcard_checks(
        target=target,
        hosts=set(all_dns) | raw_subdomains,
        run_dir=run_dir,
        logs_dir=logs_dir,
        args=args,
    )
    tool_results.append(wildcard_result)
    required_names.add("dnsx_wildcards")
    validated_dns, wildcard_suspected = _apply_wildcard_state(
        all_dns,
        zone_signatures,
        target,
        exact_hosts=raw_subdomains,
    )

    # Previous hosts remain evidence, but are not silently promoted if this run could not revalidate them.
    carried_forward = {
        host: {**record, "validation_state": "previous_run_unvalidated", "needs_revalidation": True}
        for host, record in previous_records.items()
        if host not in validated_dns
    }
    write_json(run_dir / "carried_forward_unvalidated.json", carried_forward)
    write_json(run_dir / "wildcard_suspected_hosts.json", wildcard_suspected)
    write_lines(run_dir / "unconfirmed_tool_found_subdomains.txt", raw_subdomains - set(validated_dns))

    write_lines(run_dir / "validated_dns_hosts.txt", validated_dns)
    write_json(run_dir / "validated_dns_hosts.json", validated_dns)
    # Compatibility aliases for older consumers.
    write_lines(run_dir / "confirmed_subdomains.txt", validated_dns)
    write_json(run_dir / "confirmed_subdomains.json", validated_dns)

    # HTTP probing and classification.
    classified_assets: list[dict[str, Any]] = []
    child_http_records: list[dict[str, Any]] = []
    if validated_dns:
        print(f"[+] Stage 3: probing {len(validated_dns)} DNS-validated hosts")
        http_result = run_cmd("httpx_probe", commands["httpx_probe"], logs_dir, min(args.timeout, 1800))
        tool_results.append(http_result)
        required_names.add("httpx_probe")
        child_http_records = read_jsonl(run_dir / "httpx_probe.jsonl")
    http_records = merge_http_review_records(root_probe_records, child_http_records)
    classified_assets = [classify_http_asset(record) for record in http_records]
    classified_assets.sort(
        key=lambda item: (
            item.get("priority") != "High",
            item.get("ownership") == "third_party_saas",
            str(item.get("category")),
            str(item.get("host")),
        )
    )
    write_json(run_dir / "http_review_classification.json", classified_assets)
    make_review_csv(run_dir / "http_review_classification.csv", classified_assets)

    endpoint_summary = summarize_endpoint_categories(katana_urls, target)
    write_json(run_dir / "endpoint_classification.json", endpoint_summary)
    write_lines(run_dir / "external_references.txt", endpoint_summary.get("external_references", []))
    write_lines(run_dir / "openapi_candidates.txt", endpoint_summary.get("openapi_candidates", []))

    # Screenshots with explicit coverage reporting.
    live_urls, screenshot_coverage = select_live_urls(http_records, args.screenshot_limit, classified_assets)
    write_lines(run_dir / "live_urls_for_screenshot.txt", live_urls)
    screenshot_requested = bool(live_urls) and not args.no_screenshots
    screenshot_result = None
    if screenshot_requested:
        print(f"[+] Stage 4: screenshotting {len(live_urls)} selected live URLs")
        screenshot_result = run_cmd(
            "httpx_screenshot",
            commands["httpx_screenshot"],
            logs_dir,
            args.screenshot_timeout,
        )
        tool_results.append(screenshot_result)
        try:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{str(run_dir.resolve())}:/output", "alpine", "sh", "-c", "chmod -R a+rX /output 2>/dev/null || true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        except Exception:
            pass
    screenshot_status, screenshot_files = build_screenshot_status(
        run_dir, screenshot_requested, screenshot_result, screenshot_coverage
    )
    write_json(run_dir / "screenshot_status.json", screenshot_status)

    # Browser-only discovery remains separately revalidated.
    screenshot_records = read_jsonl(run_dir / "httpx_screenshots.jsonl")
    browser_urls, browser_all_hosts = extract_browser_observations(screenshot_records, target)
    browser_new_hosts = browser_all_hosts - set(validated_dns) - {target}
    write_lines(run_dir / "browser_discovered_urls.txt", browser_urls)
    write_lines(run_dir / "browser_observed_hosts_all.txt", browser_all_hosts)
    write_lines(run_dir / "browser_discovered_hosts.txt", browser_new_hosts)

    browser_validated: dict[str, dict[str, Any]] = {}
    if browser_new_hosts:
        write_lines(run_dir / "browser_discovered_hosts.txt", browser_new_hosts)
        browser_dns_command = build_dnsx_command(
            run_dir,
            input_file="browser_discovered_hosts.txt",
            output_file="dnsx_browser_discovered.jsonl",
            threads=min(args.dnsx_threads, 30),
            rate_limit=min(args.dnsx_rate_limit, 50),
            retries=args.dnsx_retries,
        )
        browser_dns_result = run_cmd("dnsx_browser_discovered", browser_dns_command, logs_dir, min(args.timeout, 900))
        tool_results.append(browser_dns_result)
        browser_validated = parse_dnsx_jsonl(run_dir / "dnsx_browser_discovered.jsonl")
        write_lines(run_dir / "browser_validated_subdomains.txt", browser_validated)
        if browser_validated:
            browser_http_result = run_cmd(
                "httpx_browser_discovered",
                commands["httpx_browser_discovered"],
                logs_dir,
                min(args.timeout, 900),
            )
            tool_results.append(browser_http_result)
            browser_http_records = read_jsonl(run_dir / "httpx_browser_discovered.jsonl")
            http_records.extend(browser_http_records)
            classified_assets.extend(classify_http_asset(record) for record in browser_http_records)
            for host, record in browser_validated.items():
                zone = parent_zone_for_host(host, target)
                wildcard_like = bool(zone_signatures.get(zone) and zone_signatures[zone] == get_answer_signature(record))
                record["wildcard_like"] = wildcard_like
                record["validation_state"] = "wildcard_suspected" if wildcard_like else record.get("validation_state", "dns_resolved")
                if not wildcard_like:
                    validated_dns[host] = record
            write_lines(run_dir / "validated_dns_hosts.txt", validated_dns)
            write_json(run_dir / "validated_dns_hosts.json", validated_dns)
            write_lines(run_dir / "confirmed_subdomains.txt", validated_dns)
            write_json(run_dir / "confirmed_subdomains.json", validated_dns)
            write_json(run_dir / "http_review_classification.json", classified_assets)
            make_review_csv(run_dir / "http_review_classification.csv", classified_assets)
    else:
        write_lines(run_dir / "browser_validated_subdomains.txt", [])

    # Shodan host enrichment now runs before recursive expansion so every
    # newly discovered in-scope hostname can be revalidated during the same run.
    shodan_summary = run_shodan_host_enrichment(
        target=target,
        run_dir=run_dir,
        context=shodan_context,
        args=args,
        discovery=shodan_discovery,
        validated_dns=validated_dns,
        classified_assets=classified_assets,
    )

    recursive_seed_hosts = set(shodan_summary.get("discovered_hosts") or []) | set(browser_new_hosts)
    recursive_result = run_recursive_recon(
        target=target,
        run_dir=run_dir,
        logs_dir=logs_dir,
        args=args,
        validated_dns=validated_dns,
        http_records=http_records,
        classified_assets=classified_assets,
        initial_urls=katana_urls,
        seed_hosts=recursive_seed_hosts,
        wildcard_signatures=zone_signatures,
        shodan_context=shodan_context,
        shodan_summary=shodan_summary,
    )
    tool_results.extend(recursive_result.get("tool_results") or [])
    required_names.update(recursive_result.get("required_names") or set())
    validated_dns = recursive_result["validated_dns"]
    http_records = recursive_result["http_records"]
    classified_assets = recursive_result["classified_assets"]
    katana_urls = list(recursive_result["all_urls"])
    zone_signatures = recursive_result["wildcard_signatures"]
    shodan_summary = recursive_result["shodan_summary"]
    recursive_summary = recursive_result["summary"]
    wildcard_suspected.update(recursive_result.get("wildcard_suspected") or {})

    # Persist the same-run revalidated inventory before any active enrichment.
    carried_forward = {
        host: record for host, record in carried_forward.items() if host not in validated_dns
    }
    write_json(run_dir / "carried_forward_unvalidated.json", carried_forward)
    write_json(run_dir / "wildcard_suspected_hosts.json", wildcard_suspected)
    write_lines(run_dir / "validated_dns_hosts.txt", validated_dns)
    write_json(run_dir / "validated_dns_hosts.json", validated_dns)
    write_lines(run_dir / "confirmed_subdomains.txt", validated_dns)
    write_json(run_dir / "confirmed_subdomains.json", validated_dns)
    write_json(run_dir / "http_review_classification.json", classified_assets)
    make_review_csv(run_dir / "http_review_classification.csv", classified_assets)

    endpoint_summary = summarize_endpoint_categories(katana_urls, target)
    write_json(run_dir / "endpoint_classification.json", endpoint_summary)
    write_lines(run_dir / "external_references.txt", endpoint_summary.get("external_references", []))
    write_lines(run_dir / "openapi_candidates.txt", endpoint_summary.get("openapi_candidates", []))

    recursive_screenshot_files = recursive_result.get("recursive_screenshot_files") or []
    screenshot_files = sorted(set(screenshot_files) | set(recursive_screenshot_files))
    screenshot_status["recursive_image_files"] = len(recursive_screenshot_files)
    screenshot_status["recursive_skipped_existing_hosts"] = int(
        recursive_summary.get("recursive_screenshot_skipped_existing_hosts") or 0
    )
    screenshot_status["image_files"] = len(screenshot_files)
    screenshot_status["recursive_levels_enabled"] = bool(recursive_summary.get("requested"))
    screenshot_status["artifact_summary"] = screenshot_artifact_summary(run_dir, screenshot_files)
    write_json(run_dir / "screenshot_status.json", screenshot_status)

    # Dedicated edge/CDN/WAF evidence runs after recursive expansion so newly
    # validated first-party applications receive the same evidence treatment.
    waf_targets = select_waf_targets(
        classified_assets,
        limit=args.waf_limit,
        include_third_party=args.waf_include_third_party,
    )
    write_lines(run_dir / "waf_targets.txt", waf_targets)
    waf_tool_result = None
    waf_results: list[dict[str, Any]] = []
    if args.active_waf and waf_targets and waf_image_ready:
        print(f"[+] Stage 5: active WAF fingerprinting on {len(waf_targets)} selected hosts")
        waf_command = build_wafw00f_command(
            run_dir,
            request_timeout=args.waf_request_timeout,
            find_all=args.waf_find_all,
        )
        waf_tool_result = run_cmd(
            "wafw00f",
            waf_command,
            logs_dir,
            max(60, args.waf_stage_timeout),
            metadata={
                "targets": len(waf_targets),
                "active_fingerprinting": True,
                "third_party_included": bool(args.waf_include_third_party),
            },
        )
        tool_results.append(waf_tool_result)
        waf_results = parse_wafw00f_json(run_dir / "wafw00f.json")
    classified_assets = merge_active_waf_results(classified_assets, waf_results)
    edge_summary = summarize_edge_detection(
        classified_assets,
        waf_results,
        active_requested=bool(args.active_waf),
        active_tool_ok=(waf_tool_result.ok if waf_tool_result is not None else None),
        target_count=len(waf_targets),
    )
    write_json(run_dir / "waf_detection.json", waf_results)
    write_waf_csv(run_dir / "waf_detection.csv", waf_results)
    write_json(run_dir / "edge_detection_summary.json", edge_summary)
    write_json(run_dir / "http_review_classification.json", classified_assets)
    make_review_csv(run_dir / "http_review_classification.csv", classified_assets)
    recursive_summary = refresh_recursive_topology(
        target=target,
        run_dir=run_dir,
        validated_dns=validated_dns,
        classified_assets=classified_assets,
        recursive_summary=recursive_summary,
    )

    # Optional controlled port enumeration. Target selection is evidence-aware:
    # CDN/WAF edges and third-party SaaS records are excluded unless explicitly
    # included. Nmap rechecks only valid ports reported as candidates by Naabu.
    port_targets, port_target_manifest = select_port_scan_targets(
        validated_dns,
        classified_assets,
        root_target=target,
        limit=args.port_scan_limit,
        include_cdn=bool(args.port_scan_include_cdn),
        include_third_party=bool(args.port_scan_include_third_party),
    )
    write_lines(run_dir / "port_scan_targets.txt", port_targets)
    write_json(run_dir / "port_scan_target_manifest.json", port_target_manifest)
    write_port_target_manifest_csv(run_dir / "port_scan_target_manifest.csv", port_target_manifest)

    naabu_result = None
    naabu_records: list[dict[str, Any]] = []
    naabu_rejected_records: list[dict[str, Any]] = []
    nmap_results: list[Any] = []
    nmap_records: list[dict[str, Any]] = []
    port_reconciliation: list[dict[str, Any]] = []
    nmap_task_map: dict[str, str] = {}
    if port_scan_requested and port_targets and naabu_image_ready:
        print(f"[+] Stage 6: Naabu TCP CONNECT scan on {len(port_targets)} selected hosts")
        naabu_command = build_naabu_command(
            run_dir,
            top_ports=args.naabu_top_ports,
            ports=args.naabu_ports,
            rate=args.naabu_rate,
            threads=args.naabu_threads,
            retries=args.naabu_retries,
            socket_timeout_ms=args.naabu_socket_timeout,
            scan_all_ips=bool(args.naabu_scan_all_ips),
        )
        naabu_result = run_cmd(
            "naabu_port_scan",
            naabu_command,
            logs_dir,
            max(60, args.port_scan_timeout),
            metadata={
                "targets": len(port_targets),
                "scan_type": "connect",
                "top_ports": args.naabu_top_ports if not args.naabu_ports else None,
                "custom_ports": args.naabu_ports,
                "cdn_exclusion_defense_in_depth": True,
            },
        )
        tool_results.append(naabu_result)
        required_names.add("naabu_port_scan")
        naabu_output = run_dir / "naabu_ports.jsonl"
        raw_naabu_output = run_dir / "naabu_ports_raw.jsonl"
        if naabu_output.exists():
            shutil.copyfile(naabu_output, raw_naabu_output)
        naabu_records = parse_naabu_jsonl(
            naabu_output,
            rejected_path=run_dir / "naabu_rejected_records.jsonl",
        )
        naabu_rejected_records = read_jsonl(run_dir / "naabu_rejected_records.jsonl")
        # Preserve raw tool output separately and make the compatibility JSONL
        # contain only normalized valid candidate records.
        try:
            naabu_output.unlink(missing_ok=True)
        except Exception:
            pass
        write_jsonl(naabu_output, naabu_records)

        open_ports_by_host = group_open_ports(naabu_records)
        if args.nmap_service_scan and open_ports_by_host and nmap_image_ready:
            nmap_dir = run_dir / "nmap"
            nmap_dir.mkdir(parents=True, exist_ok=True)
            nmap_tasks: list[tuple[str, list[str], str | None, dict[str, object]]] = []
            for host, ports in sorted(open_ports_by_host.items()):
                stem = safe_output_stem(host)
                output_file = f"nmap/{stem}.xml"
                nmap_task_map[f"{stem}.xml"] = host
                task_name = f"nmap_{stem}"[:80]
                nmap_tasks.append((
                    task_name,
                    build_nmap_command(
                        run_dir,
                        target=host,
                        ports=ports,
                        output_file=output_file,
                        host_timeout=args.nmap_host_timeout,
                    ),
                    None,
                    {"target": host, "ports": ports, "output_file": output_file},
                ))
                required_names.add(task_name)
            print(f"[+] Stage 7: Nmap service validation on {len(nmap_tasks)} hosts")
            nmap_results = run_parallel(
                nmap_tasks,
                logs_dir,
                max(60, args.port_scan_timeout),
                max(1, args.nmap_workers),
            )
            tool_results.extend(nmap_results)
            nmap_records = parse_nmap_directory(nmap_dir)
            for record in nmap_records:
                requested_target = nmap_task_map.get(str(record.get("source_file") or ""))
                if requested_target:
                    record["requested_target"] = requested_target
                    record["target"] = requested_target

    port_reconciliation = reconcile_port_candidates(
        naabu_records=naabu_records,
        nmap_records=nmap_records,
        nmap_results=nmap_results,
        nmap_requested=bool(args.nmap_service_scan),
    )
    write_json(run_dir / "naabu_ports.json", naabu_records)
    write_naabu_csv(run_dir / "naabu_ports.csv", naabu_records)
    write_json(run_dir / "nmap_services.json", nmap_records)
    write_nmap_csv(run_dir / "nmap_services.csv", nmap_records)
    write_json(run_dir / "port_candidate_reconciliation.json", port_reconciliation)
    write_port_reconciliation_csv(run_dir / "port_candidate_reconciliation.csv", port_reconciliation)
    port_scan_summary = summarize_port_scan(
        requested=port_scan_requested,
        targets=port_targets,
        target_manifest=port_target_manifest,
        naabu_records=naabu_records,
        naabu_rejected_records=naabu_rejected_records,
        naabu_ok=(naabu_result.ok if naabu_result is not None else (False if port_scan_requested and port_targets else None)),
        nmap_requested=bool(args.nmap_service_scan),
        nmap_records=nmap_records,
        nmap_tasks=len(nmap_results),
        nmap_completed=sum(1 for result in nmap_results if result.ok),
        reconciliation=port_reconciliation,
    )
    port_scan_summary["configuration"] = {
        "target_limit": args.port_scan_limit,
        "top_ports": args.naabu_top_ports if not args.naabu_ports else None,
        "custom_ports": args.naabu_ports,
        "rate": args.naabu_rate,
        "threads": args.naabu_threads,
        "retries": args.naabu_retries,
        "socket_timeout_ms": args.naabu_socket_timeout,
        "scan_all_ips": bool(args.naabu_scan_all_ips),
        "include_cdn": bool(args.port_scan_include_cdn),
        "include_third_party": bool(args.port_scan_include_third_party),
        "nmap_host_timeout": args.nmap_host_timeout,
        "nmap_workers": args.nmap_workers,
    }
    write_json(run_dir / "port_scan_summary.json", port_scan_summary)

    # Only target-controlled content is eligible for private-IP leak reporting.
    internal_ip_leaks = extract_internal_ip_leaks_from_lines(
        katana_urls,
        "katana_target_urls",
        evidence_origin="target_response",
    )
    internal_ip_leaks.extend(extract_internal_ip_leaks_from_http_records(http_records))
    unique_leaks = {
        (str(item.get("ip")), str(item.get("source")), str(item.get("evidence"))): item
        for item in internal_ip_leaks
        if item.get("evidence_origin") == "target_response"
    }
    internal_ip_leaks = list(unique_leaks.values())
    write_json(run_dir / "internal_ip_leaks.json", internal_ip_leaks)

    write_confirmed_csv(run_dir / "validated_dns_hosts.csv", validated_dns)
    write_confirmed_csv(run_dir / "confirmed_subdomains.csv", validated_dns)

    priority_coverage = {
        "input_total": len(priority_candidates),
        "complete": priority_result.ok,
        "coverage_percent": 100.0 if priority_result.ok else 0.0,
    }
    failed_required = _required_failures(tool_results, required_names)
    if args.shodan_passive and str(shodan_summary.get("status") or "") in {"PARTIAL", "FAILED"}:
        failed_required.append("shodan_passive")
    if recursive_summary.get("requested") and str(recursive_summary.get("status") or "") in {"PARTIAL", "FAILED"}:
        failed_required.append("recursive_recon")
    if port_scan_requested and port_targets and not naabu_image_ready:
        failed_required.append("naabu_image_unavailable")
    if args.nmap_service_scan and naabu_records and not nmap_image_ready:
        failed_required.append("nmap_image_unavailable")
    failed_required = sorted(set(failed_required))
    dns_complete = priority_result.ok and bool(dns_coverage.get("complete")) and wildcard_result.ok
    canonical_reachable = root_probe_result.ok and _root_probe_is_reachable(root_probe_records, target)
    passive_discovery_ok = any(
        result.ok for result in stage1_results
        if result.name in {"subfinder", "amass", "gobuster_base", "bbot"}
    )
    overall_status = determine_run_health(
        failed_required=failed_required,
        dns_complete=dns_complete,
        canonical_reachable=canonical_reachable,
        passive_discovery_ok=passive_discovery_ok,
    )

    summary = {
        "program_version": "8.5.1-normalization-fixed",
        "target": target,
        "run_dir": str(run_dir.resolve()),
        "created_at": dt.datetime.now().isoformat(timespec="seconds"),
        "authorized_flag": args.authorized,
        "overall_status": overall_status,
        "results_are_partial": overall_status != "COMPLETE",
        "failed_required_stages": failed_required,
        "mode": "exhaustive" if args.exhaustive else ("max" if args.max else "normal"),
        "canonical_target": {"url": canonical_url, "evidence": canonical_evidence},
        "canonical_target_reachable": canonical_reachable,
        "katana_configuration": katana_config,
        "edge_detection": edge_summary,
        "port_scan": port_scan_summary,
        "shodan_passive": shodan_summary,
        "recursive_recon": recursive_summary,
        "active_waf_configuration": {
            "requested": bool(args.active_waf),
            "image": WAFW00F_IMAGE,
            "image_ready": waf_image_ready,
            "target_limit": args.waf_limit,
            "targets_selected": len(waf_targets),
            "request_timeout": args.waf_request_timeout,
            "stage_timeout": args.waf_stage_timeout,
            "find_all": bool(args.waf_find_all),
            "include_third_party": bool(args.waf_include_third_party),
        },
        "candidate_generation": candidate_stats,
        "dns_coverage": {
            "priority": priority_coverage,
            "bulk": dns_coverage,
        },
        "auto_workers": {
            "cpu_count": os.cpu_count() or 2,
            "selected_tool_workers": workers,
            "pull_workers": pull_workers,
            "dnsx_workers": args.dnsx_workers,
        },
        "image_status": image_status,
        "tool_version_manifest": "tool_versions.json",
        "command_manifest": "command_manifest.json",
        "tools": [result.to_dict() for result in tool_results],
        "counts": {
            "katana_urls": len(set(katana_urls)),
            "raw_subdomains": len(raw_subdomains),
            "accepted_keywords": len(keyword_evidence),
            "rejected_keywords": len(rejected_keywords),
            "priority_candidates": len(priority_candidates),
            "bulk_candidates": len(bulk_candidates),
            "candidates": len(candidates),
            "validated_dns_hosts": len(validated_dns),
            "wildcard_suspected_hosts": len(wildcard_suspected),
            "carried_forward_unvalidated": len(carried_forward),
            "http_assets_classified": len(classified_assets),
            "cdn_detected_assets": edge_summary.get("counts", {}).get("cdn_detected", 0),
            "passive_waf_detected_assets": edge_summary.get("counts", {}).get("passive_waf_detected", 0),
            "active_waf_detected_assets": edge_summary.get("counts", {}).get("active_waf_detected", 0),
            "unique_technologies": edge_summary.get("counts", {}).get("technologies_unique", 0),
            "port_scan_targets": len(port_targets),
            "naabu_candidate_port_records": len(naabu_records),
            "naabu_rejected_records": len(naabu_rejected_records),
            "hosts_with_naabu_candidates": len(group_open_ports(naabu_records)),
            "nmap_service_records": len(nmap_records),
            "nmap_confirmed_open_ports": int((port_scan_summary.get("reconciliation") or {}).get("confirmed_open") or 0),
            # Backward-compatible aliases.
            "naabu_open_port_records": len(naabu_records),
            "hosts_with_open_ports": len(group_open_ports(naabu_records)),
            "shodan_discovered_hosts": len(shodan_summary.get("discovered_hosts") or []),
            "shodan_discovered_ips": len(shodan_summary.get("discovered_ips") or []),
            "shodan_services_collected": int(shodan_summary.get("services_collected") or 0),
            "shodan_assets_enriched": int(shodan_summary.get("assets_enriched") or 0),
            "shodan_vulnerabilities_observed": int(shodan_summary.get("unique_vulnerabilities_observed") or 0),
            "recursive_hosts_crawled": int(recursive_summary.get("hosts_crawled") or 0),
            "recursive_hosts_discovered": int(recursive_summary.get("hosts_discovered") or 0),
            "recursive_new_hosts_validated": int(recursive_summary.get("new_hosts_validated") or 0),
            "recursive_boundary_hosts": int(recursive_summary.get("boundary_host_count") or 0),
            "raw_katana_urls_before_normalization": endpoint_summary.get("total_raw_unique_urls", 0),
            "normalized_in_scope_endpoints": endpoint_summary.get("total_normalized_in_scope_urls", 0),
            "external_references": len(endpoint_summary.get("external_references", [])),
            "openapi_candidates": len(endpoint_summary.get("openapi_candidates", [])),
            "internal_ip_leaks": len(internal_ip_leaks),
            "screenshot_files": len(screenshot_files),
            "screenshot_json_records": screenshot_status.get("json_records", 0),
            "browser_new_hosts": len(browser_new_hosts),
            "browser_validated_hosts": len(browser_validated),
        },
        "wildcard_check": wildcard_info,
        "screenshot_status": screenshot_status,
    }
    _write_command_manifest(run_dir, tool_results)
    write_json(run_dir / "summary.json", summary)
    write_json(run_dir / "autotune.json", summary["auto_workers"])

    make_report_md(
        run_dir / "final_report.md",
        target=target,
        run_dir=run_dir,
        summary=summary,
        tool_results=tool_results,
        validated=validated_dns,
        wildcard_suspected=wildcard_suspected,
        keyword_evidence=keyword_evidence,
        rejected_keyword_count=len(rejected_keywords),
        classified_assets=classified_assets,
        edge_summary=edge_summary,
        port_scan_summary=port_scan_summary,
        endpoint_summary=endpoint_summary,
        screenshot_files=screenshot_files,
        screenshot_status=screenshot_status,
        carried_forward=carried_forward,
        internal_ip_leaks=internal_ip_leaks,
        browser_all_hosts=sorted(browser_all_hosts),
        browser_new_hosts=sorted(browser_new_hosts),
        browser_validated_hosts=sorted(browser_validated),
        browser_discovered_urls=sorted(browser_urls),
    )

    print(f"[+] Completed with status: {overall_status}")
    print(f"[+] DNS-validated hosts: {len(validated_dns)}")
    print(f"[+] Report: {(run_dir / 'final_report.md').resolve()}")
    if overall_status != "COMPLETE" and args.fail_on_partial:
        return 3
    return 0
