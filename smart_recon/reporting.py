"""CSV, Markdown, and summary generation."""

from __future__ import annotations

import csv
import datetime as dt
import json
from pathlib import Path
from typing import Any

from .models import ToolResult


def write_confirmed_csv(path: Path, confirmed: dict[str, dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "host", "validation_state", "a", "aaaa", "cname", "ttl",
                "wildcard_like", "wildcard_zone", "source_pipeline",
            ],
        )
        writer.writeheader()
        for host, obj in sorted(confirmed.items()):
            writer.writerow({
                "host": host,
                "validation_state": obj.get("validation_state", ""),
                "a": ",".join(obj.get("a", []) or []),
                "aaaa": ",".join(obj.get("aaaa", []) or []),
                "cname": ",".join(obj.get("cname", []) or []),
                "ttl": obj.get("ttl", ""),
                "wildcard_like": obj.get("wildcard_like", False),
                "wildcard_zone": obj.get("wildcard_zone", ""),
                "source_pipeline": obj.get("source_pipeline", ""),
            })


def _md_escape(value: Any) -> str:
    return str(value or "").replace("|", r"\|").replace("\n", " ")


def make_report_md(
    path: Path,
    *,
    target: str,
    run_dir: Path,
    summary: dict[str, Any],
    tool_results: list[ToolResult],
    validated: dict[str, dict[str, Any]],
    wildcard_suspected: dict[str, dict[str, Any]],
    keyword_evidence: dict[str, dict[str, Any]],
    rejected_keyword_count: int,
    classified_assets: list[dict[str, Any]],
    edge_summary: dict[str, Any],
    port_scan_summary: dict[str, Any],
    endpoint_summary: dict[str, Any],
    screenshot_files: list[str],
    screenshot_status: dict[str, Any],
    carried_forward: dict[str, dict[str, Any]],
    internal_ip_leaks: list[dict[str, str]],
    browser_all_hosts: list[str],
    browser_new_hosts: list[str],
    browser_validated_hosts: list[str],
    browser_discovered_urls: list[str],
) -> None:
    overall_status = str(summary.get("overall_status") or "UNKNOWN")
    lines: list[str] = [
        f"# Smart Subdomain Recon Report: `{target}`",
        "",
        f"**Overall run status: `{overall_status}`**",
        "",
        f"Run folder: `{run_dir}`",
        f"Generated: `{dt.datetime.now().isoformat(timespec='seconds')}`",
    ]
    if overall_status != "COMPLETE":
        lines += [
            "",
            "> **Important:** One or more required stages did not complete. Counts and findings below are partial and must not be treated as complete coverage.",
        ]

    candidate_stats = summary.get("candidate_generation", {})
    bulk_coverage = summary.get("dns_coverage", {}).get("bulk", {})
    lines += [
        "",
        "## Run health and coverage",
        "",
        f"- Mode: `{summary.get('mode')}`",
        f"- Canonical crawl target: `{summary.get('canonical_target', {}).get('url', '')}`",
        f"- Candidates selected: `{candidate_stats.get('selected_after_limit', 0)}`",
        f"- Candidates generated before cap: `{candidate_stats.get('generated_before_limit', 0)}`",
        f"- Candidate list truncated: `{candidate_stats.get('truncated', False)}`",
        f"- Bulk DNS coverage: `{bulk_coverage.get('completed_input', 0)}/{bulk_coverage.get('input_total', 0)}` (`{bulk_coverage.get('coverage_percent', 0)}%`)",
        f"- DNSX chunks completed: `{bulk_coverage.get('chunks_completed', 0)}/{bulk_coverage.get('chunks_total', 0)}`",
    ]
    failed_required = summary.get("failed_required_stages", [])
    if failed_required:
        lines.append(f"- Failed required stages: `{', '.join(failed_required)}`")
    dns_coverage = summary.get("dns_coverage", {})
    zero_result_is_valid = (
        summary.get("counts", {}).get("validated_dns_hosts", 0) == 0
        and dns_coverage.get("priority", {}).get("complete") is True
        and dns_coverage.get("bulk", {}).get("complete") is True
        and summary.get("wildcard_check", {}).get("tool_status") == "OK"
    )
    if zero_result_is_valid:
        lines.append("- DNS outcome: `Valid zero-result` (the completed DNS stages found no child subdomains).")

    katana_config = summary.get("katana_configuration", {})
    if katana_config.get("requested", {}).get("enabled"):
        lines += [
            f"- Katana requested configuration: `{json.dumps(katana_config.get('requested', {}), ensure_ascii=False)}`",
            f"- Katana effective configuration: `{json.dumps(katana_config.get('effective', {}), ensure_ascii=False)}`",
        ]
        for note in katana_config.get("notes", []):
            lines.append(f"- Katana adjustment: {_md_escape(note)}")

    lines += [
        "",
        "## Tool status",
        "",
        "| Tool | Status | OK | Timed out | Warnings | Errors | Seconds | Return code |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for result in tool_results:
        lines.append(
            f"| {result.name} | {result.status} | {result.ok} | {result.timed_out} | "
            f"{len(result.warnings)} | {len(result.errors)} | {result.seconds:.2f} | {result.returncode} |"
        )

    diagnostic_results = [result for result in tool_results if result.warnings or result.errors]
    if diagnostic_results:
        lines += ["", "### Tool diagnostics", ""]
        for result in diagnostic_results:
            lines.append(f"#### `{result.name}`")
            for warning in result.warnings[:5]:
                lines.append(f"- Warning: `{_md_escape(warning)}`")
            for error in result.errors[:5]:
                lines.append(f"- Error: `{_md_escape(error)}`")
            lines.append("")

    lines += [
        "## Wildcard analysis",
        "",
        f"Zones tested: `{summary.get('wildcard_check', {}).get('zones_tested', 0)}`",
        f"Random probes sent: `{summary.get('wildcard_check', {}).get('probe_count', 0)}`",
        "",
        "| Zone | Wildcard answer | Answers | Matching signature probes |",
        "|---|---:|---:|---:|",
    ]
    for zone, info in sorted(summary.get("wildcard_check", {}).get("zones", {}).items()):
        lines.append(
            f"| `{zone}` | {info.get('has_wildcard_answer', False)} | "
            f"{info.get('answers', 0)} | {info.get('matching_signature_count', 0)} |"
        )

    lines += ["", f"## DNS-validated assets ({len(validated)})", ""]
    for host, obj in sorted(validated.items()):
        lines.append(
            f"- `{host}` state=`{obj.get('validation_state', '')}` "
            f"A=[{', '.join(obj.get('a', []) or [])}] "
            f"CNAME=[{', '.join(obj.get('cname', []) or [])}]"
        )

    if wildcard_suspected:
        lines += ["", f"## Wildcard-suspected assets ({len(wildcard_suspected)})", ""]
        lines.append("These records matched repeated random-label DNS answers. Generated names are not treated as independent confirmed applications.")
        for host, obj in sorted(wildcard_suspected.items()):
            lines.append(
                f"- `{host}` state=`{obj.get('validation_state', '')}` zone=`{obj.get('wildcard_zone', '')}`"
            )

    if carried_forward:
        lines += ["", f"## Previous-run assets not currently validated ({len(carried_forward)})", ""]
        lines.append("These hosts were observed previously but did not produce a current validated DNS record. They remain historical evidence and are excluded from active validation counts.")
        for host in sorted(carried_forward):
            lines.append(f"- `{host}` current_state=`not_dns_validated` active_testing=`excluded`")

    ranked_keywords = sorted(
        keyword_evidence.items(),
        key=lambda item: (-int(item[1].get("score", 0)), item[0]),
    )
    lines += [
        "",
        f"## Accepted keyword evidence ({len(keyword_evidence)})",
        "",
        f"Rejected noisy/random tokens: `{rejected_keyword_count}`",
        "",
        "| Keyword | Score | Source(s) |",
        "|---|---:|---|",
    ]
    for keyword, evidence in ranked_keywords[:200]:
        sources = evidence.get("sources") or [evidence.get("source")]
        lines.append(f"| `{keyword}` | {evidence.get('score', '')} | {_md_escape(', '.join(str(value) for value in sources if value))} |")

    edge_counts = edge_summary.get("counts", {})
    active_waf = edge_summary.get("active_waf", {})
    lines += [
        "",
        "## CDN, Wappalyzer technology, and WAF detection",
        "",
        "Passive detection is always collected from HTTPX. Technology fingerprints come from HTTPX `-tech-detect` using the Wappalyzer dataset; CDN/WAF provider evidence comes primarily from HTTPX CDNCheck and DNS/CNAME context. Wappalyzer technology alone is supporting evidence, not proof of proxying.",
        "",
        f"- Assets with CDN evidence: `{edge_counts.get('cdn_detected', 0)}`",
        f"- Assets with any WAF/security-edge evidence: `{edge_counts.get('waf_detected_total', 0)}`",
        f"- Assets with passive WAF/security-edge evidence: `{edge_counts.get('passive_waf_detected', 0)}`",
        f"- Conflicting or multi-layer WAF attributions: `{edge_counts.get('waf_conflicting_or_multi_layer', 0)}`",
        f"- Generic active WAF detections: `{edge_counts.get('waf_generic_active', 0)}`",
        f"- Unique technologies detected: `{edge_counts.get('technologies_unique', 0)}`",
        f"- Active WAFW00F requested: `{active_waf.get('requested', False)}`",
        f"- Active WAFW00F targets: `{active_waf.get('targets_selected', 0)}`",
        f"- Active WAFW00F detections: `{edge_counts.get('active_waf_detected', 0)}`",
        "",
        "| Host | CDN | CDN confidence | WAF/security edge | WAF confidence | Attribution | Detection mode | Technologies |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for asset in classified_assets:
        cdn = asset.get("cdn_detection") or {}
        waf = asset.get("waf_detection") or {}
        technologies = ", ".join(asset.get("technologies") or [])
        lines.append(
            f"| `{asset.get('host', '')}` | {_md_escape(cdn.get('provider') or '')} | "
            f"{_md_escape(cdn.get('confidence') or 'none')} | {_md_escape(waf.get('provider') or '')} | "
            f"{_md_escape(waf.get('confidence') or 'none')} | {_md_escape(waf.get('attribution') or '')} | "
            f"{_md_escape(waf.get('mode') or 'passive')} | {_md_escape(technologies)} |"
        )

    shodan = summary.get("shodan_passive", {}) or {}
    shodan_credit = shodan.get("credit_ledger", {}) or {}
    lines += [
        "",
        "## Passive Shodan reconnaissance",
        "",
        "This stage queries Shodan's existing DNS, search, and host databases. It does not submit on-demand Shodan scans.",
        "",
        f"- Requested: `{shodan.get('requested', False)}`",
        f"- Status: `{shodan.get('status', 'NOT_REQUESTED')}`",
        f"- API key configured: `{shodan.get('api_key_configured', False)}`",
        f"- Shodan DNS records collected: `{shodan.get('dns_records', 0)}`",
        f"- Scoped dorks planned: `{shodan.get('dorks_planned', 0)}`",
        f"- Dorks with non-zero counts: `{shodan.get('dorks_with_results', 0)}`",
        f"- Estimated query credits spent: `{shodan_credit.get('estimated_spent', 0)}` / `{shodan_credit.get('configured_budget', 0)}`",
        f"- API-reported query-credit delta: `{shodan.get('api_query_credits_actual_delta')}`",
        f"- Host lookups completed: `{shodan.get('host_lookups_completed', 0)}`",
        f"- Services collected: `{shodan.get('services_collected', 0)}`",
        f"- Assets enriched: `{shodan.get('assets_enriched', 0)}`",
        f"- Unique vulnerability identifiers observed in Shodan metadata: `{shodan.get('unique_vulnerabilities_observed', 0)}`",
        "",
    ]
    if shodan.get("warnings"):
        lines.append("Warnings:")
        for warning in (shodan.get("warnings") or [])[:10]:
            lines.append(f"- {_md_escape(warning)}")
    if shodan.get("errors"):
        lines.append("Errors:")
        for error in (shodan.get("errors") or [])[:10]:
            lines.append(f"- {_md_escape(error)}")
    discovered_shodan_hosts = shodan.get("discovered_hosts") or []
    if discovered_shodan_hosts:
        lines += ["", f"Shodan-discovered in-scope hosts: `{len(discovered_shodan_hosts)}`"]
        for host in discovered_shodan_hosts[:50]:
            lines.append(f"- `{host}`")

    recursive = summary.get("recursive_recon", {}) or {}
    clusters: dict[str, list[str]] = {}
    try:
        clusters_value = json.loads((run_dir / "recon_clusters.json").read_text(encoding="utf-8"))
        if isinstance(clusters_value, dict):
            clusters = {str(key): [str(item) for item in (value or [])] for key, value in clusters_value.items()}
    except (OSError, json.JSONDecodeError):
        clusters = {}

    lines += [
        "",
        "## Recursive recon expansion, clustering, and topology",
        "",
        "The canonical root is level 0. Newly discovered in-scope web hosts are revalidated and crawled in parallel for at most three descendant levels. Third-party SaaS is retained as evidence but excluded from active recursive crawling.",
        "",
        f"- Requested: `{recursive.get('requested', False)}`",
        f"- Status: `{recursive.get('status', 'NOT_REQUESTED')}`",
        f"- Maximum descendant depth: `{recursive.get('max_depth', 0)}`",
        f"- Levels completed: `{recursive.get('levels_completed', 0)}`",
        f"- Parallel crawl workers: `{recursive.get('parallel_workers', 0)}`",
        f"- Hosts crawled: `{recursive.get('hosts_crawled', 0)}`",
        f"- In-scope hosts observed during expansion: `{recursive.get('hosts_discovered', 0)}`",
        f"- Newly DNS-validated hosts: `{recursive.get('new_hosts_validated', 0)}`",
        f"- URLs observed across canonical and recursive crawls: `{recursive.get('url_count', 0)}`",
        f"- Maximum-depth boundary hosts not followed: `{recursive.get('boundary_host_count', 0)}`",
        f"- Host-cap truncation: `{recursive.get('truncated_by_host_cap', False)}`",
        f"- Recursive screenshots skipped because the host was already captured: `{recursive.get('recursive_screenshot_skipped_existing_hosts', 0)}`",
        "",
        "### Expansion by level",
        "",
        "| Level | Crawled hosts | URLs observed | New hosts observed | New hosts validated | Next-level targets | Boundary |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for level_info in recursive.get("levels", []) or []:
        lines.append(
            f"| {level_info.get('level', '')} | {level_info.get('crawl_target_count', 0)} | "
            f"{level_info.get('urls_observed', 0)} | {level_info.get('new_hosts_observed', 0)} | "
            f"{level_info.get('new_hosts_validated', 0)} | {level_info.get('next_level_targets', 0)} | "
            f"{level_info.get('max_depth_boundary', False)} |"
        )

    lines += [
        "",
        "### Asset clusters",
        "",
        "| Cluster | Assets | Samples |",
        "|---|---:|---|",
    ]
    for cluster_name, hosts in sorted(clusters.items()):
        samples = "<br>".join(f"`{_md_escape(host)}`" for host in hosts[:8])
        lines.append(f"| `{cluster_name}` | {len(hosts)} | {samples} |")
    if not clusters:
        lines.append("|  | 0 |  |")

    mindmap = str(recursive.get("mindmap_mermaid") or "").strip()
    if mindmap:
        lines += [
            "",
            "### Recon mind map",
            "",
            "```mermaid",
            mindmap,
            "```",
            "",
            "The complete machine-readable graph is stored in `recon_topology.json`; the standalone Mermaid source is `recon_mindmap.mmd`.",
        ]

    lines += [
        "",
        "## HTTP probing and host classification",
        "",
        "| Host | Status | Title | Category | Priority | Edge response | Ownership | Application/SaaS provider | Network CDN | WAF | WAF attribution |",
        "|---|---:|---|---|---|---|---|---|---|---|---|",
    ]
    for asset in classified_assets:
        lines.append(
            f"| `{asset.get('host', '')}` | {asset.get('status_code', '')} | {_md_escape(asset.get('title'))} | "
            f"{_md_escape(asset.get('category'))} | {asset.get('priority', '')} | "
            f"{_md_escape(asset.get('edge_response_category'))} | {_md_escape(asset.get('ownership'))} | "
            f"{_md_escape(asset.get('application_provider') or asset.get('provider'))} | "
            f"{_md_escape(asset.get('network_provider') or (asset.get('cdn_detection') or {}).get('provider') or asset.get('cdn_name'))} | "
            f"{_md_escape((asset.get('waf_detection') or {}).get('provider'))} | "
            f"{_md_escape((asset.get('waf_detection') or {}).get('attribution'))} |"
        )

    port_targets = port_scan_summary.get("targets", {})
    naabu = port_scan_summary.get("naabu", {})
    nmap = port_scan_summary.get("nmap", {})
    reconciliation = port_scan_summary.get("reconciliation", {})
    lines += [
        "",
        "## Controlled port enumeration",
        "",
        "This stage is opt-in. DNS CNAME ownership is evaluated before HTTP classification. Third-party delegated services, CDN/security edges, and unresolved ownership are excluded by default. Naabu reports candidate TCP ports; Nmap independently rechecks only valid candidates. A Naabu result is not treated as confirmed open until Nmap reports the port state as `open`.",
        "",
        f"- Requested: `{port_scan_summary.get('requested', False)}`",
        f"- Targets selected: `{port_targets.get('selected', 0)}`",
        f"- Targets excluded: `{port_targets.get('excluded', 0)}`",
        f"- Naabu candidate hosts: `{naabu.get('hosts_with_candidates', 0)}`",
        f"- Naabu candidate ports: `{naabu.get('candidate_ports_total', 0)}`",
        f"- Rejected invalid Naabu records: `{naabu.get('rejected_records', 0)}`",
        f"- Nmap validation requested: `{nmap.get('requested', False)}`",
        f"- Nmap port-state/service records: `{nmap.get('records', 0)}`",
        f"- Nmap-confirmed open ports: `{reconciliation.get('confirmed_open', 0)}`",
        f"- Nmap-not-confirmed candidates: `{reconciliation.get('not_confirmed', 0)}`",
        "",
        "| Host | Port | Naabu status | Nmap state | Final status | Service evidence |",
        "|---|---:|---|---|---|---|",
    ]
    candidate_results = reconciliation.get("candidate_results") or []
    for item in candidate_results:
        service = " ".join(str(value) for value in (item.get("nmap_service"), item.get("nmap_product"), item.get("nmap_version")) if value)
        lines.append(
            f"| `{item.get('host', '')}` | {item.get('port', '')} | `{item.get('candidate_status', 'NAABU_CANDIDATE')}` | "
            f"`{item.get('nmap_state') or ''}` | `{item.get('final_status', '')}` | {_md_escape(service)} |"
        )
    if not candidate_results:
        lines.append("|  |  |  |  |  |  |")

    lines += [
        "",
        "## Endpoint classification across canonical and recursive crawls",
        "",
        f"Raw unique URLs seen: `{endpoint_summary.get('total_raw_unique_urls', 0)}`",
        f"Normalized in-scope endpoints: `{endpoint_summary.get('total_normalized_in_scope_urls', 0)}`",
        f"Deduplicated/filtered/malformed/external: `{endpoint_summary.get('deduplicated_or_filtered_urls', 0)}`",
        f"External references recorded but not crawled into candidate generation: `{len(endpoint_summary.get('external_references', []))}`",
        f"OpenAPI/Swagger candidates: `{len(endpoint_summary.get('openapi_candidates', []))}`",
        "",
        "| Category | Count | Priority | Samples |",
        "|---|---:|---|---|",
    ]
    for category, info in sorted(
        endpoint_summary.get("categories", {}).items(),
        key=lambda item: (-item[1].get("count", 0), item[0]),
    ):
        samples = "<br>".join(f"`{_md_escape(value)}`" for value in (info.get("samples") or [])[:5])
        lines.append(f"| {category} | {info.get('count', 0)} | {info.get('priority', '')} | {samples} |")

    if endpoint_summary.get("openapi_candidates"):
        lines += ["", "### OpenAPI/Swagger candidates", ""]
        lines.append("These are structured API-document candidates for a later dedicated parser; they are not counted as multiple endpoints after URL normalization.")
        for value in endpoint_summary.get("openapi_candidates", [])[:50]:
            lines.append(f"- `{value}`")

    lines += ["", "## Internal IP leak / private address references", ""]
    if internal_ip_leaks:
        lines += ["| IP | Source | Evidence origin | Evidence |", "|---|---|---|---|"]
        for leak in internal_ip_leaks[:50]:
            evidence = _md_escape(str(leak.get("evidence", ""))[:160])
            lines.append(
                f"| `{leak.get('ip')}` | {leak.get('source')} | {leak.get('evidence_origin')} | `{evidence}` |"
            )
    else:
        lines.append("No private IP reference was found in fields classified as target-controlled response content.")

    screenshot_artifacts = screenshot_status.get("artifact_summary") or {}
    lines += [
        "",
        "## Screenshot capture",
        "",
        f"Screenshot execution status: `{screenshot_status.get('status')}`",
        f"Eligible unique hosts: `{screenshot_status.get('eligible_unique_hosts', screenshot_status.get('eligible_urls', 0))}`",
        f"Selected unique hosts: `{screenshot_status.get('selected_unique_hosts', screenshot_status.get('selected_urls', screenshot_status.get('input_urls', 0)))}`",
        f"Skipped by configured limit: `{screenshot_status.get('skipped_by_limit', 0)}`",
        f"Coverage: `{screenshot_status.get('coverage_percent', 0)}%`",
        f"Main screenshot JSON records: `{screenshot_status.get('json_records', 0)}`",
        f"Unique hosts captured: `{screenshot_artifacts.get('unique_hosts_captured', 0)}`",
        f"Unique screenshot contents: `{screenshot_artifacts.get('unique_content_images', 0)}`",
        f"Total screenshot artifacts retained: `{screenshot_artifacts.get('total_artifact_files', len(screenshot_files))}`",
        f"Duplicate-content artifacts: `{screenshot_artifacts.get('duplicate_content_artifacts', 0)}`",
    ]
    if screenshot_status.get("selection_policy"):
        lines.append(f"- Selection policy: {screenshot_status.get('selection_policy')}")
    for note in screenshot_status.get("notes", [])[:8]:
        lines.append(f"- {note}")
    for screenshot in screenshot_files[:50]:
        lines.append(f"- `{screenshot}`")

    lines += [
        "",
        "## Browser-rendered host/API discovery",
        "",
        f"Target-scope URLs observed by browser: `{len(browser_discovered_urls)}`",
        f"All target-scope hosts observed by browser: `{len(browser_all_hosts)}`",
        f"New browser-only hosts: `{len(browser_new_hosts)}`",
        f"New browser-only hosts validated by DNS: `{len(browser_validated_hosts)}`",
    ]
    for host in browser_new_hosts[:50]:
        lines.append(f"- `{host}`")

    lines += [
        "",
        "## Manual VAPT review plan",
        "",
        "> These are review tasks, not vulnerability claims. Perform only with explicit authorization and test accounts.",
        "",
    ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for asset in classified_assets:
        grouped.setdefault(str(asset.get("category") or "Unknown"), []).append(asset)
    for category, assets in sorted(grouped.items()):
        lines.append(f"### {category}")
        for asset in assets[:12]:
            lines.append(
                f"- `{asset.get('host')}` status=`{asset.get('status_code')}` "
                f"title=`{_md_escape(asset.get('title'))}` ownership=`{asset.get('ownership')}`"
            )
            for note in asset.get("review_notes", [])[:4]:
                lines.append(f"  - {note}")
        lines.append("")

    lines += [
        "## Output files",
        "",
        "- `summary.json`",
        "- `command_manifest.json`",
        "- `tool_versions.json`",
        "- `validated_dns_hosts.txt` / `.json` / `.csv`",
        "- `wildcard_suspected_hosts.json`",
        "- `wildcard_check.json`",
        "- `candidate_manifest.jsonl` / `.csv`",
        "- `keyword_evidence.json`",
        "- `rejected_keywords.json`",
        "- `dnsx_chunk_manifest.json`",
        "- `canonical_target.json`",
        "- `katana_urls.txt`",
        "- `endpoint_classification.json`",
        "- `external_references.txt`",
        "- `openapi_candidates.txt`",
        "- `httpx_probe.jsonl`",
        "- `http_review_classification.json` / `.csv`",
        "- `edge_detection_summary.json`",
        "- `waf_targets.txt`",
        "- `waf_detection.json` / `.csv`",
        "- `wafw00f.json` when active WAF fingerprinting is enabled",
        "- `port_scan_target_manifest.json` / `.csv`",
        "- `port_scan_targets.txt`",
        "- `naabu_ports_raw.jsonl` (unaltered tool evidence when available)",
        "- `naabu_ports.jsonl` / `.json` / `.csv` (normalized valid candidates)",
        "- `naabu_rejected_records.jsonl`",
        "- `nmap/*.xml` when Nmap service validation is enabled",
        "- `nmap_services.json` / `.csv`",
        "- `port_candidate_reconciliation.json` / `.csv`",
        "- `port_scan_summary.json`",
        "- `shodan_summary.json` / `shodan_api_info.json` / `shodan_credit_ledger.json`",
        "- `shodan_dork_plan.json` / `shodan_dork_counts.json`",
        "- `shodan_dns_domain.jsonl` / `shodan_search_results.jsonl` / `shodan_host_lookups.jsonl`",
        "- `shodan_services.jsonl` / `shodan_assets.json` / `shodan_ports.csv` / `shodan_vulnerabilities.json`",
        "- `shodan_discovered_hosts.txt` / `shodan_search_filters.json` / `shodan_host_no_data.jsonl`",
        "- `recursive_recon_summary.json` / `recursive_hosts_by_level.json` / `recursive_urls_all.txt`",
        "- `recon_topology.json` / `recon_clusters.json` / `recon_mindmap.mmd`",
        "- `recursive/level_*/` per-level DNS, HTTP, Katana, screenshot, and Shodan evidence",
        "- `screenshot_status.json`",
        "- `internal_ip_leaks.json`",
        "- `final_report.md`",
        "",
        "Compatibility aliases are also retained as `confirmed_subdomains.*`.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
