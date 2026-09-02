#!/usr/bin/env python3
"""Build one integrated report from Recon, Normalization, and Technology stages.

This script is intentionally read-only with respect to scan evidence. It reads the
latest authorized recon run and writes a single Markdown report inside that run.
It uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

PROGRAM_VERSION = "10.0.0"
DEFAULT_OUTPUT_NAME = "combined_vapt_intelligence_report.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Combine V8.x recon, V9 normalization, and V9.2 technology "
            "intelligence into one Markdown report."
        )
    )
    parser.add_argument("--target", required=True, help="Authorized root domain, e.g. hiapp.pk")
    parser.add_argument(
        "--latest-root",
        default="./recon_runs",
        help="Folder containing <target>-<timestamp> run directories.",
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Optional exact run directory. When supplied, latest-run discovery is skipped.",
    )
    parser.add_argument(
        "--output-name",
        default=DEFAULT_OUTPUT_NAME,
        help=f"Output filename inside the run directory (default: {DEFAULT_OUTPUT_NAME}).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing report with the same name.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Do not append the three original source reports.",
    )
    parser.add_argument(
        "--max-assets",
        type=int,
        default=250,
        help="Maximum asset rows in the integrated asset table (default: 250).",
    )
    return parser.parse_args()


def normalize_target(value: str) -> str:
    target = value.strip().lower().rstrip(".")
    if not target or "/" in target or "\\" in target or " " in target:
        raise ValueError(f"Invalid target domain: {value!r}")
    return target


def load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read valid JSON from {path}: {exc}") from exc


def load_text(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise RuntimeError(f"Unable to read {path}: {exc}") from exc


def select_run_dir(target: str, latest_root: Path, exact_run_dir: str | None) -> Path:
    if exact_run_dir:
        run_dir = Path(exact_run_dir).expanduser().resolve()
        if not run_dir.is_dir():
            raise FileNotFoundError(f"Run directory does not exist: {run_dir}")
        return run_dir

    root = latest_root.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Recon root does not exist: {root}")

    candidates: list[Path] = []
    prefix = f"{target}-"
    for item in root.iterdir():
        if item.is_dir() and item.name.lower().startswith(prefix):
            candidates.append(item)

    if not candidates:
        raise FileNotFoundError(f"No run folder matching {prefix}* was found in {root}")

    def sort_key(path: Path) -> tuple[float, str]:
        try:
            modified = path.stat().st_mtime
        except OSError:
            modified = 0.0
        return modified, path.name

    candidates.sort(key=sort_key, reverse=True)
    return candidates[0]


def md(value: Any) -> str:
    """Escape a scalar for use in a Markdown table cell."""
    if value is None:
        return "—"
    if isinstance(value, bool):
        text = "Yes" if value else "No"
    elif isinstance(value, (list, tuple, set)):
        text = ", ".join(str(item) for item in value) if value else "—"
    else:
        text = str(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return text.strip() or "—"


def code(value: Any) -> str:
    text = md(value)
    if text == "—":
        return text
    return f"`{text.replace('`', "'")}`"


def count_nested(mapping: dict[str, Any], *keys: str, default: int = 0) -> int:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return int(current) if isinstance(current, (int, float)) else default


def compact_note(record: dict[str, Any], limit: int = 180) -> str:
    candidates: list[Any] = []
    for key in ("reason", "error", "message", "detail", "stderr_tail", "stderr", "notes"):
        candidates.append(record.get(key))

    execution = record.get("execution")
    if isinstance(execution, dict):
        candidates.extend([execution.get("stderr"), execution.get("error"), execution.get("message")])

    for lane_name in ("full", "balanced"):
        lane = record.get(lane_name)
        if not isinstance(lane, dict):
            continue
        candidates.extend([lane.get("reason"), lane.get("stderr_tail"), lane.get("error")])
        lane_execution = lane.get("execution")
        if isinstance(lane_execution, dict):
            candidates.extend(
                [lane_execution.get("stderr"), lane_execution.get("error"), lane_execution.get("message")]
            )

    for value in candidates:
        if isinstance(value, list):
            value = "; ".join(str(item) for item in value if item)
        if value:
            text = re.sub(r"\s+", " ", str(value)).strip()
            return text if len(text) <= limit else text[: limit - 1] + "…"
    return ""


def tool_rows(tool_status: dict[str, Any]) -> list[tuple[str, str, Any, str]]:
    rows: list[tuple[str, str, Any, str]] = []
    tools = tool_status.get("tools", {}) if isinstance(tool_status, dict) else {}
    if not isinstance(tools, dict):
        return rows
    for name, value in tools.items():
        if not isinstance(value, dict):
            continue
        status = str(value.get("status", "UNKNOWN"))
        targets = value.get("targets", value.get("target_count", value.get("records", "—")))
        if isinstance(targets, list):
            targets = len(targets)
        rows.append((str(name), status, targets, compact_note(value)))
    return rows


def route_counts(eligibility: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in eligibility:
        routes = row.get("routes", {})
        if not isinstance(routes, dict):
            continue
        for route, enabled in routes.items():
            if enabled:
                counts[str(route)] += 1
    return counts


def demote_headings(markdown: str, levels: int = 2) -> str:
    """Nest a Markdown document without changing headings inside fenced blocks."""
    output: list[str] = []
    in_fence = False
    fence_marker = ""
    for line in markdown.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = ""
            output.append(line)
            continue
        if not in_fence:
            match = re.match(r"^(#{1,6})(\s+.*)$", line)
            if match:
                hashes = "#" * min(6, len(match.group(1)) + levels)
                line = hashes + match.group(2)
        output.append(line)
    return "\n".join(output).strip()


def status_icon(status: str) -> str:
    normalized = status.upper()
    if normalized in {"COMPLETE", "OK", "PASS", "SUCCESS"}:
        return "COMPLETE"
    if normalized in {"PARTIAL", "DEGRADED", "WARNING"}:
        return "PARTIAL"
    if normalized in {"MISSING", "FAILED", "ERROR"}:
        return normalized
    return normalized or "UNKNOWN"


def build_report(run_dir: Path, target: str, summary_only: bool, max_assets: int) -> str:
    recon_summary_path = run_dir / "summary.json"
    recon_report_path = run_dir / "final_report.md"

    norm_dir = run_dir / "normalization_v9"
    norm_summary_path = norm_dir / "normalization_summary.json"
    norm_assets_path = norm_dir / "asset_inventory.json"
    norm_services_path = norm_dir / "service_inventory.json"
    norm_endpoints_path = norm_dir / "endpoint_inventory.json"
    norm_conflicts_path = norm_dir / "asset_conflicts.json"
    norm_queue_path = norm_dir / "asset_revalidation_queue.json"
    eligibility_path = norm_dir / "testing_eligibility.json"
    norm_report_path = norm_dir / "asset_normalization_report.md"

    tech_dir = run_dir / "technology_enrichment_v9_2"
    tech_summary_path = tech_dir / "technology_enrichment_summary.json"
    tech_inventory_path = tech_dir / "technology_inventory.json"
    tech_services_path = tech_dir / "service_inventory_enriched.json"
    tech_conflicts_path = tech_dir / "technology_conflicts.json"
    tech_queue_path = tech_dir / "technology_revalidation_queue.json"
    tech_tools_path = tech_dir / "technology_tool_status.json"
    tech_report_path = tech_dir / "technology_enrichment_report.md"

    cve_dir = run_dir / "cve_detection"
    cve_summary_path = cve_dir / "cve_summary.json"
    cve_findings_path = cve_dir / "cve_findings.json"
    cve_report_path = cve_dir / "cve_report.md"

    recon = load_json(recon_summary_path, {})
    norm_summary = load_json(norm_summary_path, {})
    assets = load_json(norm_assets_path, [])
    services = load_json(norm_services_path, [])
    endpoints = load_json(norm_endpoints_path, [])
    norm_conflicts = load_json(norm_conflicts_path, [])
    norm_queue = load_json(norm_queue_path, [])
    eligibility = load_json(eligibility_path, [])

    tech_summary = load_json(tech_summary_path, {})
    technologies = load_json(tech_inventory_path, [])
    enriched_services = load_json(tech_services_path, [])
    tech_conflicts = load_json(tech_conflicts_path, [])
    tech_queue = load_json(tech_queue_path, [])
    tech_tools = load_json(tech_tools_path, {})

    cve_summary = load_json(cve_summary_path, {})
    cve_findings_raw = load_json(cve_findings_path, {})
    if isinstance(cve_findings_raw, dict):
        cve_findings = cve_findings_raw.get("findings", [])
    elif isinstance(cve_findings_raw, list):
        cve_findings = cve_findings_raw
    else:
        cve_findings = []
    if not isinstance(cve_findings, list):
        cve_findings = []
    cve_counts = cve_summary.get("counts", {}) if isinstance(cve_summary, dict) else {}
    cve_status = str(cve_summary.get("status", "COMPLETE" if cve_findings else ("NOT_RUN" if not cve_summary_path.is_file() else "COMPLETE")))

    if not isinstance(assets, list):
        assets = []
    if not isinstance(services, list):
        services = []
    if not isinstance(endpoints, list):
        endpoints = []
    if not isinstance(norm_conflicts, list):
        norm_conflicts = []
    if not isinstance(norm_queue, list):
        norm_queue = []
    if not isinstance(eligibility, list):
        eligibility = []
    if not isinstance(technologies, list):
        technologies = []
    if not isinstance(enriched_services, list):
        enriched_services = []
    if not isinstance(tech_conflicts, list):
        tech_conflicts = []
    if not isinstance(tech_queue, list):
        tech_queue = []

    recon_status = str(recon.get("overall_status", "MISSING" if not recon else "UNKNOWN"))
    normalization_status = "COMPLETE" if norm_summary and assets else "MISSING"
    technology_status = str(tech_summary.get("status", "MISSING" if not tech_summary else "UNKNOWN"))

    stage_statuses = [status_icon(recon_status), status_icon(normalization_status), status_icon(technology_status)]
    if "FAILED" in stage_statuses or "MISSING" in stage_statuses or "ERROR" in stage_statuses:
        combined_status = "INCOMPLETE"
    elif "PARTIAL" in stage_statuses:
        combined_status = "PARTIAL"
    else:
        combined_status = "COMPLETE"

    norm_counts = norm_summary.get("counts", {}) if isinstance(norm_summary, dict) else {}
    tech_counts = tech_summary.get("counts", {}) if isinstance(tech_summary, dict) else {}
    recon_counts = recon.get("counts", {}) if isinstance(recon, dict) else {}

    technologies_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in technologies:
        if isinstance(item, dict):
            technologies_by_host[str(item.get("host", ""))].append(item)

    current_services_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    service_source = enriched_services or services
    for item in service_source:
        if isinstance(item, dict) and item.get("current", True):
            current_services_by_host[str(item.get("host", ""))].append(item)

    category_counts = Counter(
        str(item.get("category", "Uncategorized"))
        for item in technologies
        if isinstance(item, dict)
    )
    exact_versions = [
        item
        for item in technologies
        if isinstance(item, dict) and item.get("version") not in (None, "", "NOT_EXPOSED")
    ]
    version_hidden = sum(
        1
        for item in technologies
        if isinstance(item, dict) and str(item.get("version_status", "")).upper() == "NOT_EXPOSED"
    )

    live_assets = sum(1 for item in assets if isinstance(item, dict) and item.get("http", {}).get("live"))
    dns_validated = sum(
        1 for item in assets if isinstance(item, dict) and item.get("dns", {}).get("resolved_current")
    )
    screenshots = sum(
        1 for item in assets if isinstance(item, dict) and item.get("screenshots", {}).get("captured")
    )
    allowed_active = sum(
        1 for item in eligibility if isinstance(item, dict) and item.get("active_testing_allowed")
    )
    confirmed_services = sum(
        1
        for item in service_source
        if isinstance(item, dict)
        and item.get("current", True)
        and str(item.get("final_status", "")).upper()
        in {"CONFIRMED_OPEN", "HTTP_VALIDATED", "TLS_VALIDATED", "SERVICE_CONFIRMED"}
    )

    waf_assets = sum(
        1
        for item in assets
        if isinstance(item, dict) and item.get("edge_security", {}).get("waf", {}).get("detected")
    )
    cdn_assets = sum(
        1
        for item in assets
        if isinstance(item, dict) and item.get("edge_security", {}).get("cdn", {}).get("detected")
    )

    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    lines: list[str] = []
    lines.append(f"# Combined VAPT Intelligence Report: `{target}`")
    lines.append("")
    lines.append(f"- **Combined report status:** `{combined_status}`")
    lines.append(f"- **Source run:** `{run_dir}`")
    lines.append(f"- **Generated at:** `{generated_at}`")
    lines.append(f"- **Report generator:** `0xCrawller Combined Report v{PROGRAM_VERSION}`")
    lines.append("")
    lines.append("> This document consolidates reconnaissance, normalized asset intelligence, and technology/service identification. It does **not** by itself prove exploitable vulnerabilities.")
    lines.append("")

    lines.append("## Pipeline status")
    lines.append("")
    lines.append("| Stage | Purpose | Status | Primary evidence |")
    lines.append("|---|---|---|---|")
    lines.append(
        f"| 1. Reconnaissance | Discover and validate hosts, URLs, DNS, WAF/CDN, screenshots, passive observations, and bounded ports | `{status_icon(recon_status)}` | `{recon_summary_path.relative_to(run_dir)}` |"
    )
    lines.append(
        f"| 2. Normalization | Convert raw tool outputs into canonical assets, services, endpoints, conflicts, and testing eligibility | `{status_icon(normalization_status)}` | `{norm_summary_path.relative_to(run_dir)}` |"
    )
    lines.append(
        f"| 3. Technology identification | Correlate HTTP, JavaScript, tool fingerprints, and eligible service evidence | `{status_icon(technology_status)}` | `{tech_summary_path.relative_to(run_dir)}` |"
    )
    lines.append(
        f"| 4. CVE Intelligence | Correlate software versions against NVD database to identify CVEs and CVSS severities | `{status_icon(cve_status)}` | `{cve_summary_path.relative_to(run_dir) if cve_summary_path.is_file() else 'cve_detection/cve_summary.json'}` |"
    )
    lines.append("")

    lines.append("## Executive coverage")
    lines.append("")
    lines.append("| Metric | Count | Meaning |")
    lines.append("|---|---:|---|")
    metrics = [
        ("Canonical assets", len(assets) or norm_counts.get("assets", 0), "Unique normalized hosts in the current inventory"),
        ("DNS-validated assets", dns_validated, "Hosts resolved in the current run"),
        ("Live web assets", live_assets, "Hosts with a current HTTP observation"),
        ("Normalized endpoints", len(endpoints) or norm_counts.get("endpoints", 0), "Canonical URLs/endpoints after deduplication"),
        ("Suspicious endpoints", norm_counts.get("suspicious_endpoints", 0), "Crawler observations requiring focused revalidation"),
        ("Current services", len(service_source), "Normalized web/network service records"),
        ("Confirmed/current services", confirmed_services, "Services supported by current validation evidence"),
        ("Technology records", len(technologies) or tech_counts.get("technologies", 0), "Per-host technology/component fingerprints"),
        ("Exact versions", len(exact_versions) or tech_counts.get("exact_versions", 0), "Versions supported by defensible evidence"),
        ("Versions not exposed", version_hidden, "Detected products without an exact observed version"),
        ("Identified CVEs", len(cve_findings) or cve_counts.get("total", 0), "Total CVE vulnerabilities matched to detected versions"),
        ("Critical CVEs", cve_counts.get("critical", sum(1 for f in cve_findings if str(f.get("severity", "")).upper() == "CRITICAL")), "Vulnerabilities with CVSS >= 9.0"),
        ("High CVEs", cve_counts.get("high", sum(1 for f in cve_findings if str(f.get("severity", "")).upper() == "HIGH")), "Vulnerabilities with CVSS 7.0 - 8.9"),
        ("Technology conflicts", len(tech_conflicts), "Conflicting technology/version observations"),
        ("Normalization conflicts", len(norm_conflicts), "Evidence requiring reconciliation or revalidation"),
        ("Normalization revalidation items", len(norm_queue), "Assets/endpoints queued for additional validation"),
        ("Technology revalidation items", len(tech_queue), "Technology evidence requiring additional validation"),
        ("Screenshot-covered assets", screenshots, "Assets with captured screenshot evidence"),
        ("CDN-detected assets", cdn_assets, "Assets identified behind an edge/CDN"),
        ("WAF-detected assets", waf_assets, "Assets with passive or active WAF evidence"),
        ("Active-testing eligible assets", allowed_active, "Assets permitted by the generated routing policy"),
    ]
    for name, value, meaning in metrics:
        lines.append(f"| {md(name)} | {md(value)} | {md(meaning)} |")
    lines.append("")

    lines.append("## Important interpretation")
    lines.append("")
    lines.append("- Reconnaissance discovers and validates the attack surface; it does not confirm a vulnerability.")
    lines.append("- Normalization is the trust boundary that separates current first-party assets from historical, third-party, wildcard-like, conflicting, or unvalidated observations.")
    lines.append("- Technology identification reports only evidence-backed products and versions. `NOT_EXPOSED` means the product was detected but an exact version was not defensibly observable.")
    lines.append("- Vulnerability mapping and validation should consume normalized eligibility and technology evidence, not raw scanner output.")
    lines.append("")

    lines.append("## Asset-level consolidated inventory")
    lines.append("")
    lines.append("| Host | HTTP | Priority | Asset types | CDN / WAF | Current services | Technologies | Testing decision |")
    lines.append("|---|---|---|---|---|---|---|---|")
    sorted_assets = sorted(
        [item for item in assets if isinstance(item, dict)],
        key=lambda item: str(item.get("host", "")),
    )
    for item in sorted_assets[: max(0, max_assets)]:
        host = str(item.get("host", ""))
        http = item.get("http", {}) if isinstance(item.get("http"), dict) else {}
        http_value = "not live"
        if http.get("live"):
            status = http.get("status_code", "?")
            title = http.get("title") or http.get("category") or "live"
            http_value = f"{status} {title}"
        edge = item.get("edge_security", {}) if isinstance(item.get("edge_security"), dict) else {}
        cdn = edge.get("cdn", {}) if isinstance(edge.get("cdn"), dict) else {}
        waf = edge.get("waf", {}) if isinstance(edge.get("waf"), dict) else {}
        edge_parts: list[str] = []
        if cdn.get("detected"):
            edge_parts.append(f"CDN: {cdn.get('provider') or 'detected'}")
        if waf.get("detected"):
            edge_parts.append(f"WAF: {waf.get('provider') or 'detected'}")

        host_services: list[str] = []
        for service in current_services_by_host.get(host, []):
            protocol = service.get("protocol", "tcp")
            port = service.get("port", "?")
            family = service.get("service_family") or service.get("product") or "service"
            version = service.get("version")
            label = f"{protocol}/{port} {family}"
            if version:
                label += f" {version}"
            host_services.append(label)

        host_tech: list[str] = []
        for technology in sorted(
            technologies_by_host.get(host, []), key=lambda row: str(row.get("name", ""))
        ):
            name = str(technology.get("name", "Unknown"))
            version = technology.get("version")
            host_tech.append(f"{name} {version}" if version else name)

        testing_policy = item.get("testing_policy", {})
        decision = testing_policy.get("decision") if isinstance(testing_policy, dict) else None
        lines.append(
            "| "
            + " | ".join(
                [
                    code(host),
                    md(http_value),
                    md(http.get("priority", "—")),
                    md(item.get("asset_types", [])),
                    md(edge_parts),
                    md(host_services),
                    md(host_tech),
                    code(decision or "UNKNOWN"),
                ]
            )
            + " |"
        )
    if len(sorted_assets) > max_assets:
        lines.append(f"\n_Asset table limited to {max_assets} of {len(sorted_assets)} records._")
    lines.append("")

    lines.append("## Technology intelligence")
    lines.append("")
    if category_counts:
        lines.append("### Categories")
        lines.append("")
        lines.append("| Category | Records |")
        lines.append("|---|---:|")
        for category, count in sorted(category_counts.items(), key=lambda pair: (-pair[1], pair[0])):
            lines.append(f"| {md(category)} | {count} |")
        lines.append("")

    lines.append("### Exact observed versions")
    lines.append("")
    if exact_versions:
        lines.append("| Host | Technology | Version | Category | Confidence | Sources |")
        lines.append("|---|---|---|---|---|---|")
        for item in sorted(exact_versions, key=lambda row: (str(row.get("host", "")), str(row.get("name", "")))):
            lines.append(
                f"| {code(item.get('host'))} | {md(item.get('name'))} | {code(item.get('version'))} | "
                f"{md(item.get('category'))} | {md(item.get('confidence'))} | {md(item.get('sources', []))} |"
            )
    else:
        lines.append("No exact product versions were defensibly observed.")
    lines.append("")

    lines.append("### Technology tool lanes")
    lines.append("")
    rows = tool_rows(tech_tools)
    if rows:
        lines.append("| Lane | Status | Targets/records | Note |")
        lines.append("|---|---|---:|---|")
        for name, status, targets, note in rows:
            lines.append(f"| `{md(name)}` | `{md(status)}` | {md(targets)} | {md(note)} |")
    else:
        lines.append("Technology tool status data was not available.")
    lines.append("")

    lines.append("## CVE Intelligence")
    lines.append("")
    if cve_findings:
        lines.append("| Product | Version | CVE | Severity | CVSS | Affected Hosts |")
        lines.append("|---|---|---|---|---|---|")
        for item in cve_findings:
            hosts = item.get("hosts", [])
            hosts_str = ", ".join(hosts[:3]) + (f" (+{len(hosts)-3} more)" if len(hosts) > 3 else "")
            cve_id = item.get("cve") or item.get("cve_id") or "UNKNOWN"
            source = item.get("source") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            lines.append(
                f"| {md(item.get('product'))} | {code(item.get('version'))} | [{cve_id}]({source}) | "
                f"{md(item.get('severity', 'UNKNOWN'))} | {md(item.get('cvss', 'N/A'))} | {code(hosts_str)} |"
            )
    else:
        lines.append("No CVE matches identified.")
    lines.append("")

    lines.append("## Services and ports")
    lines.append("")
    current_service_rows = [
        item for item in service_source if isinstance(item, dict) and item.get("current", True)
    ]
    if current_service_rows:
        lines.append("| Host | Protocol | Port | Family/product | Version | Status |")
        lines.append("|---|---|---:|---|---|---|")
        for item in sorted(
            current_service_rows,
            key=lambda row: (str(row.get("host", "")), int(row.get("port", 0) or 0)),
        ):
            family = item.get("product") or item.get("service_family") or "unknown"
            lines.append(
                f"| {code(item.get('host'))} | {md(item.get('protocol', 'tcp'))} | {md(item.get('port'))} | "
                f"{md(family)} | {code(item.get('version'))} | {code(item.get('final_status', 'UNKNOWN'))} |"
            )
    else:
        lines.append("No current normalized services were available.")
    lines.append("")

    lines.append("## Revalidation and evidence conflicts")
    lines.append("")
    if norm_queue:
        lines.append("### Normalization revalidation queue")
        lines.append("")
        lines.append("| Host | Priority | Reason | Recommended action |")
        lines.append("|---|---|---|---|")
        for item in norm_queue[:100]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {code(item.get('host'))} | {md(item.get('priority'))} | {md(item.get('reason'))} | {md(item.get('recommended_action'))} |"
            )
        lines.append("")
    else:
        lines.append("No normalization revalidation items were generated.")
        lines.append("")

    if norm_conflicts:
        lines.append("### Normalization conflicts")
        lines.append("")
        lines.append("| Host | Severity | Type | Description |")
        lines.append("|---|---|---|---|")
        for item in norm_conflicts[:100]:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"| {code(item.get('host'))} | {md(item.get('severity'))} | {md(item.get('type'))} | {md(item.get('description'))} |"
            )
        lines.append("")

    if tech_conflicts:
        lines.append("### Technology conflicts")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(tech_conflicts[:50], indent=2, ensure_ascii=False))
        lines.append("```")
        lines.append("")
    else:
        lines.append("No conflicting exact technology versions were observed.")
        lines.append("")

    lines.append("## Authorized next-stage routing")
    lines.append("")
    routes = route_counts(eligibility)
    route_labels = {
        "http_headers": "HTTP security headers, cookie flags, methods, and disclosure checks",
        "tls_checks": "TLS protocol, certificate, and cipher configuration checks",
        "safe_web_templates": "Safe and rate-limited web vulnerability templates",
        "technology_specific_templates": "Evidence-driven checks selected from confirmed technologies",
        "network_service_checks": "Protocol-specific checks against confirmed direct services",
        "openvas_remote_checks": "Remote vulnerability checks against eligible direct first-party services",
        "authenticated_checks": "Authenticated application checks after credentials and explicit scope are provided",
        "third_party_checks": "Third-party service checks only with separate authorization",
    }
    if routes:
        lines.append("| Route | Eligible assets |")
        lines.append("|---|---:|")
        for route, count_value in sorted(routes.items(), key=lambda pair: (-pair[1], pair[0])):
            lines.append(f"| {md(route_labels.get(route, route))} | {count_value} |")
    else:
        lines.append("No testing eligibility routes were available.")
    lines.append("")
    lines.append("The next implementation layer should perform vulnerability discovery, CVE/CPE mapping, evidence-backed validation, false-positive control, and human approval for intrusive or authenticated checks.")
    lines.append("")

    lines.append("## Evidence files consumed")
    lines.append("")
    evidence_paths = [
        recon_summary_path,
        recon_report_path,
        norm_summary_path,
        norm_assets_path,
        norm_services_path,
        norm_endpoints_path,
        norm_conflicts_path,
        norm_queue_path,
        eligibility_path,
        norm_report_path,
        tech_summary_path,
        tech_inventory_path,
        tech_services_path,
        tech_conflicts_path,
        tech_queue_path,
        tech_tools_path,
        tech_report_path,
        cve_summary_path,
        cve_findings_path,
        cve_report_path,
    ]
    for path in evidence_paths:
        status = "read" if path.is_file() else "missing"
        try:
            relative = path.relative_to(run_dir)
        except ValueError:
            relative = path
        lines.append(f"- `{relative}` — {status}")
    lines.append("")

    if not summary_only:
        source_reports = [
            ("Reconnaissance source report", recon_report_path),
            ("Normalization source report", norm_report_path),
            ("Technology source report", tech_report_path),
            ("CVE intelligence source report", cve_report_path),
        ]
        lines.append("## Embedded source reports")
        lines.append("")
        lines.append("The original stage reports are embedded below so the consolidated file remains self-contained.")
        lines.append("")
        for title, path in source_reports:
            lines.append(f"### {title}")
            lines.append("")
            content = load_text(path)
            if content:
                lines.append(demote_headings(content, levels=3))
            else:
                lines.append(f"Source report missing: `{path.relative_to(run_dir)}`")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    try:
        target = normalize_target(args.target)
        run_dir = select_run_dir(target, Path(args.latest_root), args.run_dir)
        output_name = Path(args.output_name).name
        if output_name != args.output_name or not output_name.lower().endswith(".md"):
            raise ValueError("--output-name must be a plain .md filename, not a path")
        output_path = run_dir / output_name
        if output_path.exists() and not args.overwrite:
            raise FileExistsError(
                f"Output already exists: {output_path}. Use --overwrite to replace it."
            )
        report = build_report(
            run_dir=run_dir,
            target=target,
            summary_only=args.summary_only,
            max_assets=max(0, args.max_assets),
        )
        output_path.write_text(report, encoding="utf-8", newline="\n")
        print(f"[COMPLETE] Combined report written: {output_path}")
        return 0
    except (ValueError, FileNotFoundError, FileExistsError, RuntimeError, OSError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
