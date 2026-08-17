from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def _escape(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _version_label(item: dict[str, Any]) -> str:
    if item.get("version"):
        return str(item["version"])
    if item.get("alternative_versions"):
        return " / ".join(item["alternative_versions"])
    return item.get("version_status") or "NOT_EXPOSED"


def build_stack_mermaid(assets: list[dict[str, Any]], technologies: list[dict[str, Any]]) -> str:
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in technologies:
        by_host[str(item.get("host") or "")].append(item)
    lines = ["flowchart LR", '  ROOT["Authorized attack surface"]']
    index = 0
    category_order = {
        "CDN / Security Edge": 0,
        "Web Server": 1,
        "Application Server": 2,
        "Runtime": 3,
        "Programming Language": 4,
        "Web Framework": 5,
        "CMS": 6,
        "CMS / Site Generator": 6,
        "Database": 7,
        "Database / Cache": 7,
        "Search / Database": 7,
        "Message Queue": 8,
        "Task Queue": 8,
        "JavaScript Library": 9,
        "UI Framework": 9,
    }
    for asset in assets:
        host = str(asset.get("host") or "")
        if not host:
            continue
        host_id = f"H{index}"
        index += 1
        ownership = str((asset.get("ownership") or {}).get("classification") or "unknown")
        lines.append(f'  {host_id}["{host}\\n{ownership}"]')
        lines.append(f"  ROOT --> {host_id}")
        host_tech = sorted(by_host.get(host, []), key=lambda item: (category_order.get(str(item.get("category")), 50), str(item.get("name"))))
        previous = host_id
        for tech in host_tech[:14]:
            tech_id = f"T{index}"
            index += 1
            label = f"{tech.get('name')}"
            if tech.get("version"):
                label += f" {tech.get('version')}"
            elif tech.get("version_status") == "NOT_EXPOSED":
                label += " (version hidden)"
            lines.append(f'  {tech_id}["{label}\\n{tech.get("category")}"]')
            lines.append(f"  {previous} --> {tech_id}")
            previous = tech_id
    return "\n".join(lines) + "\n"


def write_report(
    path: Path,
    *,
    run_dir: Path,
    summary: dict[str, Any],
    tools: dict[str, Any],
    plan: dict[str, Any],
    technologies: list[dict[str, Any]],
    service_fingerprints: list[dict[str, Any]],
    conflicts: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    mermaid: str,
    vulnerability_findings: list[dict[str, Any]] | None = None,
) -> None:
    vulnerability_findings = vulnerability_findings or []
    category_counts = Counter(str(item.get("category") or "Unknown") for item in technologies)
    source_counts = Counter(source for item in technologies for source in item.get("sources") or [])
    exact = [item for item in technologies if item.get("version_status") == "EXACT_OBSERVED"]
    hidden = [item for item in technologies if item.get("version_status") == "NOT_EXPOSED"]
    db_queue = [item for item in technologies if any(token in str(item.get("category") or "").lower() for token in ("database", "queue", "cache", "search"))]

    lines: list[str] = []
    lines += [
        f"# V9.2 Technology and Service Intelligence Report",
        "",
        f"Source run: `{run_dir}`",
        f"Overall status: **{summary.get('status')}**",
        "",
        "## Coverage",
        "",
        f"- Canonical assets considered: `{summary.get('counts', {}).get('assets', 0)}`",
        f"- Web targets enriched: `{summary.get('counts', {}).get('web_targets', 0)}`",
        f"- Network services fingerprinted: `{summary.get('counts', {}).get('service_targets', 0)}`",
        f"- JavaScript assets considered: `{summary.get('counts', {}).get('javascript_targets', 0)}`",
        f"- Technologies/components consolidated: `{len(technologies)}`",
        f"- Exact versions observed: `{len(exact)}`",
        f"- Technology detected but version not exposed: `{len(hidden)}`",
        f"- Technology version conflicts: `{len(conflicts)}`",
        "",
        "`NOT_EXPOSED` means the product/framework was detected, but the remote evidence did not reveal a defensible exact version. It is not treated as a scanner failure.",
        "",
        "## Parallel tool lanes",
        "",
        "| Lane | Status | Targets | Notes |",
        "|---|---|---:|---|",
    ]
    for name in ("http_evidence", "whatweb", "wappalyzer_next", "retirejs", "zgrab2", "nuclei"):
        record = tools.get(name) or {}
        notes = record.get("reason") or record.get("stderr_tail") or ""
        lines.append(f"| `{name}` | `{_escape(record.get('status'))}` | {record.get('targets', 0)} | {_escape(str(notes)[:240])} |")

    lines += ["", "## Technology categories", "", "| Category | Count |", "|---|---:|"]
    for category, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| {_escape(category)} | {count} |")

    lines += ["", "## Exact observed versions", "", "| Host | Technology | Version | Category | Confidence | Sources |", "|---|---|---|---|---|---|"]
    for item in sorted(exact, key=lambda value: (value.get("host", ""), value.get("category", ""), value.get("name", ""))):
        lines.append(
            f"| `{_escape(item.get('host'))}` | {_escape(item.get('name'))} | `{_escape(item.get('version'))}` | {_escape(item.get('category'))} | `{_escape(item.get('confidence'))}` | {_escape(', '.join(item.get('sources') or []))} |"
        )
    if not exact:
        lines.append("| — | — | — | — | — | No exact versions were defensibly exposed |")

    lines += ["", "## Database, cache, search, and queue evidence", "", "| Host | Component | Version state | Scope | Service confirmed | Confidence |", "|---|---|---|---|---:|---|"]
    for item in sorted(db_queue, key=lambda value: (value.get("host", ""), value.get("name", ""))):
        lines.append(
            f"| `{_escape(item.get('host'))}` | {_escape(item.get('name'))} | `{_escape(_version_label(item))}` | {_escape(', '.join(item.get('scopes') or []))} | {bool(item.get('service_confirmed'))} | `{_escape(item.get('confidence'))}` |"
        )
    if not db_queue:
        lines.append("| — | — | — | — | — | No database or queue evidence observed |")

    lines += ["", "## Service handshakes", "", "| Host | Port | Module | Status | Product | Version | Sources |", "|---|---:|---|---|---|---|---|"]
    for item in sorted(service_fingerprints, key=lambda value: (value.get("host", ""), int(value.get("port") or 0))):
        lines.append(
            f"| `{_escape(item.get('host'))}` | {item.get('port') or ''} | `{_escape(item.get('module'))}` | `{_escape(item.get('status'))}` | {_escape(item.get('product'))} | `{_escape(item.get('version') or 'NOT_EXPOSED')}` | {_escape(', '.join(item.get('sources') or []))} |"
        )
    if not service_fingerprints:
        lines.append("| — | — | — | — | — | — | No eligible direct first-party network services |")

    lines += ["", "## Vulnerability findings (Nuclei)", ""]
    lines.append(
        "Template matches are corroborating evidence for manual review — they are **not** auto-merged into "
        "technology confidence scoring above, since a template match can be behavior-based rather than a "
        "confirmed exact version."
    )
    lines += ["", "| Host | Severity | Template | CVE | Matched at |", "|---|---|---|---|---|"]
    high_or_critical = [f for f in vulnerability_findings if str(f.get("severity") or "").upper() in {"HIGH", "CRITICAL"}]
    for item in sorted(vulnerability_findings, key=lambda v: (str(v.get("host") or ""), str(v.get("severity") or ""))):
        lines.append(
            f"| `{_escape(item.get('host'))}` | `{_escape(item.get('severity'))}` | {_escape(item.get('template_name') or item.get('template_id'))} | "
            f"{_escape(', '.join(item.get('cve') or []) or '—')} | {_escape(item.get('matched_at'))} |"
        )
    if not vulnerability_findings:
        lines.append("| — | — | — | — | No Nuclei findings for the enriched web targets |")
    lines += ["", f"High/Critical severity findings: `{len(high_or_critical)}` (also added to `technology_revalidation_queue.json`)"]

    lines += ["", "## Version conflicts", ""]
    if conflicts:
        for item in conflicts:
            lines.append(f"- `{item.get('host')}` — **{item.get('technology')}**: {', '.join(item.get('versions') or [])} ({', '.join(item.get('sources') or [])})")
    else:
        lines.append("No conflicting exact versions were observed.")

    lines += [
        "",
        "## Technology stack map",
        "",
        "```mermaid",
        mermaid.rstrip(),
        "```",
        "",
        "## Interpretation rules",
        "",
        "- A framework-like login page can establish a technology fingerprint, but it cannot guarantee an exact backend version.",
        "- Database or queue names found in application errors, HTML, or JavaScript are recorded as application references until a current protocol handshake confirms an exposed service.",
        "- Current Nmap/ZGrab2 evidence has precedence over passive historical records.",
        "- CDN-fronted hostnames receive bounded HTTP technology enrichment, not direct origin-service attribution.",
        "- Third-party SaaS is excluded from active enrichment unless separately authorized.",
        "",
        "## Output files",
        "",
        "- `technology_inventory.json` / `.csv`",
        "- `technology_evidence.jsonl`",
        "- `technology_conflicts.json`",
        "- `service_fingerprints.json` / `.csv`",
        "- `wappalyzer_next_results.json`",
        "- `javascript_components.json`",
        "- `asset_inventory_enriched.json` / `.csv`",
        "- `service_inventory_enriched.json` / `.csv`",
        "- `technology_revalidation_queue.json`",
        "- `vulnerability_findings.json`",
        "- `technology_stack_map.mmd`",
        "- `technology_enrichment_summary.json`",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
