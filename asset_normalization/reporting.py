from __future__ import annotations

from collections import Counter
from typing import Any


def _esc(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def render_report(summary: dict[str, Any], assets: list[dict[str, Any]], services: list[dict[str, Any]], endpoints: list[dict[str, Any]], conflicts: list[dict[str, Any]], revalidation: list[dict[str, Any]], eligibility: list[dict[str, Any]]) -> str:
    counts = summary["counts"]
    lines = [
        f"# V9 Asset Validation and Normalization Report: `{summary['target']}`",
        "",
        f"- Schema version: `{summary['schema_version']}`",
        f"- Source recon version: `{summary.get('source_program_version')}`",
        f"- Source run: `{summary['source_run']}`",
        f"- Normalized: `{summary['normalized_at']}`",
        "",
        "## Executive normalization result",
        "",
        f"- Canonical assets: `{counts['assets']}`",
        f"- Current validated assets: `{counts['current_validated_assets']}`",
        f"- Historical/unresolved assets: `{counts['historical_unresolved_assets']}`",
        f"- Third-party assets restricted: `{counts['third_party_assets']}`",
        f"- Assets eligible for some active testing: `{counts['active_testing_allowed_assets']}`",
        f"- Canonical services: `{counts['services']}`",
        f"- Current confirmed HTTP/network services: `{counts['confirmed_open_services']}`",
        f"- Endpoints normalized: `{counts['endpoints']}`",
        f"- Syntactically suspicious endpoints: `{counts['suspicious_endpoints']}`",
        f"- Evidence conflicts: `{counts['conflicts']}`",
        f"- Revalidation queue items: `{counts['revalidation_items']}`",
        "",
        "> This report does not claim vulnerabilities. It converts recon evidence into policy-controlled assets that can be safely routed to later vulnerability-discovery stages.",
        "",
        "## Normalization decision flow",
        "",
        "```mermaid",
        "flowchart TD",
        "  A[Raw V8.5.1 evidence] --> B[Canonical host identity]",
        "  B --> C[Current vs historical evidence]",
        "  C --> D[Ownership and CDN/SaaS policy]",
        "  D --> E[Service and endpoint reconciliation]",
        "  E --> F[Conflicts and revalidation queue]",
        "  F --> G[Testing eligibility routes]",
        "  G --> H[Vulnerability discovery planner]",
        "```",
        "",
        "## Canonical asset inventory",
        "",
        "| Host | Types | Ownership | Freshness | DNS | HTTP | Confirmed ports | Testing decision |",
        "|---|---|---|---|---:|---:|---|---|",
    ]
    for a in assets:
        lines.append("| " + " | ".join([
            f"`{_esc(a['host'])}`",
            _esc(", ".join(a.get("asset_types") or [])),
            _esc((a.get("ownership") or {}).get("classification")),
            _esc((a.get("freshness") or {}).get("state")),
            "Yes" if (a.get("dns") or {}).get("resolved_current") else "No",
            str((a.get("http") or {}).get("status_code") or ""),
            _esc(", ".join(str(p) for p in a.get("confirmed_open_ports") or [])),
            _esc((a.get("testing_policy") or {}).get("decision")),
        ]) + " |")

    lines += ["", "## Scanner eligibility", "", "| Host | Decision | Headers | TLS | Safe web | Technology-specific | Network/OpenVAS | Reasons |", "|---|---|---:|---:|---:|---:|---:|---|"]
    for item in eligibility:
        routes = item.get("routes") or {}
        lines.append("| " + " | ".join([
            f"`{_esc(item['host'])}`", _esc(item.get("decision")),
            "Yes" if routes.get("http_headers") else "No",
            "Yes" if routes.get("tls_checks") else "No",
            "Yes" if routes.get("safe_web_templates") else "No",
            "Yes" if routes.get("technology_specific_templates") else "No",
            "Yes" if routes.get("openvas_remote_checks") else "No",
            _esc("; ".join(item.get("reasons") or [])),
        ]) + " |")

    state_counts = Counter(s.get("final_status") for s in services)
    lines += ["", "## Service reconciliation", "", "Final service states:"]
    for state, count in sorted(state_counts.items(), key=lambda x: str(x[0])):
        lines.append(f"- `{state}`: `{count}`")
    lines += ["", "| Host | Protocol | Port | Final state | Service | Product/version |", "|---|---|---:|---|---|---|"]
    for s in services:
        product = " ".join(str(v) for v in (s.get("product"), s.get("version")) if v)
        lines.append(f"| `{_esc(s['host'])}` | {_esc(s['protocol'])} | {s['port']} | `{_esc(s.get('final_status'))}` | {_esc(s.get('service_family'))} | {_esc(product)} |")

    endpoint_states = Counter(e.get("state") for e in endpoints)
    endpoint_categories = Counter(e.get("category") for e in endpoints)
    lines += ["", "## Endpoint normalization", ""]
    for state, count in sorted(endpoint_states.items()):
        lines.append(f"- `{state}`: `{count}`")
    lines += ["", "Top categories:"]
    for category, count in endpoint_categories.most_common(12):
        lines.append(f"- `{category}`: `{count}`")
    suspicious = [e for e in endpoints if e.get("state") == "SYNTACTICALLY_SUSPICIOUS"]
    if suspicious:
        lines += ["", "### Suspicious crawler observations", "", "These URLs must be HTTP-revalidated before any vulnerability tool uses them:", ""]
        for e in suspicious[:30]:
            lines.append(f"- `{e['url']}` — {', '.join(e.get('suspicious_reasons') or [])}")

    lines += ["", "## Evidence conflicts", ""]
    if not conflicts:
        lines.append("No material evidence conflict was generated.")
    else:
        lines += ["| ID | Host | Type | Severity | Description |", "|---|---|---|---|---|"]
        for c in conflicts:
            lines.append(f"| `{c['conflict_id']}` | `{_esc(c['host'])}` | {_esc(c['type'])} | {_esc(c['severity'])} | {_esc(c['description'])} |")

    lines += ["", "## Revalidation queue", ""]
    if not revalidation:
        lines.append("No revalidation item was generated.")
    else:
        lines += ["| Queue ID | Host | Priority | Reason | Recommended action |", "|---|---|---|---|---|"]
        for item in revalidation:
            lines.append(f"| `{item['queue_id']}` | `{_esc(item['host'])}` | {_esc(item['priority'])} | {_esc(item['reason'])} | {_esc(item['recommended_action'])} |")

    lines += [
        "", "## V10 handoff", "",
        "The next stage should consume `testing_eligibility.json`, not raw scanner output.", "",
        "Recommended first vulnerability-discovery routes:", "",
        "1. HTTP headers, cookie flags, TLS configuration, methods, and disclosure checks.",
        "2. Safe technology-specific templates only for current, owned assets.",
        "3. OpenVAS remote checks only for direct first-party services with confirmed current ports.",
        "4. Third-party SaaS and historical/unresolved assets remain blocked pending explicit authorization or revalidation.",
        "",
    ]
    return "\n".join(lines)
