"""Output writers for CVE Detection Module."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}


def save_findings_json(findings: List[Dict[str, Any]], output_path: Path, target: str, run_dir: str, counts: Dict[str, int]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1.0",
        "status": "COMPLETE",
        "target": target,
        "run_dir": str(run_dir),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "counts": counts,
        "findings": findings,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def save_findings_csv(findings: List[Dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["product", "version", "cve", "severity", "cvss", "cvss_version", "hosts", "description", "source"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for f_item in findings:
            hosts = f_item.get("hosts", [])
            hosts_str = ", ".join(hosts) if isinstance(hosts, list) else str(hosts)
            writer.writerow({
                "product": f_item.get("product", ""),
                "version": f_item.get("version", ""),
                "cve": f_item.get("cve", ""),
                "severity": f_item.get("severity", "UNKNOWN"),
                "cvss": f_item.get("cvss", ""),
                "cvss_version": f_item.get("cvss_version", ""),
                "hosts": hosts_str,
                "description": f_item.get("description", ""),
                "source": f_item.get("source", ""),
            })


def save_summary_json(
    output_path: Path,
    target: str,
    run_dir: str,
    counts: Dict[str, int],
    scanned_products: List[Dict[str, Any]],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "schema_version": "1.0",
        "status": "COMPLETE",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target": target,
        "run_dir": str(run_dir),
        "counts": counts,
        "scanned_products": scanned_products,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)


def save_markdown_report(
    findings: List[Dict[str, Any]],
    output_path: Path,
    target: str,
    counts: Dict[str, int],
    scanned_products: List[Dict[str, Any]],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    lines: List[str] = [
        f"# CVE Intelligence & Vulnerability Report: `{target}`",
        "",
        f"- **Generated at:** `{generated_at}`",
        f"- **Total CVE Matches:** `{counts.get('total', 0)}`",
        f"- **Versioned Technologies Scanned:** `{len(scanned_products)}`",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
        f"| Critical | {counts.get('critical', 0)} |",
        f"| High | {counts.get('high', 0)} |",
        f"| Medium | {counts.get('medium', 0)} |",
        f"| Low | {counts.get('low', 0)} |",
        f"| Unknown / Info | {counts.get('unknown', 0)} |",
        "",
        "## CVE Findings Table",
        "",
    ]

    if not findings:
        lines.append("> No CVE matches identified for the detected software versions.")
        lines.append("")
    else:
        lines.append("| Product | Version | CVE ID | Severity | CVSS | Affected Hosts |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            hosts = f.get("hosts", [])
            hosts_str = ", ".join(hosts[:3]) + (f" (+{len(hosts)-3} more)" if len(hosts) > 3 else "")
            cve_link = f"[{f.get('cve', '')}]({f.get('source', '#')})"
            cvss_str = f"{f.get('cvss', 'N/A')}"
            lines.append(
                f"| {f.get('product', '')} | {f.get('version', '')} | {cve_link} | {f.get('severity', '')} | {cvss_str} | {hosts_str} |"
            )
        lines.append("")
        lines.append("## Detailed Findings")
        lines.append("")
        for f in findings:
            hosts_str = ", ".join(f.get("hosts", []))
            lines.append(f"### [{f.get('severity', 'UNKNOWN')}] {f.get('cve', '')} — {f.get('product', '')} {f.get('version', '')}")
            lines.append(f"- **CVSS Score:** {f.get('cvss', 'N/A')} ({f.get('cvss_version', 'N/A')})")
            lines.append(f"- **Affected Hosts:** {hosts_str}")
            lines.append(f"- **Source Link:** [{f.get('source', '')}]({f.get('source', '')})")
            lines.append(f"- **Description:** {f.get('description', '')}")
            lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def save_all_outputs(
    output_dir: Path,
    target: str,
    run_dir: str,
    findings: List[Dict[str, Any]],
    scanned_products: List[Dict[str, Any]],
) -> Dict[str, Any]:
    counts = {
        "total": len(findings),
        "critical": sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"),
        "high": sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH"),
        "medium": sum(1 for f in findings if str(f.get("severity", "")).upper() == "MEDIUM"),
        "low": sum(1 for f in findings if str(f.get("severity", "")).upper() == "LOW"),
        "unknown": sum(1 for f in findings if str(f.get("severity", "")).upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}),
        "products_scanned": len(scanned_products),
    }

    # Sort findings by severity then CVSS descending
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(str(f.get("severity", "UNKNOWN")).upper(), 99),
            -(float(f.get("cvss") or 0.0)),
        )
    )

    save_findings_json(findings, output_dir / "cve_findings.json", target, run_dir, counts)
    save_findings_csv(findings, output_dir / "cve_findings.csv")
    save_summary_json(output_dir / "cve_summary.json", target, run_dir, counts, scanned_products)
    save_markdown_report(findings, output_dir / "cve_report.md", target, counts, scanned_products)

    return counts
