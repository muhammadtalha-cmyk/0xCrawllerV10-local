from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from asset_normalization.engine import normalize_run

from .config import EnrichmentConfig
from .docker_runner import docker_available
from .http_evidence import run_http_evidence
from .io_utils import prepare_output_dir, read_json, write_csv, write_json, write_jsonl
from .reconcile import reconcile_technology
from .reporting import build_stack_mermaid, write_report
from .nuclei_runner import run_nuclei
from .retirejs_runner import run_retirejs
from .target_planner import build_plan
from .whatweb_runner import run_whatweb
from .wappalyzer_next_runner import run_wappalyzer_next
from .zgrab2_runner import run_zgrab2

SCHEMA_VERSION = "9.2.0"


@dataclass
class EnrichmentResult:
    output_dir: Path
    summary: dict[str, Any]
    technologies: list[dict[str, Any]]
    service_fingerprints: list[dict[str, Any]]
    conflicts: list[dict[str, Any]]


def _flatten_technology(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "technology_id": item.get("technology_id"),
        "asset_id": item.get("asset_id"),
        "host": item.get("host"),
        "name": item.get("name"),
        "category": item.get("category"),
        "version": item.get("version"),
        "version_status": item.get("version_status"),
        "alternative_versions": item.get("alternative_versions"),
        "confidence": item.get("confidence"),
        "confidence_score": item.get("confidence_score"),
        "sources": item.get("sources"),
        "scopes": item.get("scopes"),
        "service_confirmed": item.get("service_confirmed"),
        "application_reference_only": item.get("application_reference_only"),
        "evidence_count": item.get("evidence_count"),
    }


def _flatten_service(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_id": item.get("service_id"),
        "asset_id": item.get("asset_id"),
        "host": item.get("host"),
        "port": item.get("port"),
        "protocol": item.get("protocol"),
        "module": item.get("module"),
        "status": item.get("status"),
        "success": item.get("success"),
        "product": item.get("product"),
        "version": item.get("version"),
        "sources": item.get("sources"),
        "version_product_fields": item.get("version_product_fields"),
    }


def _build_revalidation_queue(technologies: list[dict[str, Any]], conflicts: list[dict[str, Any]], tools: dict[str, Any], vulnerability_findings: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    queue: list[dict[str, Any]] = []
    for item in technologies:
        if item.get("version_status") == "NOT_EXPOSED" and item.get("category") in {
            "Web Framework", "CMS", "Database", "Database / Cache", "Message Queue", "Task Queue", "Search / Database"
        }:
            queue.append({
                "host": item.get("host"), "technology": item.get("name"),
                "reason": "exact_version_not_remotely_exposed", "recommended_action": "authenticated_inventory_or_product_specific_manual_validation",
                "priority": "medium",
            })
    for conflict in conflicts:
        queue.append({
            "host": conflict.get("host"), "technology": conflict.get("technology"),
            "reason": "conflicting_version_evidence", "recommended_action": "repeat_targeted_fingerprint_and_review_raw_evidence",
            "priority": "high",
        })
    for lane, record in tools.items():
        if record.get("status") in {"FAILED", "PARTIAL"}:
            queue.append({
                "host": None, "technology": None, "reason": f"tool_lane_{lane.lower()}_{record.get('status', '').lower()}",
                "recommended_action": "review_tool_status_and_rerun_only_failed_lane", "priority": "medium",
            })
    for finding in vulnerability_findings or []:
        if str(finding.get("severity") or "").upper() in {"HIGH", "CRITICAL"}:
            queue.append({
                "host": finding.get("host"), "technology": finding.get("template_name"),
                "reason": "nuclei_high_or_critical_severity_match", "recommended_action": "manual_verification_and_prioritized_remediation_review",
                "priority": "high",
            })
    return queue


def enrich_run(
    run_dir: Path,
    output_dir: Path,
    *,
    config: EnrichmentConfig,
    overwrite: bool = False,
    normalize_if_missing: bool = False,
    normalization_dir: Path | None = None,
    offline: bool = False,
) -> EnrichmentResult:
    run_dir = run_dir.resolve()
    if not run_dir.is_dir():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")
    output_dir = output_dir.resolve()
    prepare_output_dir(output_dir, overwrite)
    normalization_dir = (normalization_dir or (run_dir / "normalization_v9")).resolve()
    if not (normalization_dir / "asset_inventory.json").exists():
        if not normalize_if_missing:
            raise FileNotFoundError(f"V9 normalization output not found: {normalization_dir}. Run V9 or use --normalize-if-missing.")
        normalize_run(run_dir, normalization_dir, overwrite=overwrite)

    assets = read_json(normalization_dir / "asset_inventory.json", [])
    services = read_json(normalization_dir / "service_inventory.json", [])
    if not isinstance(assets, list) or not isinstance(services, list):
        raise ValueError("Invalid V9 normalization outputs")
    plan = build_plan(normalization_dir, max_web=config.max_web_targets, max_services=config.max_service_targets, max_js=config.max_js_urls)
    write_json(output_dir / "technology_target_plan.json", {
        "schema_version": SCHEMA_VERSION,
        "root_domain": plan.root_domain,
        "web_targets": plan.web_targets,
        "service_targets": plan.service_targets,
        "javascript_targets": plan.js_targets,
        "excluded_assets": plan.excluded_assets,
    })

    docker_ok, docker_detail = docker_available()
    tools: dict[str, Any] = {}

    def http_lane() -> dict[str, Any]:
        if offline:
            return {"status": "SKIPPED", "reason": "offline_mode", "records": [], "targets": len(plan.web_targets)}
        return run_http_evidence(plan.web_targets, workers=config.http_workers, timeout=config.request_timeout, max_bytes=config.max_http_bytes, user_agent=config.user_agent)

    def whatweb_lane() -> dict[str, Any]:
        if offline:
            return {"status": "SKIPPED", "reason": "offline_mode", "records": [], "targets": len(plan.web_targets)}
        if not docker_ok:
            return {"status": "FAILED", "reason": f"docker_unavailable:{docker_detail}", "records": [], "targets": len(plan.web_targets)}
        return run_whatweb(plan.web_targets, output_dir=output_dir, image=config.whatweb_image, threads=config.whatweb_threads, aggression=config.whatweb_aggression, timeout=config.lane_timeout, request_timeout=config.request_timeout)

    def wappalyzer_next_lane() -> dict[str, Any]:
        if offline:
            return {"status": "SKIPPED", "reason": "offline_mode", "records": [], "targets": len(plan.web_targets)}
        if not docker_ok:
            return {"status": "FAILED", "reason": f"docker_unavailable:{docker_detail}", "records": [], "targets": len(plan.web_targets)}
        return run_wappalyzer_next(
            plan.web_targets,
            output_dir=output_dir,
            image=config.wappalyzer_next_image,
            max_mode=config.max_mode,
            full_workers=config.wappalyzer_next_full_workers,
            balanced_workers=config.wappalyzer_next_balanced_workers,
            full_target_cap=config.wappalyzer_next_full_target_cap,
            page_timeout=config.wappalyzer_next_page_timeout,
            lane_timeout=config.lane_timeout,
        )

    def retire_lane() -> dict[str, Any]:
        if offline:
            return {"status": "SKIPPED", "reason": "offline_mode", "records": [], "targets": len(plan.js_targets), "fetch_manifest": []}
        if not docker_ok:
            return {"status": "FAILED", "reason": f"docker_unavailable:{docker_detail}", "records": [], "targets": len(plan.js_targets), "fetch_manifest": []}
        return run_retirejs(plan.js_targets, output_dir=output_dir, image=config.retirejs_image, workers=config.js_workers, request_timeout=config.request_timeout, max_bytes=config.max_js_bytes, user_agent=config.user_agent, timeout=config.lane_timeout)

    def zgrab_lane() -> dict[str, Any]:
        if offline:
            return {"status": "SKIPPED", "reason": "offline_mode", "records": [], "targets": len(plan.service_targets), "modules": []}
        if not docker_ok:
            return {"status": "FAILED", "reason": f"docker_unavailable:{docker_detail}", "records": [], "targets": len(plan.service_targets), "modules": []}
        return run_zgrab2(plan.service_targets, image=config.zgrab2_image, workers=config.service_workers, timeout=config.lane_timeout)

    def nuclei_lane() -> dict[str, Any]:
        if offline:
            return {"status": "SKIPPED", "reason": "offline_mode", "findings": [], "targets": len(plan.web_targets)}
        if not docker_ok:
            return {"status": "FAILED", "reason": f"docker_unavailable:{docker_detail}", "findings": [], "targets": len(plan.web_targets)}
        return run_nuclei(
            plan.web_targets,
            output_dir=output_dir,
            image=config.nuclei_image,
            severity=list(config.nuclei_severity) or None,
            templates=config.nuclei_templates,
            workers=config.nuclei_workers,
            request_timeout=config.request_timeout,
            timeout=config.lane_timeout,
        )

    lane_functions: dict[str, Callable[[], dict[str, Any]]] = {
        "http_evidence": http_lane,
        "whatweb": whatweb_lane,
        "wappalyzer_next": wappalyzer_next_lane,
        "retirejs": retire_lane,
        "zgrab2": zgrab_lane,
        "nuclei": nuclei_lane,
    }
    with ThreadPoolExecutor(max_workers=max(1, config.lane_workers)) as pool:
        future_names = {pool.submit(function): name for name, function in lane_functions.items()}
        for future in as_completed(future_names):
            name = future_names[future]
            try:
                tools[name] = future.result()
            except Exception as exc:  # preserve the other independent lanes
                tools[name] = {"status": "FAILED", "reason": f"unhandled_lane_error:{type(exc).__name__}:{exc}", "records": []}

    write_json(output_dir / "technology_tool_status.json", {
        "schema_version": SCHEMA_VERSION,
        "docker_available": docker_ok,
        "docker_detail": docker_detail,
        "config": asdict(config),
        "tools": tools,
    })
    write_json(output_dir / "http_technology_evidence.json", tools.get("http_evidence") or {})
    write_json(output_dir / "whatweb_results.json", tools.get("whatweb") or {})
    write_json(output_dir / "wappalyzer_next_results.json", tools.get("wappalyzer_next") or {})
    write_json(output_dir / "javascript_components.json", {
        "records": (tools.get("retirejs") or {}).get("records") or [],
        "fetch_manifest": (tools.get("retirejs") or {}).get("fetch_manifest") or [],
    })
    write_json(output_dir / "zgrab2_service_results.json", tools.get("zgrab2") or {})
    write_json(output_dir / "vulnerability_findings.json", (tools.get("nuclei") or {}).get("findings") or [])

    reconciled = reconcile_technology(
        assets, services,
        tools.get("http_evidence") or {}, tools.get("whatweb") or {},
        tools.get("retirejs") or {}, tools.get("zgrab2") or {},
        wappalyzer_next_lane=tools.get("wappalyzer_next") or {},
    )
    technologies = reconciled["technology_inventory"]
    conflicts = reconciled["technology_conflicts"]
    service_fingerprints = reconciled["service_fingerprints"]
    vulnerability_findings = (tools.get("nuclei") or {}).get("findings") or []
    revalidation = _build_revalidation_queue(technologies, conflicts, tools, vulnerability_findings)
    mermaid = build_stack_mermaid(reconciled["asset_inventory_enriched"], technologies)

    write_json(output_dir / "technology_inventory.json", technologies)
    write_csv(output_dir / "technology_inventory.csv", [_flatten_technology(item) for item in technologies])
    write_jsonl(output_dir / "technology_evidence.jsonl", reconciled["technology_evidence"])
    write_json(output_dir / "technology_conflicts.json", conflicts)
    write_json(output_dir / "service_fingerprints.json", service_fingerprints)
    write_csv(output_dir / "service_fingerprints.csv", [_flatten_service(item) for item in service_fingerprints])
    write_json(output_dir / "asset_inventory_enriched.json", reconciled["asset_inventory_enriched"])
    write_json(output_dir / "service_inventory_enriched.json", reconciled["service_inventory_enriched"])
    write_json(output_dir / "technology_revalidation_queue.json", revalidation)
    (output_dir / "technology_stack_map.mmd").write_text(mermaid, encoding="utf-8")

    statuses = [str((tools.get(name) or {}).get("status") or "FAILED") for name in lane_functions]
    overall = "COMPLETE" if all(status in {"COMPLETE", "SKIPPED"} for status in statuses) else ("PARTIAL" if technologies else "FAILED")
    summary = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": overall,
        "source_run": str(run_dir),
        "normalization_dir": str(normalization_dir),
        "output_dir": str(output_dir),
        "docker_available": docker_ok,
        "tool_statuses": {name: (tools.get(name) or {}).get("status") for name in lane_functions},
        "counts": {
            "assets": len(assets),
            "web_targets": len(plan.web_targets),
            "service_targets": len(plan.service_targets),
            "javascript_targets": len(plan.js_targets),
            "technologies": len(technologies),
            "exact_versions": sum(item.get("version_status") == "EXACT_OBSERVED" for item in technologies),
            "version_conflicts": len(conflicts),
            "service_fingerprints": len(service_fingerprints),
            "revalidation_items": len(revalidation),
            "vulnerability_findings": len(vulnerability_findings),
            "vulnerability_findings_high_or_critical": sum(str(f.get("severity") or "").upper() in {"HIGH", "CRITICAL"} for f in vulnerability_findings),
        },
    }
    write_json(output_dir / "technology_enrichment_summary.json", summary)
    write_report(
        output_dir / "technology_enrichment_report.md",
        run_dir=run_dir, summary=summary, tools=tools,
        plan={"web_targets": plan.web_targets, "service_targets": plan.service_targets, "javascript_targets": plan.js_targets},
        technologies=technologies, service_fingerprints=service_fingerprints,
        conflicts=conflicts, assets=reconciled["asset_inventory_enriched"], mermaid=mermaid,
        vulnerability_findings=vulnerability_findings,
    )
    return EnrichmentResult(output_dir, summary, technologies, service_fingerprints, conflicts)
