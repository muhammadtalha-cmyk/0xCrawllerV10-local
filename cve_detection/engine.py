"""Core detection engine for 0xCrawller CVE Detection Module."""

from __future__ import annotations

import csv
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from .adapters.nvd_client import NvdClient
from .config import CveConfig
from .output.formatter import save_all_outputs

logger = logging.getLogger("cve_detection.engine")

IGNORE_NAMES = {
    "ip", "country", "region", "asn", "operating system",
    "web server", "crawled", "unknown"
}

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def extract_versioned_technologies(tech_dir: Path, norm_dir: Path | None = None) -> List[Dict[str, Any]]:
    """
    Extracts deduplicated (product, version) pairs along with affected hosts
    from technology_inventory.json / technology_inventory.csv.
    """
    # Key: (product_clean, version_clean) -> set of hosts
    version_map: Dict[Tuple[str, str], Set[str]] = {}

    tech_json_file = tech_dir / "technology_inventory.json"
    tech_csv_file = tech_dir / "technology_inventory.csv"

    parsed_any = False

    if tech_json_file.is_file():
        try:
            with open(tech_json_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        name = str(item.get("name") or "").strip()
                        version = item.get("version")
                        host = str(item.get("host") or "").strip()

                        if not name or name.lower() in IGNORE_NAMES:
                            continue
                        if not version or str(version).strip().upper() in {"NOT_EXPOSED", "UNKNOWN", "NONE", ""}:
                            continue
                        ver_str = str(version).strip()
                        if IP_PATTERN.match(ver_str):
                            continue

                        key = (name, ver_str)
                        if key not in version_map:
                            version_map[key] = set()
                        if host:
                            version_map[key].add(host)
                    parsed_any = True
        except Exception as exc:
            logger.warning(f"Error reading {tech_json_file}: {exc}")

    if not parsed_any and tech_csv_file.is_file():
        try:
            with open(tech_csv_file, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = str(row.get("name") or row.get("technology") or "").strip()
                    version = str(row.get("version") or "").strip()
                    host = str(row.get("host") or "").strip()

                    if not name or name.lower() in IGNORE_NAMES:
                        continue
                    if not version or version.upper() in {"NOT_EXPOSED", "UNKNOWN", "NONE", ""}:
                        continue
                    if IP_PATTERN.match(version):
                        continue

                    key = (name, version)
                    if key not in version_map:
                        version_map[key] = set()
                    if host:
                        version_map[key].add(host)
                    parsed_any = True
        except Exception as exc:
            logger.warning(f"Error reading {tech_csv_file}: {exc}")

    # Fallback to normalization asset_inventory if technology inventory had no versioned items
    if not parsed_any and norm_dir and norm_dir.is_dir():
        norm_asset_json = norm_dir / "asset_inventory.json"
        if norm_asset_json.is_file():
            try:
                with open(norm_asset_json, "r", encoding="utf-8-sig") as f:
                    assets = json.load(f)
                    for asset in assets:
                        host = str(asset.get("host") or "").strip()
                        for tech in asset.get("technologies", []):
                            if isinstance(tech, str) and ":" in tech:
                                parts = tech.split(":", 1)
                                p_name = parts[0].strip()
                                p_ver = parts[1].strip()
                                if p_name.lower() not in IGNORE_NAMES and p_ver:
                                    key = (p_name, p_ver)
                                    if key not in version_map:
                                        version_map[key] = set()
                                    if host:
                                        version_map[key].add(host)
            except Exception as exc:
                logger.warning(f"Error fallback reading {norm_asset_json}: {exc}")

    result = []
    for (product, version), hosts in sorted(version_map.items()):
        result.append({
            "product": product,
            "version": version,
            "hosts": sorted(list(hosts)),
        })

    return result


def detect_cves(config: CveConfig) -> Dict[str, Any]:
    """
    Main entry point for running CVE detection against a target run folder.
    """
    config.resolve_paths()
    run_dir = config.run_dir
    if not run_dir or not run_dir.is_dir():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")

    tech_dir = config.tech_dir or (run_dir / "technology_enrichment_v9_2")
    output_dir = config.output_dir or (run_dir / "cve_detection")
    norm_dir = run_dir / "normalization_v9"

    target_name = config.target or run_dir.name.split("-")[0]

    print("=" * 70)
    print(f"STAGE: 4/5 CVE Intelligence & Vulnerability Detection")
    print("=" * 70)
    print(f"Target Run: {run_dir.name}")
    print(f"Input Tech Dir: {tech_dir}")
    print(f"Output Dir: {output_dir}")
    print()

    versioned_items = extract_versioned_technologies(tech_dir, norm_dir)
    print(f"[OK] Identified {len(versioned_items)} unique versioned technologies for CVE mapping.")

    nvd_client = NvdClient(
        base_url=config.nvd_url,
        api_key=config.api_key,
        timeout=config.request_timeout,
        rate_limit_delay=config.rate_limit_delay,
        results_limit=config.results_per_product,
        offline=config.offline,
    )

    all_findings: List[Dict[str, Any]] = []
    scanned_products: List[Dict[str, Any]] = []

    for idx, item in enumerate(versioned_items, start=1):
        product = item["product"]
        version = item["version"]
        hosts = item["hosts"]

        print(f"[{idx}/{len(versioned_items)}] Querying CVEs for {product} {version} (affected hosts: {len(hosts)})...", flush=True)

        cve_results = nvd_client.search(product, version)

        scanned_products.append({
            "product": product,
            "version": version,
            "hosts": hosts,
            "cve_matches": len(cve_results),
        })

        for cve_item in cve_results:
            all_findings.append({
                "product": product,
                "version": version,
                "cve": cve_item["cve_id"],
                "severity": cve_item["severity"],
                "cvss": cve_item["cvss_score"],
                "cvss_version": cve_item["cvss_version"],
                "description": cve_item["description"],
                "source": cve_item["source"],
                "hosts": hosts,
                "confidence": "high",
                "evidence_source": "technology_enrichment_v9_2",
            })

    counts = save_all_outputs(output_dir, target_name, str(run_dir), all_findings, scanned_products)

    print()
    print("-" * 50)
    print(f"[COMPLETE] CVE Detection Finished:")
    print(f"  Total CVE Findings: {counts['total']}")
    print(f"  Critical: {counts['critical']}")
    print(f"  High:     {counts['high']}")
    print(f"  Medium:   {counts['medium']}")
    print(f"  Low:      {counts['low']}")
    print(f"  Outputs saved to: {output_dir}")
    print("-" * 50)

    return counts
