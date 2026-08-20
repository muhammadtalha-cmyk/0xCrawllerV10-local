import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("crawller.ingest")

def ingest_scan_results(db: Any, scan_id: str, run_dir_path: str) -> None:
    """Parses run inventory files and ingests structured data into PostgreSQL."""
    run_dir = Path(run_dir_path)
    if not run_dir.is_dir():
        logger.error(f"Run directory {run_dir} does not exist. Skipping ingestion.")
        return

    logger.info(f"Starting database ingestion for scan {scan_id} from {run_dir}")

    # Determine paths
    norm_dir = run_dir / "normalization_v9"
    tech_dir = run_dir / "technology_enrichment_v9_2"

    assets_file = tech_dir / "asset_inventory_enriched.json"
    if not assets_file.is_file():
        assets_file = norm_dir / "asset_inventory.json"

    services_file = tech_dir / "service_inventory_enriched.json"
    if not services_file.is_file():
        services_file = norm_dir / "service_inventory.json"

    tech_file = tech_dir / "technology_inventory.json"
    endpoints_file = norm_dir / "endpoint_inventory.json"
    findings_file = tech_dir / "vulnerability_findings.json"

    # Helpers to load JSON
    def load_json(path: Path) -> Any:
        if not path.is_file():
            return None
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading JSON from {path}: {e}")
            return None

    # Load data
    assets_data = load_json(assets_file) or []
    services_data = load_json(services_file) or []
    tech_data = load_json(tech_file) or []
    endpoints_data = load_json(endpoints_file) or []
    findings_data = load_json(findings_file) or []

    # Map to track inserted asset hostnames -> database asset IDs
    asset_id_map = {}

    with db.connect() as conn:
        # Clear existing ingestion data for this scan to avoid duplicates on rerun
        conn.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM endpoints WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM technologies WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM ports WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM dns_records WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM assets WHERE scan_id = %s", (scan_id,))
        conn.commit()

        # Ingest Assets
        for asset in assets_data:
            host = asset.get("host", "").strip()
            if not host:
                continue

            dns_info = asset.get("dns", {})
            ips = dns_info.get("a", [])
            ip_address = ips[0] if ips else None
            
            asset_types = asset.get("asset_types", [])
            asset_type = ",".join(asset_types) if isinstance(asset_types, list) else str(asset_types)
            
            status = "live" if asset.get("http", {}).get("live") else "dead"
            source = asset.get("ownership", {}).get("source", "recon")

            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO assets (scan_id, hostname, fqdn, asset_type, ip_address, status, source, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        scan_id,
                        host,
                        host,
                        asset_type,
                        ip_address,
                        status,
                        source,
                        json.dumps(asset)
                    )
                )
                row = cursor.fetchone()
                if row:
                    asset_id = row["id"]
                    asset_id_map[host.lower()] = asset_id

                    # Ingest DNS Records
                    for record_type in ("a", "aaaa", "cname"):
                        vals = dns_info.get(record_type, [])
                        for val in vals:
                            cursor.execute(
                                """
                                INSERT INTO dns_records (scan_id, asset_id, record_type, value, ttl, source)
                                VALUES (%s, %s, %s, %s, %s, %s)
                                """,
                                (scan_id, asset_id, record_type.upper(), str(val), 300, "dnsx")
                            )
        conn.commit()

        # Helper to find asset ID by hostname
        def get_asset_id(hostname: str) -> Any:
            if not hostname:
                return None
            h_lower = hostname.lower().strip()
            # Try exact match first
            if h_lower in asset_id_map:
                return asset_id_map[h_lower]
            # Try prefix/substring match as fallback
            for host, aid in asset_id_map.items():
                if host in h_lower or h_lower in host:
                    return aid
            return None

        # Ingest Ports/Services
        for svc in services_data:
            host = svc.get("host", "")
            asset_id = get_asset_id(host)
            
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO ports (scan_id, asset_id, port, protocol, state, service, banner)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_id,
                        asset_id,
                        svc.get("port"),
                        svc.get("protocol", "tcp"),
                        svc.get("final_status", "open"),
                        svc.get("product", svc.get("service_family", "")),
                        svc.get("version", "")
                    )
                )
        conn.commit()

        # Ingest Technologies
        for tech in tech_data:
            host = tech.get("host", "")
            asset_id = get_asset_id(host)

            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO technologies (scan_id, asset_id, name, category, version, confidence, detection_source, evidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_id,
                        asset_id,
                        tech.get("name"),
                        tech.get("category"),
                        str(tech.get("version")) if tech.get("version") is not None else None,
                        tech.get("confidence", "high"),
                        ",".join(tech.get("sources", [])),
                        json.dumps(tech)
                    )
                )
        conn.commit()

        # Ingest Endpoints
        for ep in endpoints_data:
            host = ep.get("host", "")
            asset_id = get_asset_id(host)

            url = ep.get("url", "")
            path = url.split("?", 1)[0] if url else ""

            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO endpoints (scan_id, asset_id, url, path, method, status_code, content_type, source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_id,
                        asset_id,
                        url,
                        path,
                        ep.get("method", "GET"),
                        ep.get("status_code"),
                        None,
                        ep.get("category", "endpoint")
                    )
                )
        conn.commit()

        # Ingest Findings (Vulnerabilities)
        for finding in findings_data:
            host = finding.get("host", finding.get("matched-at", ""))
            # strip scheme/port
            if "://" in host:
                host = host.split("://", 1)[1]
            host = host.split("/")[0].split(":")[0]
            
            asset_id = get_asset_id(host)

            info = finding.get("info", {})
            severity = info.get("severity", finding.get("severity", "info"))
            desc = info.get("description", finding.get("description", ""))

            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO findings (scan_id, asset_id, finding_type, severity, confidence, description, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        scan_id,
                        asset_id,
                        finding.get("template-id", finding.get("template", "vulnerability")),
                        severity,
                        "certain",
                        desc or finding.get("template", "Unnamed finding"),
                        "needs_validation"
                    )
                )
        conn.commit()

    logger.info(f"Completed database ingestion for scan {scan_id}")
