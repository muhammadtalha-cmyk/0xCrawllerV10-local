import json
import logging
from pathlib import Path
from typing import Any
import re
from datetime import datetime

logger = logging.getLogger("crawller.ingest")

def chunk_markdown(content: str, report_type: str, scan_id: str) -> list[tuple]:
    """Splits markdown into header-based chunks."""
    lines = content.split('\n')
    chunks = []
    current_header = "Introduction"
    current_level = 1
    current_content = []
    chunk_index = 0

    for line in lines:
        header_match = re.match(r'^(#{1,6})\s+(.*)', line)
        if header_match:
            if current_content:
                chunks.append((
                    scan_id,
                    report_type,
                    chunk_index,
                    current_header,
                    current_level,
                    '\n'.join(current_content)
                ))
                chunk_index += 1
            current_level = len(header_match.group(1))
            current_header = header_match.group(2)
            current_content = [line]
        else:
            current_content.append(line)

    if current_content:
        chunks.append((
            scan_id,
            report_type,
            chunk_index,
            current_header,
            current_level,
            '\n'.join(current_content)
        ))

    return chunks

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
    relationships_file = norm_dir / "asset_relationships.json"
    
    cve_dir = run_dir / "cve_detection"
    cve_file = cve_dir / "cve_findings.json"
    cve_report_file = cve_dir / "cve_report.md"

    combined_report_file = run_dir / "combined_vapt_intelligence_report.md"
    tech_report_file = tech_dir / "technology_enrichment_report.md"

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
    relationships_data = load_json(relationships_file) or []

    combined_report_text = ""
    if combined_report_file.is_file():
        combined_report_text = combined_report_file.read_text(encoding="utf-8", errors="replace")
        
    tech_report_text = ""
    if tech_report_file.is_file():
        tech_report_text = tech_report_file.read_text(encoding="utf-8", errors="replace")

    cve_data = load_json(cve_file) or {}
    cve_findings_data = cve_data.get("findings", []) if isinstance(cve_data, dict) else []

    cve_report_text = ""
    if cve_report_file.is_file():
        cve_report_text = cve_report_file.read_text(encoding="utf-8", errors="replace")

    # Map to track inserted asset hostnames/ips -> database asset IDs
    asset_id_map = {}
    ip_id_map = {}

    with db.connect() as conn:
        # Clear existing ingestion data for this scan to avoid duplicates on rerun
        conn.execute("DELETE FROM scan_metrics WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM report_sections WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM relationships WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM cve_findings WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM findings WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM endpoints WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM technologies WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM ports WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM dns_records WHERE scan_id = %s", (scan_id,))
        conn.execute("DELETE FROM assets WHERE scan_id = %s", (scan_id,))
        conn.commit()

        # Metrics tracking
        metrics = {
            "total_assets": len(assets_data),
            "total_services": len(services_data),
            "total_endpoints": len(endpoints_data),
            "total_technologies": len(tech_data),
            "total_findings": len(findings_data),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

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
                    if ip_address:
                        ip_id_map[ip_address] = asset_id

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

        # Helper to find asset ID by hostname or IP
        def get_asset_id(ident: str) -> Any:
            if not ident:
                return None
            ident_lower = ident.lower().strip()
            if ident_lower.startswith("host:"):
                ident_lower = ident_lower[5:]
            elif ident_lower.startswith("ip:"):
                ident_lower = ident_lower[3:]
                
            if ident_lower in asset_id_map:
                return asset_id_map[ident_lower]
            if ident_lower in ip_id_map:
                return ip_id_map[ident_lower]
                
            # Try prefix/substring match as fallback
            for host, aid in asset_id_map.items():
                if host in ident_lower or ident_lower in host:
                    return aid
            return None

        # Ingest Relationships
        with conn.cursor() as cursor:
            for rel in relationships_data:
                source_id = get_asset_id(rel.get("source_asset"))
                target_id = get_asset_id(rel.get("target_asset"))
                
                # Only insert if we mapped both to actual assets
                if source_id and target_id:
                    cursor.execute(
                        """
                        INSERT INTO relationships (scan_id, source_asset_id, target_asset_id, relationship_type, metadata)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (
                            scan_id,
                            source_id,
                            target_id,
                            rel.get("relationship", "unknown"),
                            json.dumps(rel)
                        )
                    )
        conn.commit()

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
            severity = info.get("severity", finding.get("severity", "info")).lower()
            desc = info.get("description", finding.get("description", ""))
            
            if severity in metrics:
                metrics[severity] += 1

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

        # Ingest CVE Findings
        for finding in cve_findings_data:
            cve_id = finding.get("cve", "CVE-UNKNOWN")
            product = finding.get("product", "Unknown")
            version = str(finding.get("version") or "")
            severity = finding.get("severity", "info").lower()
            cvss = finding.get("cvss")
            desc = finding.get("description", "")
            source = finding.get("source", "")
            hosts = finding.get("hosts", [])
            
            if not hosts:
                hosts = [""]
                
            for h in hosts:
                clean_host = h.strip()
                if "://" in clean_host:
                    clean_host = clean_host.split("://", 1)[1]
                clean_host = clean_host.split("/")[0].split(":")[0]
                asset_id = get_asset_id(clean_host) if clean_host else None
                
                if severity in metrics:
                    metrics[severity] += 1
                metrics["total_findings"] += 1
                
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO cve_findings (scan_id, asset_id, cve_id, product, version, cvss_score, severity, description, source, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (scan_id, asset_id, cve_id, product, version, float(cvss) if cvss is not None else None, severity, desc, source, utc_now())
                    )
                    cursor.execute(
                        """
                        INSERT INTO findings (scan_id, asset_id, finding_type, severity, confidence, description, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            scan_id,
                            asset_id,
                            cve_id,
                            severity,
                            "certain",
                            f"{product} {version}: {desc}".strip(),
                            "needs_validation"
                        )
                    )
        conn.commit()

        # Ingest Report Sections
        with conn.cursor() as cursor:
            if combined_report_text:
                chunks = chunk_markdown(combined_report_text, "combined_intelligence", scan_id)
                if chunks:
                    cursor.executemany(
                        """
                        INSERT INTO report_sections (scan_id, report_type, section_index, header, level, content)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        chunks
                    )
            
            if tech_report_text:
                chunks = chunk_markdown(tech_report_text, "technology_enrichment", scan_id)
                if chunks:
                    cursor.executemany(
                        """
                        INSERT INTO report_sections (scan_id, report_type, section_index, header, level, content)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        chunks
                    )

            if cve_report_text:
                chunks = chunk_markdown(cve_report_text, "cve_intelligence", scan_id)
                if chunks:
                    cursor.executemany(
                        """
                        INSERT INTO report_sections (scan_id, report_type, section_index, header, level, content)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        chunks
                    )
        conn.commit()

        # Ingest Metrics
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO scan_metrics (scan_id, total_assets, total_services, total_endpoints, 
                                          total_findings, total_technologies, severity_critical, 
                                          severity_high, severity_medium, severity_low, severity_info)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    scan_id,
                    metrics["total_assets"],
                    metrics["total_services"],
                    metrics["total_endpoints"],
                    metrics["total_findings"],
                    metrics["total_technologies"],
                    metrics["critical"],
                    metrics["high"],
                    metrics["medium"],
                    metrics["low"],
                    metrics["info"]
                )
            )
        conn.commit()

    logger.info(f"Completed database ingestion for scan {scan_id}")
