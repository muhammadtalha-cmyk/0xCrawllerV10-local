from pathlib import Path

from app.artifacts import artifact_kind
from app.database import Database
from app.orchestrator import Orchestrator


def test_target_normalization() -> None:
    assert Orchestrator.normalize_target("https://Example.COM/path") == "example.com"


def test_target_rejects_commands() -> None:
    for value in ("example.com & whoami", "example.com:443", "localhost", "https://"):
        try:
            Orchestrator.normalize_target(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"unsafe target accepted: {value}")


def test_database_scan_lifecycle(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    scan_id = db.create_scan("example.com")
    scan = db.get_scan(scan_id)
    assert scan is not None
    assert scan["status"] == "queued"
    assert len(scan["steps"]) == 5
    db.update_scan(scan_id, status="running", progress=25)
    assert db.get_scan(scan_id)["progress"] == 25  # type: ignore[index]


def test_cve_ingestion_with_utc_now(tmp_path: Path) -> None:
    import pytest
    from app.config import settings
    from app.ingest import ingest_scan_results
    import json
    
    if not settings.database_url:
        pytest.skip("PostgreSQL required for ingestion test")

    db = Database(settings.database_path, settings.database_url)
    scan_id = db.create_scan("cve-test.example.com")
    
    # Create mock run directory structure
    run_dir = tmp_path / "recon_run"
    cve_dir = run_dir / "cve_detection"
    cve_dir.mkdir(parents=True)
    
    cve_data = {
        "status": "COMPLETE",
        "findings": [
            {
                "product": "TestProduct",
                "version": "1.0",
                "cve": "CVE-2026-9999",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "description": "Test vulnerability",
                "source": "https://nvd.nist.gov",
                "hosts": ["example.com"]
            }
        ]
    }
    (cve_dir / "cve_findings.json").write_text(json.dumps(cve_data))
    
    # Ensure ingest executes without NameError or crash
    ingest_scan_results(db, scan_id, str(run_dir))
    
    # Verify CVE finding was written into findings table
    findings = db.get_findings_paginated(scan_id, 10, 0)
    assert findings["total"] >= 1
    assert findings["items"][0]["finding_type"] == "CVE-2026-9999"


def test_artifact_classification() -> None:
    assert artifact_kind(Path("final_report.md")) == "report"
    assert artifact_kind(Path("httpx_screenshots/screenshot/home.png")) == "screenshot"
    assert artifact_kind(Path("normalization_v9/asset_inventory.json")) == "data"
