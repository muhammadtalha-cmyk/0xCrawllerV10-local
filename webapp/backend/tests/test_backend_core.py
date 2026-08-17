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
    assert len(scan["steps"]) == 4
    db.update_scan(scan_id, status="running", progress=25)
    assert db.get_scan(scan_id)["progress"] == 25  # type: ignore[index]


def test_artifact_classification() -> None:
    assert artifact_kind(Path("final_report.md")) == "report"
    assert artifact_kind(Path("httpx_screenshots/screenshot/home.png")) == "screenshot"
    assert artifact_kind(Path("normalization_v9/asset_inventory.json")) == "data"
