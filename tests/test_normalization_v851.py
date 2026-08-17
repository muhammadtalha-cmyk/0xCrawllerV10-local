from pathlib import Path

from smart_recon.screenshots import screenshot_artifact_summary, select_live_urls


def test_screenshot_summary_separates_unique_content_from_artifacts(tmp_path: Path):
    first = tmp_path / "httpx_screenshots" / "screenshot" / "api.example.com" / "a.png"
    duplicate = tmp_path / "recursive" / "level_01" / "screenshots" / "screenshot" / "api.example.com" / "b.png"
    other = tmp_path / "httpx_screenshots" / "screenshot" / "admin.example.com" / "c.png"
    for path in (first, duplicate, other):
        path.parent.mkdir(parents=True, exist_ok=True)
    first.write_bytes(b"same-image")
    duplicate.write_bytes(b"same-image")
    other.write_bytes(b"different-image")

    files = [str(path.relative_to(tmp_path)) for path in (first, duplicate, other)]
    summary = screenshot_artifact_summary(tmp_path, files)
    assert summary["total_artifact_files"] == 3
    assert summary["unique_content_images"] == 2
    assert summary["duplicate_content_artifacts"] == 1
    assert summary["unique_hosts_captured"] == 2


def test_screenshot_selection_keeps_one_best_url_per_host():
    records = [
        {"host": "api.example.com", "url": "http://api.example.com", "status_code": 200},
        {"host": "api.example.com", "url": "https://api.example.com", "status_code": 200},
        {"host": "admin.example.com", "url": "https://admin.example.com", "status_code": 403},
    ]
    selected, coverage = select_live_urls(records, 10)
    assert "https://api.example.com" in selected
    assert "http://api.example.com" not in selected
    assert len(selected) == 2
    assert coverage["eligible_unique_hosts"] == 2
    assert coverage["selected_unique_hosts"] == 2
