from __future__ import annotations

import json
from pathlib import Path

from asset_normalization.endpoint_rules import normalize_endpoint
from asset_normalization.engine import normalize_run
from asset_normalization.policy import determine_ownership, route_testing


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def make_run(tmp_path: Path) -> Path:
    run = tmp_path / "example.com-20260728-120000"
    run.mkdir()
    write(run / "summary.json", {"program_version": "8.5.1", "target": "example.com", "created_at": "2026-07-28T12:00:00Z", "canonical_target_reachable": True, "canonical_target": {"url": "https://example.com", "evidence": {"status_code": 200}}})
    write(run / "validated_dns_hosts.json", {
        "app.example.com": {"host": "app.example.com", "a": ["203.0.113.10"], "cname": [], "validation_state": "dns_resolved", "timestamp": "2026-07-28T12:00:00Z"},
        "saas.example.com": {"host": "saas.example.com", "a": ["198.51.100.10"], "cname": ["tenant.samanage.com"], "validation_state": "dns_resolved"},
    })
    write(run / "carried_forward_unvalidated.json", {"old.example.com": {"host": "old.example.com", "a": ["203.0.113.55"], "validation_state": "previous_run_unvalidated", "previous_run_dir": "older"}})
    write(run / "http_review_classification.json", [
        {"host": "app.example.com", "url": "https://app.example.com", "status_code": 200, "title": "App", "category": "Unknown / Needs Review", "priority": "Medium", "ownership": "first_party_or_unknown", "technologies": ["Nginx"], "cdn_detection": {"detected": False}, "waf_detection": {"detected": False}},
        {"host": "saas.example.com", "url": "https://saas.example.com", "status_code": 200, "title": "SaaS", "ownership": "third_party_saas", "application_provider": "SolarWinds Service Desk", "cdn_detection": {"detected": True, "provider": "Google"}, "waf_detection": {"detected": False}},
    ])
    write(run / "endpoint_classification.json", {"records": [
        {"url": "https://app.example.com/api/v1", "normalized_url": "https://app.example.com/api/v1", "host": "app.example.com", "path": "/api/v1", "category": "API Endpoint", "priority": "High"},
        {"url": "https://app.example.com/%5C/app.example.com%5C/admin", "normalized_url": "https://app.example.com/app.example.com/admin", "host": "app.example.com", "path": "/app.example.com/admin", "category": "Other Endpoint", "priority": "Low"},
    ]})
    write(run / "port_candidate_reconciliation.json", [
        {"host": "app.example.com", "port": 443, "protocol": "tcp", "candidate_status": "NAABU_CANDIDATE", "final_status": "NMAP_CONFIRMED_OPEN", "nmap_state": "open", "nmap_service": "https"},
        {"host": "app.example.com", "port": 22, "protocol": "tcp", "candidate_status": "NAABU_CANDIDATE", "final_status": "NMAP_NOT_CONFIRMED", "nmap_state": "filtered"},
        {"host": "app.example.com", "port": 0, "protocol": "tcp", "final_status": "NMAP_CONFIRMED_OPEN"},
    ])
    write(run / "recon_topology.json", {"nodes": {"app.example.com": {"host": "app.example.com", "level": 1, "sources": ["initial_inventory"]}}, "edges": [{"parent": "example.com", "child": "app.example.com", "source": "initial_inventory", "level": 1}, {"parent": "app.example.com", "child": "2fapp.example.com", "source": "bad_encoded", "level": 2}]})
    return run


def test_third_party_cname_precedence():
    result = determine_ownership(host="x.example.com", root="example.com", dns={"cname": ["tenant.samanage.com"], "a": ["1.2.3.4"]}, http={"ownership": "first_party_or_unknown"}, historical_only=False)
    assert result["classification"] == "third_party_saas"
    assert result["provider"] == "SolarWinds Service Desk"


def test_cdn_routes_block_network():
    result = route_testing(ownership={"classification": "cdn_edge_or_first_party_frontend"}, has_http=True, current_dns=True, confirmed_ports=True, asset_types=["web_application"], waf={})
    assert result["routes"]["safe_web_templates"] is True
    assert result["routes"]["openvas_remote_checks"] is False


def test_suspicious_endpoint_detection():
    record = normalize_endpoint({"url": "https://app.example.com/%5C/app.example.com%5C/admin", "normalized_url": "https://app.example.com/app.example.com/admin", "category": "Other Endpoint", "priority": "Low"}, {"app.example.com"})
    assert record and record["state"] == "SYNTACTICALLY_SUSPICIOUS"


def test_full_engine(tmp_path: Path):
    run = make_run(tmp_path)
    out = tmp_path / "out"
    result = normalize_run(run, out)
    hosts = {a["host"] for a in result.assets}
    assert "2fapp.example.com" not in hosts
    assert "old.example.com" in hosts
    app = next(a for a in result.assets if a["host"] == "app.example.com")
    assert app["confirmed_open_ports"] == [443]
    assert all(p["port"] != 0 for p in app["ports"])
    saas = next(a for a in result.assets if a["host"] == "saas.example.com")
    assert saas["testing_policy"]["decision"] == "THIRD_PARTY_RESTRICTED"
    assert (out / "asset_inventory.json").exists()
    assert (out / "asset_normalization_report.md").exists()
    assert any(c["type"] == "port_validation_conflict" for c in result.conflicts)


def test_compatibility_fallback_without_reconciliation_file(tmp_path: Path):
    run = make_run(tmp_path)
    (run / "port_candidate_reconciliation.json").unlink()
    write(run / "naabu_ports.json", [{"host": "app.example.com", "port": 8443, "protocol": "tcp"}])
    write(run / "nmap_services.json", [])
    result = normalize_run(run, tmp_path / "fallback")
    app = next(a for a in result.assets if a["host"] == "app.example.com")
    assert any(p["port"] == 8443 and p["final_status"] == "NAABU_CANDIDATE_UNVALIDATED" for p in app["ports"])

from asset_normalization.identity import in_scope, is_valid_host, normalize_host, normalize_url
from asset_normalization.io_utils import latest_run


def test_identity_normalization():
    assert normalize_host("HTTPS://Admin.Example.COM./x") == "admin.example.com"
    assert normalize_url("HTTPS://Admin.Example.COM:443/a#frag") == "https://admin.example.com/a"


def test_scope_boundaries():
    assert in_scope("a.example.com", "example.com")
    assert in_scope("example.com", "example.com")
    assert not in_scope("evil-example.com", "example.com")


def test_invalid_encoded_host_rejected():
    assert not is_valid_host("2f%2fadmin.example.com")
    assert not is_valid_host("bad\\host.example.com")


def test_historical_ownership():
    result = determine_ownership(host="old.example.com", root="example.com", dns={}, http=None, historical_only=True)
    assert result["classification"] == "historical_unresolved"


def test_first_party_direct_route_allows_network():
    result = route_testing(ownership={"classification": "first_party_or_unknown"}, has_http=True, current_dns=True, confirmed_ports=True, asset_types=["web_application"], waf={})
    assert result["decision"] == "ALLOWED_ACTIVE"
    assert result["routes"]["openvas_remote_checks"] is True


def test_third_party_route_blocks_everything():
    result = route_testing(ownership={"classification": "third_party_saas"}, has_http=True, current_dns=True, confirmed_ports=True, asset_types=["third_party_saas"], waf={})
    assert result["decision"] == "THIRD_PARTY_RESTRICTED"
    assert not any(result["routes"].values())


def test_static_endpoint_state():
    record = normalize_endpoint({"url": "https://app.example.com/a.js", "category": "JavaScript/Static Bundle", "priority": "Medium"}, {"app.example.com"})
    assert record and record["state"] == "STATIC_ASSET"
    assert record["requires_http_revalidation"] is False


def test_validated_root_endpoint_state():
    record = normalize_endpoint({"url": "https://app.example.com/", "category": "Other Endpoint", "priority": "Low"}, {"app.example.com"})
    assert record and record["state"] == "VALIDATED_ROOT_ENDPOINT"


def test_outputs_are_complete(tmp_path: Path):
    result = normalize_run(make_run(tmp_path), tmp_path / "complete")
    expected = {
        "asset_inventory.json", "asset_inventory.csv", "service_inventory.json", "service_inventory.csv",
        "endpoint_inventory.json", "endpoint_inventory.csv", "asset_relationships.json",
        "asset_conflicts.json", "asset_revalidation_queue.json", "testing_eligibility.json",
        "normalization_summary.json", "asset_normalization_report.md",
    }
    assert expected == {p.name for p in result.output_dir.iterdir() if p.is_file()}


def test_shodan_stays_passive(tmp_path: Path):
    run = make_run(tmp_path)
    write(run / "shodan_assets.json", {"203.0.113.10": {"ip": "203.0.113.10", "ports": [9999], "last_seen": ["2025-01-01T00:00:00"]}})
    result = normalize_run(run, tmp_path / "shodan")
    app = next(a for a in result.assets if a["host"] == "app.example.com")
    assert app["passive_observations"]["shodan"]["available"] is True
    assert 9999 not in app["confirmed_open_ports"]


def test_multilayer_waf_conflict(tmp_path: Path):
    run = make_run(tmp_path)
    records = json.loads((run / "http_review_classification.json").read_text())
    records[0]["waf_detection"] = {"detected": True, "provider": "Cloudflare / Azure Front Door", "providers": ["Cloudflare", "Azure Front Door"], "attribution": "conflicting_or_multi_layer"}
    write(run / "http_review_classification.json", records)
    result = normalize_run(run, tmp_path / "multi")
    assert any(c["type"] == "multi_layer_edge_attribution" for c in result.conflicts)


def test_latest_run_selection(tmp_path: Path):
    older = tmp_path / "example.com-20260101-000000"
    newer = tmp_path / "example.com-20260728-120000"
    older.mkdir(); newer.mkdir()
    older.touch(); newer.touch()
    assert latest_run(tmp_path, "example.com") == newer


def test_existing_output_requires_overwrite(tmp_path: Path):
    run = make_run(tmp_path)
    out = tmp_path / "existing"
    out.mkdir(); (out / "x.txt").write_text("x")
    try:
        normalize_run(run, out)
    except FileExistsError:
        pass
    else:
        raise AssertionError("Expected FileExistsError")
