from __future__ import annotations

import json
from pathlib import Path

from technology_enrichment.config import EnrichmentConfig, auto_workers
from technology_enrichment.engine import _build_revalidation_queue, enrich_run
from technology_enrichment.http_evidence import extract_http_technologies
from technology_enrichment.nuclei_runner import parse_nuclei_findings
from technology_enrichment.reconcile import parse_existing_technology, reconcile_technology
from technology_enrichment.retirejs_runner import parse_retirejs
from technology_enrichment.target_planner import build_plan
from technology_enrichment.whatweb_runner import parse_whatweb_records
from technology_enrichment.zgrab2_runner import _normalise_record


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _fixture_normalization(path: Path) -> None:
    assets = [
        {
            "schema_version": "9.0.0", "asset_id": "host:app.example.com", "host": "app.example.com", "root_domain": "example.com",
            "asset_types": ["web_application", "admin_or_management_surface"],
            "ownership": {"classification": "first_party_or_unknown"},
            "http": {"live": True, "primary_url": "https://app.example.com/", "priority": "High"},
            "dns": {"a": ["192.0.2.10"]},
            "technologies": ["PHP:8.3.31", "WordPress:6.7.1"],
            "testing_policy": {"active_testing_allowed": True, "routes": {"network_service_checks": True}},
        },
        {
            "schema_version": "9.0.0", "asset_id": "host:cdn.example.com", "host": "cdn.example.com", "root_domain": "example.com",
            "asset_types": ["web_application", "cdn_fronted_web"],
            "ownership": {"classification": "cdn_edge_or_first_party_frontend"},
            "http": {"live": True, "primary_url": "https://cdn.example.com/", "priority": "Medium"},
            "dns": {"a": ["198.51.100.10"]}, "technologies": ["Cloudflare"],
            "testing_policy": {"active_testing_allowed": True, "routes": {"network_service_checks": False}},
        },
        {
            "schema_version": "9.0.0", "asset_id": "host:saas.example.com", "host": "saas.example.com", "root_domain": "example.com",
            "asset_types": ["third_party_saas", "web_application"],
            "ownership": {"classification": "third_party_saas"},
            "http": {"live": True, "primary_url": "https://saas.example.com/", "priority": "Medium"},
            "dns": {"a": ["203.0.113.10"]}, "technologies": ["Ruby on Rails"],
            "testing_policy": {"active_testing_allowed": False, "routes": {"network_service_checks": False}},
        },
    ]
    services = [
        {"service_id": "service:app.example.com:tcp:3306", "asset_id": "host:app.example.com", "host": "app.example.com", "port": 3306, "protocol": "tcp", "service_family": "mysql", "final_status": "NMAP_CONFIRMED_OPEN", "product": "MySQL", "version": "8.0.36"},
        {"service_id": "service:cdn.example.com:tcp:443", "asset_id": "host:cdn.example.com", "host": "cdn.example.com", "port": 443, "protocol": "tcp", "service_family": "https", "final_status": "HTTP_VALIDATED"},
    ]
    endpoints = [
        {"endpoint_id": "url:https://app.example.com/static/jquery-3.7.1.min.js", "url": "https://app.example.com/static/jquery-3.7.1.min.js", "host": "app.example.com", "category": "JavaScript/Static Bundle", "state": "STATIC_ASSET", "requires_http_revalidation": False},
        {"endpoint_id": "url:https://app.example.com/bad.js", "url": "https://app.example.com/bad.js", "host": "app.example.com", "category": "JavaScript/Static Bundle", "state": "SYNTACTICALLY_SUSPICIOUS", "requires_http_revalidation": True},
    ]
    _write(path / "asset_inventory.json", assets)
    _write(path / "service_inventory.json", services)
    _write(path / "endpoint_inventory.json", endpoints)


def test_parse_existing_wappalyzer_version():
    assert parse_existing_technology("PHP:8.3.31") == ("PHP", "8.3.31")
    assert parse_existing_technology("Cloudflare") == ("Cloudflare", None)


def test_http_evidence_detects_django_but_does_not_invent_version():
    record = {
        "headers": {"set-cookie": ["csrftoken=abc; Path=/", "sessionid=def; Path=/"]},
        "body_text": '<form><input name="csrfmiddlewaretoken"><link href="/static/admin/css/base.css"></form>',
    }
    tech = extract_http_technologies(record)
    django = [item for item in tech if item["name"] == "Django"]
    assert django
    assert all(item.get("version") is None for item in django)


def test_http_evidence_extracts_explicit_versions():
    record = {
        "headers": {"server": ["nginx/1.26.3"], "x-powered-by": ["PHP/8.3.31"]},
        "body_text": '<meta name="generator" content="WordPress 6.7.1"><script src="jquery-3.7.1.min.js"></script>',
    }
    tech = extract_http_technologies(record)
    pairs = {(item["name"], item.get("version")) for item in tech}
    assert ("Nginx", "1.26.3") in pairs
    assert ("PHP", "8.3.31") in pairs
    assert ("WordPress", "6.7.1") in pairs
    assert ("jQuery", "3.7.1") in pairs


def test_database_error_is_reference_not_service_confirmation():
    record = {"headers": {}, "body_text": "django.db.utils.OperationalError: could not connect to PostgreSQL server"}
    tech = extract_http_technologies(record)
    postgres = next(item for item in tech if item["name"] == "PostgreSQL")
    assert postgres["scope"] == "application_reference_not_service_confirmation"
    assert postgres["confidence_score"] < 0.7


def test_plan_excludes_third_party_and_cdn_network(tmp_path: Path):
    norm = tmp_path / "normalization_v9"
    _fixture_normalization(norm)
    plan = build_plan(norm, max_web=100, max_services=100, max_js=100)
    assert {item["host"] for item in plan.web_targets} == {"app.example.com", "cdn.example.com"}
    assert [item["host"] for item in plan.service_targets] == ["app.example.com"]
    assert plan.service_targets[0]["zgrab2_module"] == "mysql"
    assert [item["url"] for item in plan.js_targets] == ["https://app.example.com/static/jquery-3.7.1.min.js"]


def test_whatweb_parser_keeps_versions():
    raw = [{"target": "https://app.example.com", "http_status": 200, "plugins": {"PHP": {"version": ["8.3.31"]}, "Django": {"string": ["Django admin"]}}}]
    parsed = parse_whatweb_records(raw)
    by_name = {item["name"]: item for item in parsed[0]["technologies"]}
    assert by_name["PHP"]["versions"] == ["8.3.31"]
    assert by_name["Django"]["versions"] == []


def test_retire_parser_maps_component_to_host():
    raw = [{"file": "/workspace/app.example.com__abc__jquery.js", "results": [{"component": "jquery", "version": "3.7.1", "vulnerabilities": []}]}]
    manifest = [{"filename": "app.example.com__abc__jquery.js", "host": "app.example.com", "url": "https://app.example.com/jquery.js"}]
    parsed = parse_retirejs(raw, manifest)
    assert parsed[0]["host"] == "app.example.com"
    assert parsed[0]["version"] == "3.7.1"


def test_zgrab_normalization_extracts_version_fields():
    target = {"service_id": "service:db.example.com:tcp:3306", "asset_id": "host:db.example.com", "host": "db.example.com", "ip": "192.0.2.5", "port": 3306, "protocol": "tcp"}
    raw = {"ip": "192.0.2.5", "domain": "db.example.com", "data": {"mysql": {"status": "success", "result": {"server_version": "8.0.36", "protocol_version": 10}}}}
    record = _normalise_record("mysql", [target], raw)
    assert record["success"] is True
    assert any(item["value"] == "8.0.36" for item in record["version_product_fields"])


def test_reconcile_detects_version_conflict():
    assets = [{"asset_id": "host:app.example.com", "host": "app.example.com", "technologies": ["PHP:8.2.0"]}]
    result = reconcile_technology(
        assets, [],
        {"records": [{"host": "app.example.com", "technologies": [{"name": "PHP", "version": "8.3.31", "source": "custom_http_evidence", "category": "Programming Language", "confidence_score": 0.96, "scope": "web_application"}]}]},
        {}, {}, {},
    )
    php = next(item for item in result["technology_inventory"] if item["name"] == "PHP")
    assert php["version_status"] == "CONFLICTING"
    assert result["technology_conflicts"]


def test_reconcile_network_db_is_service_confirmed():
    assets = [{"asset_id": "host:db.example.com", "host": "db.example.com", "technologies": []}]
    services = [{"service_id": "service:db.example.com:tcp:3306", "host": "db.example.com", "port": 3306, "protocol": "tcp", "product": "MySQL", "version": "8.0.36"}]
    result = reconcile_technology(assets, services, {}, {}, {}, {})
    mysql = next(item for item in result["technology_inventory"] if item["name"] == "MySQL")
    assert mysql["service_confirmed"] is True
    assert mysql["version"] == "8.0.36"


def test_auto_worker_caps():
    assert auto_workers(100, ceiling=8) == 8
    assert auto_workers(0, ceiling=8) == 1


def test_max_config_uses_bounded_settings():
    config = EnrichmentConfig.create(max_mode=True, workers=100, http_workers=100, js_workers=100, service_workers=100, whatweb_threads=100, request_timeout=10, lane_timeout=900, whatweb_image=None, retirejs_image=None, zgrab2_image=None)
    assert config.lane_workers == 5
    assert config.http_workers == 16
    assert config.service_workers == 8
    assert config.whatweb_aggression == 3
    assert config.max_web_targets == 250


def test_offline_engine_smoke(tmp_path: Path):
    run = tmp_path / "recon_runs" / "example.com-20260729-000000"
    run.mkdir(parents=True)
    norm = run / "normalization_v9"
    _fixture_normalization(norm)
    config = EnrichmentConfig.create(max_mode=False, workers=4, http_workers=4, js_workers=4, service_workers=4, whatweb_threads=4, request_timeout=5, lane_timeout=60, whatweb_image=None, retirejs_image=None, zgrab2_image=None)
    result = enrich_run(run, run / "technology_enrichment_v9_1", config=config, overwrite=True, offline=True)
    assert result.summary["status"] == "COMPLETE"
    assert result.summary["counts"]["technologies"] >= 3
    assert (result.output_dir / "technology_inventory.json").exists()
    assert (result.output_dir / "technology_enrichment_report.md").exists()
    php = next(item for item in result.technologies if item["name"] == "PHP")
    assert php["version"] == "8.3.31"

from technology_enrichment.wappalyzer_next_runner import parse_wappalyzer_next


def test_wappalyzer_next_parser_preserves_version_confidence_and_categories():
    raw = {
        "https://app.example.com": {
            "Django": {"version": "5.2.1", "confidence": 100, "categories": ["Web frameworks"], "groups": ["Web development"]},
            "PostgreSQL": {"version": "16", "confidence": 72, "categories": ["Databases"], "groups": ["Data stores"]},
        }
    }
    rows = parse_wappalyzer_next(raw, scan_type="full")
    by_name = {item["name"]: item for item in rows[0]["technologies"]}
    assert by_name["Django"]["version"] == "5.2.1"
    assert by_name["Django"]["confidence_score"] == 1.0
    assert by_name["Django"]["category"] == "Web Framework"
    assert by_name["PostgreSQL"]["scope"] == "application_reference_not_service_confirmation"


def test_reconcile_accepts_wappalyzer_next_without_confirming_database_service():
    assets = [{"asset_id": "host:app.example.com", "host": "app.example.com", "technologies": []}]
    dynamic = {
        "records": [{
            "target": "https://app.example.com",
            "host": "app.example.com",
            "scan_type": "full",
            "technologies": [
                {"name": "Django", "version": "5.2.1", "category": "Web Framework", "scope": "web_application", "confidence_score": 1.0},
                {"name": "PostgreSQL", "version": "16", "category": "Database", "scope": "application_reference_not_service_confirmation", "confidence_score": 0.72},
            ],
        }]
    }
    result = reconcile_technology(assets, [], {}, {}, {}, {}, wappalyzer_next_lane=dynamic)
    django = next(item for item in result["technology_inventory"] if item["name"] == "Django")
    postgres = next(item for item in result["technology_inventory"] if item["name"] == "PostgreSQL")
    assert django["version"] == "5.2.1"
    assert "wappalyzer_next" in django["sources"]
    assert postgres["service_confirmed"] is False
    assert postgres["application_reference_only"] is True


def test_v92_config_caps_browser_workers_and_expands_lane_pool():
    config = EnrichmentConfig.create(
        max_mode=True, workers=100, http_workers=100, js_workers=100,
        service_workers=100, whatweb_threads=100, request_timeout=10,
        lane_timeout=900, whatweb_image=None, retirejs_image=None,
        zgrab2_image=None, wappalyzer_next_workers=100,
        wappalyzer_next_balanced_workers=100,
        wappalyzer_next_full_target_cap=500,
    )
    assert config.lane_workers == 5
    assert config.wappalyzer_next_full_workers == 3
    assert config.wappalyzer_next_balanced_workers == 20
    assert config.wappalyzer_next_full_target_cap == 50


def test_httpx_wappalyzer_database_is_reference_until_network_confirmed():
    assets = [{"asset_id": "host:app.example.com", "host": "app.example.com", "technologies": ["MySQL"]}]
    result = reconcile_technology(assets, [], {}, {}, {}, {})
    mysql = next(item for item in result["technology_inventory"] if item["name"] == "MySQL")
    assert mysql["service_confirmed"] is False
    assert mysql["application_reference_only"] is True


def test_parse_nuclei_findings_extracts_cve_and_dedupes():
    raw_jsonl = "\n".join([
        '{"template-id":"apache-version-detect","info":{"name":"Apache Version","severity":"info","classification":{}},'
        '"host":"https://app.example.com","matched-at":"https://app.example.com","type":"http"}',
        '{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal","severity":"critical",'
        '"classification":{"cve-id":["CVE-2021-41773"]}},"host":"https://app.example.com",'
        '"matched-at":"https://app.example.com/icons/","type":"http"}',
        # exact duplicate of the line above -- must be deduplicated
        '{"template-id":"CVE-2021-41773","info":{"name":"Apache Path Traversal","severity":"critical",'
        '"classification":{"cve-id":["CVE-2021-41773"]}},"host":"https://app.example.com",'
        '"matched-at":"https://app.example.com/icons/","type":"http"}',
        "not-valid-json",
        "",
    ])
    findings = parse_nuclei_findings(raw_jsonl)
    assert len(findings) == 2
    critical = next(f for f in findings if f["severity"] == "CRITICAL")
    assert critical["cve"] == ["CVE-2021-41773"]
    assert critical["template_id"] == "CVE-2021-41773"
    info = next(f for f in findings if f["severity"] == "INFO")
    assert info["cve"] == []


def test_parse_nuclei_findings_handles_empty_and_garbage_input():
    assert parse_nuclei_findings("") == []
    assert parse_nuclei_findings("not json\nalso not json") == []


def test_revalidation_queue_flags_high_and_critical_nuclei_findings_only():
    vulnerability_findings = [
        {"host": "app.example.com", "template_name": "Info Disclosure", "severity": "INFO"},
        {"host": "app.example.com", "template_name": "Path Traversal", "severity": "CRITICAL"},
        {"host": "app.example.com", "template_name": "Outdated Header", "severity": "HIGH"},
    ]
    queue = _build_revalidation_queue([], [], {}, vulnerability_findings)
    reasons = [item["reason"] for item in queue]
    assert reasons.count("nuclei_high_or_critical_severity_match") == 2
    assert all(item["priority"] == "high" for item in queue if item["reason"] == "nuclei_high_or_critical_severity_match")


def test_v92_config_defaults_and_overrides_nuclei_settings():
    default_config = EnrichmentConfig.create(
        max_mode=False, workers="auto", http_workers="auto", js_workers="auto",
        service_workers="auto", whatweb_threads="auto", request_timeout=10,
        lane_timeout=900, whatweb_image=None, retirejs_image=None, zgrab2_image=None,
    )
    assert default_config.nuclei_image == "projectdiscovery/nuclei:latest"
    assert default_config.nuclei_severity == ()

    custom_config = EnrichmentConfig.create(
        max_mode=False, workers="auto", http_workers="auto", js_workers="auto",
        service_workers="auto", whatweb_threads="auto", request_timeout=10,
        lane_timeout=900, whatweb_image=None, retirejs_image=None, zgrab2_image=None,
        nuclei_image="custom/nuclei:1.0", nuclei_workers=100,
        nuclei_severity=["high", "critical"], nuclei_templates="/opt/templates",
    )
    assert custom_config.nuclei_image == "custom/nuclei:1.0"
    assert custom_config.nuclei_workers == 25  # capped at ceiling
    assert custom_config.nuclei_severity == ("high", "critical")
    assert custom_config.nuclei_templates == "/opt/templates"
