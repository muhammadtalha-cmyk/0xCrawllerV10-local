from pathlib import Path

from smart_recon.env_utils import load_env_file
from smart_recon.shodan_passive import (
    CreditLedger,
    build_scopes,
    extract_domain_hosts,
    load_dork_templates,
    render_dork_plan,
)


def test_env_loader_keeps_empty_api_key(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text("SHODAN_API_KEY=\nOTHER=value\n", encoding="utf-8")
    loaded = load_env_file(env)
    assert loaded["SHODAN_API_KEY"] == ""
    assert loaded["OTHER"] == "value"


def test_scopes_are_explicit_and_bounded():
    scopes = build_scopes("example.com", org="Example Corp", asn="64500", net="203.0.113.0/24")
    values = {row["scope_id"]: row["scope"] for row in scopes}
    assert values["hostname"] == 'hostname:"example.com"'
    assert values["org"] == 'org:"Example Corp"'
    assert values["asn"] == "asn:AS64500"
    assert values["net"] == "net:203.0.113.0/24"


def test_dork_plan_does_not_generate_global_queries():
    templates = [{
        "id": "ssh",
        "query_template": "{scope} port:22",
        "scope_types": ["hostname"],
        "enabled_by_default": True,
    }]
    plan = render_dork_plan(
        templates,
        target="example.com",
        org=None,
        asn=None,
        net=None,
        include_disabled=False,
        max_dorks=10,
    )
    assert plan[0]["query"] == 'hostname:"example.com" port:22'
    assert "{" not in plan[0]["query"]


def test_disabled_dorks_require_explicit_enable():
    templates = [{
        "id": "db",
        "query_template": "{scope} port:27017",
        "scope_types": ["org"],
        "enabled_by_default": False,
    }]
    assert render_dork_plan(
        templates, target="example.com", org="Example", asn=None, net=None,
        include_disabled=False, max_dorks=10,
    ) == []
    assert len(render_dork_plan(
        templates, target="example.com", org="Example", asn=None, net=None,
        include_disabled=True, max_dorks=10,
    )) == 1


def test_domain_extraction_only_accepts_in_scope_hosts():
    response = {"data": [
        {"subdomain": "api", "type": "A", "value": "203.0.113.10"},
        {"subdomain": "", "type": "MX", "value": "mail.example.net"},
        {"subdomain": "-bad", "type": "A", "value": "203.0.113.11"},
    ]}
    hosts, records, ips = extract_domain_hosts(response, "example.com")
    assert hosts == {"api.example.com"}
    assert "203.0.113.10" in ips
    assert all(row["host"] != "-bad.example.com" for row in records)


def test_credit_ledger_enforces_budget():
    ledger = CreditLedger(2)
    assert ledger.can_spend(1)
    ledger.spend(operation="dns_domain", amount=1, detail="page 1")
    ledger.spend(operation="host_search", amount=1, detail="query 1")
    assert not ledger.can_spend(1)
    assert ledger.to_dict()["estimated_spent"] == 2


def test_default_dorks_file_is_valid():
    root = Path(__file__).resolve().parents[1]
    templates = load_dork_templates(root / "shodan_dorks.json")
    assert templates
    assert all("query_template" in item and "scope_types" in item for item in templates)
