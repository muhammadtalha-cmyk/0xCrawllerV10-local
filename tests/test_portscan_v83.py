from pathlib import Path

from smart_recon.classification import classify_http_asset
from smart_recon.commands import build_naabu_command, build_nmap_command
from smart_recon.keywords import keyword_tokens_from_url
from smart_recon.models import ToolResult
from smart_recon.portscan import (
    parse_naabu_jsonl,
    parse_nmap_xml,
    reconcile_port_candidates,
    select_port_scan_targets,
)


def test_query_values_do_not_become_keywords():
    url = (
        "https://sky47.com.pk/services/1228?"
        "__cf_chl_f_tk=7yVrYU4bmVnZiGS0JSyYm5f3mVuV435rFAJves&"
        "utm_source=newsletter&page=2"
    )
    tokens = keyword_tokens_from_url(url, "sky47.com.pk")
    assert "services" in tokens
    assert "page" in tokens
    assert "newsletter" not in tokens
    assert "fajves" not in tokens
    assert "7yvr" not in tokens


def test_saas_owner_is_separate_from_network_cdn():
    asset = classify_http_asset({
        "host": "servicehub.sky47.com.pk",
        "url": "https://servicehub.sky47.com.pk",
        "status_code": 200,
        "title": "SolarWinds Service Desk",
        "cname": ["sky47limited.samanage.com"],
        "cdn": True,
        "cdn_name": "google",
        "cdn_type": "cdn",
        "tech": ["Ruby on Rails"],
    })
    assert asset["ownership"] == "third_party_saas"
    assert asset["application_provider"] == "SolarWinds Service Desk"
    assert asset["network_provider"] == "Google"
    assert asset["cdn_detection"]["provider"] == "Google"


def test_port_target_selection_excludes_cdn_and_third_party():
    validated = {
        "api.example.com": {"a": ["203.0.113.10"], "cname": []},
        "www.example.com": {"a": ["104.16.1.1"], "cname": []},
        "support.example.com": {"a": [], "cname": ["tenant.samanage.com"]},
    }
    assets = [
        {
            "host": "api.example.com",
            "ownership": "first_party_or_unknown",
            "priority": "High",
            "status_code": 200,
            "cdn_detection": {"detected": False},
            "waf_detection": {"detected": False},
        },
        {
            "host": "www.example.com",
            "ownership": "cdn_edge_or_first_party_frontend",
            "priority": "Medium",
            "status_code": 200,
            "cdn_detection": {"detected": True, "provider": "Cloudflare"},
            "waf_detection": {"detected": True, "provider": "Cloudflare"},
        },
        {
            "host": "support.example.com",
            "ownership": "third_party_saas",
            "application_provider": "SolarWinds Service Desk",
            "priority": "Medium",
            "status_code": 200,
            "cdn_detection": {"detected": False},
            "waf_detection": {"detected": False},
        },
    ]
    targets, manifest = select_port_scan_targets(
        validated,
        assets,
        root_target="example.com",
        limit=50,
    )
    assert "api.example.com" in targets
    assert "www.example.com" not in targets
    assert "support.example.com" not in targets
    reasons = {item["host"]: item["reason"] for item in manifest}
    assert reasons["www.example.com"] == "excluded_cdn_or_security_edge"
    assert reasons["support.example.com"] == "excluded_third_party_dns_or_saas"


def test_naabu_command_is_connect_bounded(tmp_path: Path):
    command = build_naabu_command(
        tmp_path,
        top_ports="1000",
        ports=None,
        rate=100,
        threads=25,
        retries=2,
        socket_timeout_ms=1500,
    )
    joined = " ".join(command)
    assert "projectdiscovery/naabu:latest" in command
    assert "-s c" in joined
    assert "-tp 1000" in joined
    assert "-rate 100" in joined
    assert "-ec" in command
    assert "-j" in command


def test_nmap_command_only_scans_given_ports(tmp_path: Path):
    command = build_nmap_command(
        tmp_path,
        target="api.example.com",
        ports=[443, 22, 443],
        output_file="nmap/api.example.com.xml",
        host_timeout="5m",
    )
    joined = " ".join(command)
    assert "-sT" in command
    assert "-sV" in command
    assert "--version-light" in command
    assert "-p 22,443" in joined
    assert "--script" not in joined
    assert "-O" not in command
    assert "--open" not in command


def test_parse_naabu_and_nmap(tmp_path: Path):
    naabu = tmp_path / "naabu.jsonl"
    naabu.write_text(
        '{"host":"api.example.com","ip":"203.0.113.10","port":443}\n',
        encoding="utf-8",
    )
    assert parse_naabu_jsonl(naabu)[0]["port"] == 443

    xml = tmp_path / "api.xml"
    xml.write_text(
        """<?xml version='1.0'?>
<nmaprun><host><status state='up'/><address addr='203.0.113.10' addrtype='ipv4'/>
<hostnames><hostname name='api.example.com' type='user'/></hostnames>
<ports><port protocol='tcp' portid='443'><state state='open' reason='syn-ack'/>
<service name='https' product='nginx' version='1.24' method='probed' conf='10'/>
</port></ports></host></nmaprun>""",
        encoding="utf-8",
    )
    records = parse_nmap_xml(xml)
    assert records[0]["service"] == "https"
    assert records[0]["product"] == "nginx"
    assert records[0]["port"] == 443


def test_dns_only_microsoft_cname_is_excluded_without_http_record():
    validated = {
        "autodiscover.admin.example.com": {
            "a": ["40.99.68.40"],
            "cname": [
                "autod.ms-acdc-autod.office.com",
                "autodiscover.outlook.cloud.microsoft",
                "autodiscover.outlook.com",
            ],
        },
        "api.example.com": {"a": ["203.0.113.10"], "cname": []},
    }
    targets, manifest = select_port_scan_targets(
        validated,
        [],
        root_target="example.com",
        limit=50,
    )
    assert "autodiscover.admin.example.com" not in targets
    assert "api.example.com" in targets
    by_host = {item["host"]: item for item in manifest}
    item = by_host["autodiscover.admin.example.com"]
    assert item["reason"] == "excluded_third_party_dns_or_saas"
    assert item["ownership"] == "third_party_saas"
    assert item["ownership_source"] == "dns_cname"
    assert item["application_provider"] in {"Microsoft 365", "Microsoft 365 / Outlook"}


def test_unknown_cname_ownership_is_excluded_by_default():
    validated = {
        "delegated.example.com": {
            "a": ["203.0.113.44"],
            "cname": ["customer.unknown-provider.invalid"],
        }
    }
    targets, manifest = select_port_scan_targets(
        validated, [], root_target="example.com", limit=50
    )
    assert targets == []
    assert manifest[0]["reason"] == "excluded_unresolved_ownership"


def test_naabu_port_zero_is_rejected_and_never_returned(tmp_path: Path):
    raw = tmp_path / "naabu.jsonl"
    rejected = tmp_path / "rejected.jsonl"
    raw.write_text(
        '{"host":"vpn-h.example.com","ip":"203.0.113.9","port":0,"protocol":""}\n'
        '{"host":"vpn.example.com","ip":"203.0.113.10","port":179,"protocol":"tcp"}\n',
        encoding="utf-8",
    )
    records = parse_naabu_jsonl(raw, rejected_path=rejected)
    assert [(item["host"], item["port"]) for item in records] == [("vpn.example.com", 179)]
    rejection = rejected.read_text(encoding="utf-8")
    assert "invalid_port_range" in rejection
    assert '"port": 0' in rejection


def test_nmap_reconciliation_does_not_promote_unreported_candidate(tmp_path: Path):
    result = ToolResult(
        name="nmap_vpn.example.com",
        ok=True,
        returncode=0,
        seconds=1.0,
        stdout_path=tmp_path / "stdout.txt",
        stderr_path=tmp_path / "stderr.txt",
        metadata={"target": "vpn.example.com", "ports": [179]},
    )
    candidates = [{
        "host": "vpn.example.com", "ip": "203.0.113.10", "port": 179,
        "protocol": "tcp", "candidate_status": "NAABU_CANDIDATE",
    }]
    reconciled = reconcile_port_candidates(
        naabu_records=candidates,
        nmap_records=[],
        nmap_results=[result],
        nmap_requested=True,
    )
    assert reconciled[0]["final_status"] == "NMAP_NOT_CONFIRMED"
    assert reconciled[0]["nmap_state"] == "not_reported"


def test_nmap_reconciliation_confirms_only_explicit_open_state(tmp_path: Path):
    result = ToolResult(
        name="nmap_api.example.com",
        ok=True,
        returncode=0,
        seconds=1.0,
        stdout_path=tmp_path / "stdout.txt",
        stderr_path=tmp_path / "stderr.txt",
        metadata={"target": "api.example.com", "ports": [443, 8443]},
    )
    candidates = [
        {"host": "api.example.com", "ip": "203.0.113.10", "port": 443, "protocol": "tcp"},
        {"host": "api.example.com", "ip": "203.0.113.10", "port": 8443, "protocol": "tcp"},
    ]
    nmap_records = [
        {"requested_target": "api.example.com", "port": 443, "state": "open", "service": "https"},
        {"requested_target": "api.example.com", "port": 8443, "state": "filtered"},
    ]
    reconciled = reconcile_port_candidates(
        naabu_records=candidates,
        nmap_records=nmap_records,
        nmap_results=[result],
        nmap_requested=True,
    )
    by_port = {item["port"]: item for item in reconciled}
    assert by_port[443]["final_status"] == "NMAP_CONFIRMED_OPEN"
    assert by_port[8443]["final_status"] == "NMAP_NOT_CONFIRMED"
    assert by_port[8443]["nmap_state"] == "filtered"


def test_nmap_command_refuses_only_invalid_ports(tmp_path: Path):
    import pytest

    with pytest.raises(ValueError):
        build_nmap_command(
            tmp_path,
            target="api.example.com",
            ports=[0, 65536],
            output_file="nmap/api.xml",
            host_timeout="5m",
        )
