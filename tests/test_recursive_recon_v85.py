import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from smart_recon.cli import build_parser
from smart_recon.commands import build_katana_command, build_httpx_file_command
from smart_recon.parsers import extract_in_scope_hosts_from_url
from smart_recon.recursive_recon import _cluster_assets, _write_mindmap, refresh_recursive_topology
from smart_recon.shodan_passive import DEFAULT_FIELDS, ShodanClient, ShodanNoData


def test_shodan_search_uses_fields_with_minify_false(monkeypatch):
    client = ShodanClient("test-key", api_rps=1000)
    captured = {}

    def fake_get(path, params=None, use_cache=True):
        captured["path"] = path
        captured["params"] = dict(params or {})
        return {"matches": []}

    monkeypatch.setattr(client, "get", fake_get)
    client.search('hostname:"example.com"', page=2)
    assert captured["path"] == "/shodan/host/search"
    assert captured["params"]["minify"] == "false"
    assert captured["params"]["fields"] == DEFAULT_FIELDS
    assert captured["params"]["page"] == 2


def test_shodan_host_404_is_normal_no_data(monkeypatch):
    client = ShodanClient("test-key", api_rps=1000)

    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            404,
            "Not Found",
            {},
            io.BytesIO(b'{"error":"No information available for that IP"}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ShodanNoData) as exc:
        client.host("203.0.113.10")
    assert exc.value.ip == "203.0.113.10"


def test_recursive_cli_is_bounded_to_three_levels():
    parser = build_parser()
    args = parser.parse_args([
        "--target", "example.com", "--authorized", "--recursive-recon",
        "--recursive-depth", "3", "--recursive-workers", "6",
    ])
    assert args.recursive_depth == 3
    assert args.recursive_workers == 6
    with pytest.raises(SystemExit):
        parser.parse_args(["--target", "example.com", "--authorized", "--recursive-depth", "4"])


def test_katana_and_httpx_support_per_level_output_files(tmp_path: Path):
    katana = build_katana_command(
        "https://api.example.com",
        tmp_path,
        max_mode=True,
        depth=3,
        concurrency=5,
        rate_limit=20,
        crawl_duration="2m",
        output_file="recursive/level_01/katana_api.txt",
    )
    assert katana[katana.index("-o") + 1] == "/output/recursive/level_01/katana_api.txt"
    httpx = build_httpx_file_command(
        tmp_path,
        input_file="recursive/level_01/hosts.txt",
        output_file="recursive/level_01/httpx.jsonl",
    )
    assert httpx[httpx.index("-l") + 1] == "/output/recursive/level_01/hosts.txt"
    assert httpx[httpx.index("-o") + 1] == "/output/recursive/level_01/httpx.jsonl"


def test_recursive_clustering_separates_first_party_edge_and_saas():
    validated = {
        "api.example.com": {"validation_state": "dns_resolved"},
        "portal.example.com": {"validation_state": "dns_resolved"},
        "help.example.com": {"validation_state": "dns_resolved"},
        "waf.example.com": {"validation_state": "dns_resolved"},
    }
    assets = [
        {
            "host": "api.example.com", "url": "https://api.example.com", "status_code": 200,
            "ownership": "first_party_or_unknown", "cdn_detection": {"detected": False},
            "waf_detection": {"detected": False},
        },
        {
            "host": "portal.example.com", "url": "https://portal.example.com", "status_code": 200,
            "ownership": "cdn_edge_or_first_party_frontend", "cdn_detection": {"detected": True},
            "waf_detection": {"detected": True},
        },
        {
            "host": "help.example.com", "url": "https://help.example.com", "status_code": 200,
            "ownership": "third_party_saas", "cdn_detection": {"detected": False},
            "waf_detection": {"detected": False},
        },
        {
            "host": "waf.example.com", "url": "https://waf.example.com", "status_code": 200,
            "ownership": "first_party_or_unknown", "cdn_detection": {"detected": False},
            "waf_detection": {"detected": True, "provider": "Generic/Unknown WAF"},
        },
    ]
    clusters = _cluster_assets(
        target="example.com",
        validated_dns=validated,
        classified_assets=assets,
        boundary_hosts=set(),
        wildcard_hosts=set(),
    )
    assert clusters["first_party_direct_web"] == ["api.example.com"]
    assert clusters["first_party_cdn_fronted"] == ["portal.example.com"]
    assert clusters["first_party_waf_detected"] == ["waf.example.com"]
    assert clusters["third_party_saas"] == ["help.example.com"]


def test_mindmap_and_refresh_outputs(tmp_path: Path):
    topology = {
        "root": "example.com",
        "max_depth": 3,
        "nodes": {
            "example.com": {"host": "example.com", "level": 0, "ownership": "authorized_root"},
            "api.example.com": {"host": "api.example.com", "level": 1},
        },
        "edges": [{"parent": "example.com", "child": "api.example.com", "source": "katana", "level": 1}],
    }
    (tmp_path / "recon_topology.json").write_text(json.dumps(topology), encoding="utf-8")
    (tmp_path / "recursive_wildcard_suspected.json").write_text("{}", encoding="utf-8")
    summary = {
        "boundary_hosts": [],
        "mindmap_mermaid": _write_mindmap(
            target="example.com",
            edges=topology["edges"],
            nodes=topology["nodes"],
            path=tmp_path / "recon_mindmap.mmd",
        ),
    }
    updated = refresh_recursive_topology(
        target="example.com",
        run_dir=tmp_path,
        validated_dns={"api.example.com": {"validation_state": "dns_resolved"}},
        classified_assets=[{
            "host": "api.example.com", "url": "https://api.example.com", "status_code": 200,
            "ownership": "first_party_or_unknown", "cdn_detection": {"detected": False},
            "waf_detection": {"detected": False},
        }],
        recursive_summary=summary,
    )
    assert "flowchart TD" in (tmp_path / "recon_mindmap.mmd").read_text(encoding="utf-8")
    assert updated["cluster_counts"]["first_party_direct_web"] == 1


def test_encoded_nested_url_does_not_create_2f_hostname():
    url = (
        "https://admin.example.com/wp-json/oembed/1.0/embed?"
        "url=https%3A%2F%2Fadmin.example.com%2Fleadership%2Fperson"
    )
    hosts = extract_in_scope_hosts_from_url(url, "example.com")
    assert hosts == {"admin.example.com"}
    assert "2fadmin.example.com" not in hosts


def test_nested_complete_url_query_can_discover_real_child_host():
    url = (
        "https://admin.example.com/redirect?"
        "next=https%3A%2F%2Fapi.example.com%2Fv1%2Fstatus"
    )
    hosts = extract_in_scope_hosts_from_url(url, "example.com")
    assert hosts == {"admin.example.com", "api.example.com"}
