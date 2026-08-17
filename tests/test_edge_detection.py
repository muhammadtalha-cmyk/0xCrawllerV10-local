from pathlib import Path

from smart_recon.classification import classify_http_asset
from smart_recon.edge_detection import (
    WAFW00F_DOCKERFILE,
    merge_active_waf_results,
    parse_wafw00f_json,
    select_waf_targets,
    summarize_edge_detection,
)


def test_httpx_wappalyzer_and_cdncheck_are_structured():
    asset = classify_http_asset({
        "host": "www.example.com",
        "url": "https://www.example.com",
        "status_code": 200,
        "tech": ["Cloudflare", "React"],
        "cdn": True,
        "cdn_name": "cloudflare",
        "cdn_type": "waf",
    })
    assert asset["technologies"] == ["Cloudflare", "React"]
    assert asset["cdn_detection"]["detected"] is True
    assert asset["cdn_detection"]["provider"] == "Cloudflare"
    assert asset["cdn_detection"]["confidence"] == "high"
    assert asset["waf_detection"]["detected"] is True
    assert asset["waf_detection"]["provider"] == "Cloudflare"


def test_wappalyzer_only_is_supporting_not_high_confidence():
    asset = classify_http_asset({
        "host": "www.example.com",
        "url": "https://www.example.com",
        "status_code": 200,
        "tech": ["Cloudflare"],
    })
    assert asset["cdn_detection"]["detected"] is True
    assert asset["cdn_detection"]["confidence"] == "supporting"
    assert asset["waf_detection"]["confidence"] == "supporting"


def test_cname_can_support_cdn_detection():
    asset = classify_http_asset({
        "host": "static.example.com",
        "url": "https://static.example.com",
        "status_code": 200,
        "cname": ["d111111abcdef8.cloudfront.net"],
    })
    assert asset["cdn_detection"]["detected"] is True
    assert asset["cdn_detection"]["provider"] == "Amazon CloudFront"
    assert asset["cdn_detection"]["confidence"] == "medium"


def test_waf_targets_exclude_third_party_by_default():
    assets = [
        {
            "host": "api.example.com",
            "url": "https://api.example.com",
            "status_code": 200,
            "priority": "High",
            "ownership": "first_party",
        },
        {
            "host": "blog.example.com",
            "url": "https://blog.example.com",
            "status_code": 200,
            "priority": "Medium",
            "ownership": "third_party_saas",
        },
    ]
    assert select_waf_targets(assets, limit=10) == ["https://api.example.com"]
    assert len(select_waf_targets(assets, limit=10, include_third_party=True)) == 2


def test_parse_and_merge_wafw00f_json(tmp_path: Path):
    path = tmp_path / "wafw00f.json"
    path.write_text(
        '[{"url":"https://api.example.com","detected":true,'
        '"firewall":"Cloudflare","manufacturer":"Cloudflare",'
        '"trigger_url":"https://api.example.com/?x=payload"}]',
        encoding="utf-8",
    )
    results = parse_wafw00f_json(path)
    assets = [{
        "host": "api.example.com",
        "url": "https://api.example.com",
        "waf_detection": {"detected": False, "evidence": [], "mode": "passive"},
    }]
    merged = merge_active_waf_results(assets, results)
    assert merged[0]["waf_detection"]["detected"] is True
    assert merged[0]["waf_detection"]["confidence"] == "high"
    assert merged[0]["waf_detection"]["mode"] == "active_fingerprinting"


def test_edge_summary_counts_active_and_passive():
    assets = [{
        "host": "www.example.com",
        "technologies": ["React"],
        "cdn_detection": {"detected": True},
        "waf_detection": {"detected": True},
    }]
    results = [{"host": "www.example.com", "detected": True}]
    summary = summarize_edge_detection(
        assets,
        results,
        active_requested=True,
        active_tool_ok=True,
        target_count=1,
    )
    assert summary["counts"]["cdn_detected"] == 1
    assert summary["counts"]["passive_waf_detected"] == 1
    assert summary["counts"]["active_waf_detected"] == 1


def test_local_waf_image_is_version_pinned():
    assert "wafw00f==2.4.2" in WAFW00F_DOCKERFILE
    assert 'ENTRYPOINT ["wafw00f"]' in WAFW00F_DOCKERFILE


def test_generic_wafw00f_detection_is_medium_confidence(tmp_path: Path):
    path = tmp_path / "generic.json"
    path.write_text(
        '[{"url":"https://vpn.example.com","detected":true,'
        '"firewall":"Generic","manufacturer":"Unknown"}]',
        encoding="utf-8",
    )
    results = parse_wafw00f_json(path)
    assets = [{
        "host": "vpn.example.com",
        "url": "https://vpn.example.com",
        "cdn_detection": {"detected": False},
        "waf_detection": {"detected": False, "evidence": [], "mode": "passive"},
    }]
    merged = merge_active_waf_results(assets, results)
    waf = merged[0]["waf_detection"]
    assert waf["provider"] == "Generic/Unknown WAF"
    assert waf["confidence"] == "medium"
    assert waf["attribution"] == "generic_active_fingerprint"


def test_conflicting_waf_providers_are_retained_as_multilayer(tmp_path: Path):
    path = tmp_path / "conflict.json"
    path.write_text(
        '[{"url":"https://app.example.com","detected":true,'
        '"firewall":"Azure Front Door","manufacturer":"Microsoft"}]',
        encoding="utf-8",
    )
    results = parse_wafw00f_json(path)
    assets = [{
        "host": "app.example.com",
        "url": "https://app.example.com",
        "cdn_detection": {"detected": True, "provider": "Cloudflare", "confidence": "high"},
        "waf_detection": {
            "detected": True,
            "provider": "Cloudflare",
            "confidence": "high",
            "mode": "passive",
            "evidence": [{"source": "httpx_cdncheck", "value": "Cloudflare", "confidence": "high"}],
        },
    }]
    merged = merge_active_waf_results(assets, results)
    waf = merged[0]["waf_detection"]
    assert waf["confidence"] == "medium"
    assert waf["attribution"] == "conflicting_or_multi_layer"
    assert waf["outer_edge_provider"] == "Cloudflare"
    assert set(waf["providers"]) == {"Cloudflare", "Azure Front Door"}


def test_named_active_waf_stays_high_confidence(tmp_path: Path):
    path = tmp_path / "named.json"
    path.write_text(
        '[{"url":"https://app.example.com","detected":true,'
        '"firewall":"Cloudflare","manufacturer":"Cloudflare"}]',
        encoding="utf-8",
    )
    results = parse_wafw00f_json(path)
    assets = [{
        "host": "app.example.com",
        "url": "https://app.example.com",
        "cdn_detection": {"detected": True, "provider": "Cloudflare"},
        "waf_detection": {"detected": True, "provider": "Cloudflare", "confidence": "high", "evidence": []},
    }]
    waf = merge_active_waf_results(assets, results)[0]["waf_detection"]
    assert waf["provider"] == "Cloudflare"
    assert waf["confidence"] == "high"
    assert waf["attribution"] == "named_active_fingerprint"
