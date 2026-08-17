"""Structured CDN, technology, and WAF evidence handling.

Passive evidence comes from ProjectDiscovery HTTPX:
- ``-tech-detect`` uses the bundled Wappalyzer technology dataset.
- ``-cdn`` uses HTTPX/CDNCheck to identify known CDN/WAF providers.

Active WAF fingerprinting is optional and handled by WAFW00F. It is never
silently enabled because WAFW00F may send payload-like requests to distinguish
security products.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .config import THIRD_PARTY_PROVIDERS
from .validation import normalize_hostname

# Keep aliases conservative. Wappalyzer technologies can be supporting evidence,
# but technology presence alone is not treated as proof that traffic is proxied.
CDN_ALIASES = {
    "akamai": "Akamai",
    "amazon cloudfront": "Amazon CloudFront",
    "cloudfront": "Amazon CloudFront",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "imperva": "Imperva",
    "incapsula": "Imperva",
    "keycdn": "KeyCDN",
    "stackpath": "StackPath",
    "sucuri": "Sucuri",
    "vercel": "Vercel",
    "azure front door": "Microsoft Azure Front Door",
    "google": "Google",
    "google cloud cdn": "Google Cloud CDN",
    "bunnycdn": "Bunny CDN",
}

CDN_CNAME_SUFFIXES = {
    "cloudflare.net": "Cloudflare",
    "cloudfront.net": "Amazon CloudFront",
    "akamaiedge.net": "Akamai",
    "akamaized.net": "Akamai",
    "akamai.net": "Akamai",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "azurefd.net": "Microsoft Azure Front Door",
    "edgesuite.net": "Akamai",
    "edgekey.net": "Akamai",
    "cdn77.org": "CDN77",
    "b-cdn.net": "Bunny CDN",
}

WAF_ALIASES = {
    "akamai kona sitedefender": "Akamai Kona Site Defender",
    "akamai": "Akamai",
    "aws waf": "AWS WAF",
    "cloudflare": "Cloudflare",
    "cloudflare bot management": "Cloudflare",
    "fortiweb": "Fortinet FortiWeb",
    "f5 big-ip": "F5 BIG-IP",
    "imperva": "Imperva",
    "incapsula": "Imperva",
    "modsecurity": "ModSecurity",
    "sucuri": "Sucuri",
    "wallarm": "Wallarm",
    "wordfence": "Wordfence",
}

WAFW00F_IMAGE = "smartrecon/wafw00f:2.4.2"
WAFW00F_VERSION = "2.4.2"
WAFW00F_DOCKERFILE = f"""FROM python:3.12-slim\nRUN python -m pip install --no-cache-dir wafw00f=={WAFW00F_VERSION}\nENTRYPOINT [\"wafw00f\"]\n"""


def _as_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _canonical_provider(value: str, aliases: dict[str, str]) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    if normalized in aliases:
        return aliases[normalized]
    for alias, provider in aliases.items():
        if alias in normalized:
            return provider
    return None


def _cdn_provider_from_cnames(cnames: Iterable[str]) -> str | None:
    """Return only a network-edge/CDN provider from CNAME evidence."""
    for cname in cnames:
        normalized = normalize_hostname(cname)
        for suffix, provider in CDN_CNAME_SUFFIXES.items():
            if normalized == suffix or normalized.endswith("." + suffix):
                return provider
    return None


def _application_provider_from_cnames(cnames: Iterable[str]) -> str | None:
    """Return the SaaS/application owner separately from network delivery."""
    for cname in cnames:
        normalized = normalize_hostname(cname)
        for suffix, provider in THIRD_PARTY_PROVIDERS.items():
            if normalized == suffix or normalized.endswith("." + suffix):
                return provider
    return None


def _evidence_record(source: str, value: str, confidence: str, detail: str = "") -> dict[str, str]:
    return {
        "source": source,
        "value": value,
        "confidence": confidence,
        "detail": detail,
    }


def extract_passive_edge_evidence(record: dict[str, Any]) -> dict[str, Any]:
    """Create conservative passive CDN/WAF/technology evidence from HTTPX JSON."""
    technologies = sorted(set(_as_strings(record.get("tech"))))
    cnames = sorted(set(normalize_hostname(value) for value in _as_strings(record.get("cname")) if value))
    cdn_name_raw = str(record.get("cdn_name") or "").strip()
    cdn_type = str(record.get("cdn_type") or "").strip().lower()
    cdn_flag = bool(record.get("cdn"))

    cdn_evidence: list[dict[str, str]] = []
    waf_evidence: list[dict[str, str]] = []
    cdn_provider: str | None = None
    waf_provider: str | None = None

    if cdn_name_raw:
        cdn_provider = _canonical_provider(cdn_name_raw, CDN_ALIASES) or cdn_name_raw
        cdn_evidence.append(
            _evidence_record(
                "httpx_cdncheck",
                cdn_provider,
                "high",
                f"HTTPX cdn_name={cdn_name_raw!r}, cdn_type={cdn_type or 'unknown'!r}",
            )
        )
        if cdn_type == "waf":
            waf_provider = _canonical_provider(cdn_name_raw, WAF_ALIASES) or cdn_provider
            waf_evidence.append(
                _evidence_record(
                    "httpx_cdncheck",
                    waf_provider,
                    "high",
                    "HTTPX identified the provider with cdn_type=waf.",
                )
            )
    elif cdn_flag:
        cdn_evidence.append(
            _evidence_record("httpx_cdncheck", "unknown", "medium", "HTTPX set cdn=true without a provider name.")
        )

    cname_cdn_provider = _cdn_provider_from_cnames(cnames)
    application_provider = _application_provider_from_cnames(cnames)
    if cname_cdn_provider:
        cdn_evidence.append(
            _evidence_record(
                "dns_cname",
                cname_cdn_provider,
                "medium",
                "CNAME terminates at a known network CDN/edge provider.",
            )
        )
        cdn_provider = cdn_provider or cname_cdn_provider

    for technology in technologies:
        tech_cdn = _canonical_provider(technology, CDN_ALIASES)
        if tech_cdn:
            cdn_evidence.append(
                _evidence_record(
                    "wappalyzer_technology",
                    tech_cdn,
                    "supporting",
                    f"HTTPX -tech-detect identified {technology!r} using the Wappalyzer dataset.",
                )
            )
            cdn_provider = cdn_provider or tech_cdn
        tech_waf = _canonical_provider(technology, WAF_ALIASES)
        if tech_waf:
            waf_evidence.append(
                _evidence_record(
                    "wappalyzer_technology",
                    tech_waf,
                    "supporting",
                    f"Technology fingerprint {technology!r} is associated with a WAF/security edge.",
                )
            )
            waf_provider = waf_provider or tech_waf

    # Deduplicate evidence without losing source distinctions.
    def dedupe(items: list[dict[str, str]]) -> list[dict[str, str]]:
        seen: set[tuple[str, str, str, str]] = set()
        output: list[dict[str, str]] = []
        for item in items:
            key = (item["source"], item["value"], item["confidence"], item["detail"])
            if key not in seen:
                seen.add(key)
                output.append(item)
        return output

    cdn_evidence = dedupe(cdn_evidence)
    waf_evidence = dedupe(waf_evidence)
    cdn_confidence = "none"
    if any(item["confidence"] == "high" for item in cdn_evidence):
        cdn_confidence = "high"
    elif any(item["confidence"] == "medium" for item in cdn_evidence):
        cdn_confidence = "medium"
    elif cdn_evidence:
        cdn_confidence = "supporting"

    waf_confidence = "none"
    if any(item["confidence"] == "high" for item in waf_evidence):
        waf_confidence = "high"
    elif any(item["confidence"] == "medium" for item in waf_evidence):
        waf_confidence = "medium"
    elif waf_evidence:
        waf_confidence = "supporting"

    return {
        "technologies": {
            "detected": bool(technologies),
            "source": "httpx_wappalyzer",
            "items": technologies,
        },
        "application_provider": application_provider,
        "network_provider": cdn_provider,
        "cdn": {
            "detected": bool(cdn_evidence),
            "provider": cdn_provider,
            "confidence": cdn_confidence,
            "evidence": cdn_evidence,
        },
        "waf": {
            "detected": bool(waf_evidence),
            "provider": waf_provider,
            "confidence": waf_confidence,
            "mode": "passive",
            "evidence": waf_evidence,
        },
    }


def prepare_wafw00f_build_context(run_dir: Path) -> Path:
    context = run_dir / "support" / "wafw00f_image"
    context.mkdir(parents=True, exist_ok=True)
    (context / "Dockerfile").write_text(WAFW00F_DOCKERFILE, encoding="utf-8")
    return context


def parse_wafw00f_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    records: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        try:
            host = normalize_hostname(urlsplit(url).hostname or "")
        except ValueError:
            host = ""
        records.append({
            "url": url,
            "host": host,
            "detected": bool(item.get("detected")),
            "firewall": str(item.get("firewall") or "None"),
            "manufacturer": str(item.get("manufacturer") or "None"),
            "trigger_url": str(item.get("trigger_url") or "") or None,
            "source": "wafw00f",
            "mode": "active_fingerprinting",
        })
    return records


def select_waf_targets(
    assets: list[dict[str, Any]],
    *,
    limit: int,
    include_third_party: bool = False,
) -> list[str]:
    """Select one canonical live URL per host for optional WAFW00F scanning."""
    candidates: list[tuple[int, int, str, str]] = []
    seen_hosts: set[str] = set()
    for asset in assets:
        host = normalize_hostname(asset.get("host") or "")
        url = str(asset.get("url") or "").strip()
        if not host or not url.startswith(("http://", "https://")):
            continue
        if asset.get("ownership") == "third_party_saas" and not include_third_party:
            continue
        try:
            status = int(asset.get("status_code") or 0)
        except (TypeError, ValueError):
            status = 0
        if not 100 <= status < 600:
            continue
        priority_rank = 0 if asset.get("priority") == "High" else (1 if asset.get("priority") == "Medium" else 2)
        status_rank = 0 if 200 <= status < 400 else 1
        candidates.append((priority_rank, status_rank, host, url))

    selected: list[str] = []
    for _, _, host, url in sorted(candidates):
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        selected.append(url)
        if len(selected) >= max(0, int(limit)):
            break
    return selected


def merge_active_waf_results(
    assets: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge WAFW00F evidence without overstating generic/conflicting results."""
    by_host: dict[str, list[dict[str, Any]]] = {}
    for result in results:
        host = normalize_hostname(result.get("host") or "")
        if host:
            by_host.setdefault(host, []).append(result)

    generic_labels = {
        "generic", "generic waf", "generic detection", "generic detection (unknown)",
        "generic/unknown waf", "unknown", "unknown waf", "none", "", "waf",
    }

    def canonical_active_provider(value: Any) -> tuple[str | None, bool]:
        raw = str(value or "").strip()
        if raw.lower() in generic_labels:
            return ("Generic/Unknown WAF" if raw else None), True
        return raw or None, False

    for asset in assets:
        host = normalize_hostname(asset.get("host") or "")
        matches = by_host.get(host, [])
        if not matches:
            continue
        active_detected = [item for item in matches if item.get("detected")]
        existing = dict(asset.get("waf_detection") or {})
        evidence = list(existing.get("evidence") or [])

        active_named: list[str] = []
        active_generic = False
        for item in matches:
            provider, is_generic = canonical_active_provider(item.get("firewall"))
            if item.get("detected"):
                if is_generic:
                    active_generic = True
                elif provider:
                    active_named.append(provider)
            evidence.append({
                "source": "wafw00f",
                "value": provider or "None",
                "confidence": "medium" if is_generic and item.get("detected") else (
                    "high" if item.get("detected") else "negative_observation"
                ),
                "detail": f"manufacturer={item.get('manufacturer') or 'None'}",
            })

        if active_detected:
            active_named = list(dict.fromkeys(active_named))
            existing_provider = str(existing.get("provider") or "").strip()
            existing_providers = [
                part.strip() for part in existing_provider.split("/")
                if part.strip() and part.strip().lower() not in generic_labels
            ]
            all_named = list(dict.fromkeys(existing_providers + active_named))

            if active_named and existing_providers and set(active_named) != set(existing_providers):
                existing.update({
                    "detected": True,
                    "provider": " / ".join(all_named),
                    "providers": all_named,
                    "confidence": "medium",
                    "mode": "active_fingerprinting",
                    "attribution": "conflicting_or_multi_layer",
                    "outer_edge_provider": (asset.get("cdn_detection") or {}).get("provider"),
                    "active_provider": " / ".join(active_named),
                    "active_matches": active_detected,
                    "evidence": evidence,
                })
            elif active_named:
                provider = active_named[0] if len(active_named) == 1 else " / ".join(active_named)
                existing.update({
                    "detected": True,
                    "provider": provider,
                    "providers": active_named,
                    "confidence": "high",
                    "mode": "active_fingerprinting",
                    "attribution": "named_active_fingerprint",
                    "active_provider": provider,
                    "active_matches": active_detected,
                    "evidence": evidence,
                })
            elif active_generic and existing_provider:
                existing.update({
                    "detected": True,
                    "provider": existing_provider,
                    "confidence": existing.get("confidence") or "medium",
                    "mode": "active_fingerprinting",
                    "attribution": "passive_named_plus_generic_active",
                    "active_provider": "Generic/Unknown WAF",
                    "active_confidence": "medium",
                    "active_matches": active_detected,
                    "evidence": evidence,
                })
            else:
                existing.update({
                    "detected": True,
                    "provider": "Generic/Unknown WAF",
                    "providers": ["Generic/Unknown WAF"],
                    "confidence": "medium",
                    "mode": "active_fingerprinting",
                    "attribution": "generic_active_fingerprint",
                    "active_provider": "Generic/Unknown WAF",
                    "active_confidence": "medium",
                    "active_matches": active_detected,
                    "evidence": evidence,
                })
        else:
            existing.update({
                "active_checked": True,
                "active_detected": False,
                "evidence": evidence,
            })
        asset["waf_detection"] = existing
    return assets


def summarize_edge_detection(
    assets: list[dict[str, Any]],
    active_results: list[dict[str, Any]],
    *,
    active_requested: bool,
    active_tool_ok: bool | None,
    target_count: int,
) -> dict[str, Any]:
    cdn_assets = [asset for asset in assets if (asset.get("cdn_detection") or {}).get("detected")]
    waf_assets = [asset for asset in assets if (asset.get("waf_detection") or {}).get("detected")]
    passive_waf_assets = []
    for asset in waf_assets:
        waf = asset.get("waf_detection") or {}
        evidence = waf.get("evidence") or []
        has_passive_evidence = any(
            str(item.get("source") or "") != "wafw00f"
            and str(item.get("confidence") or "") != "negative_observation"
            for item in evidence
        )
        # Backward compatibility for records created before evidence arrays were
        # mandatory: a detected non-active record is considered passive.
        if has_passive_evidence or (not evidence and waf.get("mode") != "active_fingerprinting"):
            passive_waf_assets.append(asset)
    conflict_assets = [
        asset for asset in waf_assets
        if (asset.get("waf_detection") or {}).get("attribution") == "conflicting_or_multi_layer"
    ]
    generic_assets = [
        asset for asset in waf_assets
        if (asset.get("waf_detection") or {}).get("attribution") == "generic_active_fingerprint"
    ]
    active_waf_hosts = sorted({str(item.get("host")) for item in active_results if item.get("detected") and item.get("host")})
    technologies = sorted({tech for asset in assets for tech in (asset.get("technologies") or [])})
    return {
        "methodology": {
            "technology": "HTTPX -tech-detect using the Wappalyzer dataset",
            "cdn": "HTTPX CDNCheck, CNAME/provider evidence, and supporting Wappalyzer fingerprints",
            "waf_passive": "HTTPX cdn_type/waf and supporting technology fingerprints",
            "waf_active": "Optional WAFW00F active fingerprinting",
        },
        "counts": {
            "assets": len(assets),
            "cdn_detected": len(cdn_assets),
            "waf_detected_total": len(waf_assets),
            "passive_waf_detected": len(passive_waf_assets),
            "active_waf_detected": len(active_waf_hosts),
            "waf_conflicting_or_multi_layer": len(conflict_assets),
            "waf_generic_active": len(generic_assets),
            "technologies_unique": len(technologies),
        },
        "active_waf": {
            "requested": active_requested,
            "tool_ok": active_tool_ok,
            "targets_selected": target_count,
            "records": len(active_results),
            "detected_hosts": active_waf_hosts,
        },
        "technologies": technologies,
    }


def write_waf_csv(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["url", "host", "detected", "firewall", "manufacturer", "source", "mode"],
        )
        writer.writeheader()
        for record in records:
            writer.writerow({key: record.get(key, "") for key in writer.fieldnames})
