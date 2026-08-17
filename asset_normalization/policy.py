from __future__ import annotations

from typing import Any

from .identity import in_scope, normalize_host

THIRD_PARTY_SUFFIXES: dict[str, str] = {
    "outlook.com": "Microsoft 365",
    "outlook.cloud.microsoft": "Microsoft 365",
    "office.com": "Microsoft 365",
    "cloud.microsoft": "Microsoft 365",
    "manage.microsoft.com": "Microsoft Intune",
    "microsoftonline.com": "Microsoft Entra ID",
    "msidentity.com": "Microsoft Entra ID",
    "windows.net": "Microsoft Azure / Entra ID",
    "azurefd.net": "Microsoft Azure Front Door",
    "trafficmanager.net": "Microsoft Azure",
    "akadns.net": "Akamai/Microsoft managed edge",
    "samanage.com": "SolarWinds Service Desk",
    "sendgrid.net": "Twilio SendGrid",
    "hubspot.net": "HubSpot",
    "hubspot.com": "HubSpot",
    "googlehosted.com": "Google managed service",
    "github.io": "GitHub Pages",
    "herokudns.com": "Heroku",
    "cloudfront.net": "Amazon CloudFront",
}


def provider_from_cnames(cnames: list[str]) -> str | None:
    for cname in cnames:
        c = normalize_host(cname)
        for suffix, provider in THIRD_PARTY_SUFFIXES.items():
            if c == suffix or c.endswith("." + suffix):
                return provider
    return None


def determine_ownership(*, host: str, root: str, dns: dict[str, Any] | None, http: dict[str, Any] | None, historical_only: bool) -> dict[str, Any]:
    dns = dns or {}
    http = http or {}
    cnames_raw = dns.get("cname") or http.get("cname") or []
    if isinstance(cnames_raw, str):
        cnames_raw = [cnames_raw]
    cnames = sorted({normalize_host(v) for v in cnames_raw if normalize_host(v)})
    delegated_provider = provider_from_cnames(cnames)
    http_ownership = str(http.get("ownership") or "").strip()
    app_provider = http.get("application_provider") or http.get("provider")
    cdn = http.get("cdn_detection") or {}
    cdn_detected = bool(cdn.get("detected")) or bool(http.get("cdn")) or http_ownership == "cdn_edge_or_first_party_frontend"

    if delegated_provider or http_ownership == "third_party_saas":
        return {
            "classification": "third_party_saas",
            "confidence": "high",
            "provider": delegated_provider or app_provider,
            "source": "dns_cname" if delegated_provider else "http_classification",
            "evidence": ([f"external_cname:{c}" for c in cnames] if cnames else ["http_third_party_classification"]),
        }
    if historical_only:
        return {
            "classification": "historical_unresolved",
            "confidence": "high",
            "provider": None,
            "source": "freshness_policy",
            "evidence": ["not_validated_in_current_run"],
        }
    if cdn_detected:
        provider = cdn.get("provider") or http.get("network_provider") or http.get("cdn_name")
        return {
            "classification": "cdn_edge_or_first_party_frontend",
            "confidence": "high",
            "provider": provider,
            "source": "http_edge_detection",
            "evidence": ["cdn_or_security_edge_detected"],
        }
    if in_scope(host, root) and (dns.get("a") or dns.get("aaaa") or http):
        return {
            "classification": "first_party_or_unknown",
            "confidence": "medium",
            "provider": None,
            "source": "in_scope_direct_evidence",
            "evidence": ["hostname_inside_authorized_root", "no_known_external_cname"],
        }
    return {
        "classification": "unresolved_ownership",
        "confidence": "low",
        "provider": None,
        "source": "insufficient_evidence",
        "evidence": ["ownership_not_resolved"],
    }


def route_testing(*, ownership: dict[str, Any], has_http: bool, current_dns: bool, confirmed_ports: bool, asset_types: list[str], waf: dict[str, Any] | None) -> dict[str, Any]:
    classification = ownership.get("classification")
    reasons: list[str] = []
    routes = {
        "http_headers": False,
        "tls_checks": False,
        "safe_web_templates": False,
        "technology_specific_templates": False,
        "network_service_checks": False,
        "openvas_remote_checks": False,
        "authenticated_checks": False,
        "third_party_checks": False,
    }
    if classification == "third_party_saas":
        reasons.append("third_party_infrastructure_restricted")
        return {"decision": "THIRD_PARTY_RESTRICTED", "active_testing_allowed": False, "requires_human_approval": True, "routes": routes, "reasons": reasons}
    if classification in {"historical_unresolved", "unresolved_ownership"}:
        reasons.append("asset_not_currently_validated_or_owned")
        return {"decision": "PASSIVE_ONLY", "active_testing_allowed": False, "requires_human_approval": True, "routes": routes, "reasons": reasons}
    if has_http:
        routes["http_headers"] = True
        routes["tls_checks"] = True
        routes["safe_web_templates"] = True
        routes["technology_specific_templates"] = True
    if confirmed_ports and classification == "first_party_or_unknown":
        routes["network_service_checks"] = True
        routes["openvas_remote_checks"] = True
    elif confirmed_ports and classification == "cdn_edge_or_first_party_frontend":
        reasons.append("network_scanning_blocked_for_shared_edge")
    if classification == "cdn_edge_or_first_party_frontend":
        reasons.append("web_vhost_checks_only_on_cdn_edge")
    if "vpn_or_security_appliance" in asset_types:
        reasons.append("security_appliance_requires_product_specific_review")
    if waf and waf.get("detected"):
        reasons.append("waf_present_use_rate_limited_checks")
    decision = "ALLOWED_ACTIVE" if any(routes.values()) else "REVALIDATION_REQUIRED"
    return {"decision": decision, "active_testing_allowed": decision == "ALLOWED_ACTIVE", "requires_human_approval": False, "routes": routes, "reasons": reasons}
