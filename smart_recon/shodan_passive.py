"""Credit-aware passive Shodan reconnaissance using the official REST API.

This module never calls Shodan's on-demand scanning endpoints. It uses only
passive database, DNS, count/search, and host-information methods.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .env_utils import load_env_file
from .io_utils import read_jsonl, write_json, write_jsonl, write_lines
from .validation import is_in_scope_host, is_valid_hostname, normalize_hostname

SHODAN_API_BASE = "https://api.shodan.io"
DEFAULT_FIELDS = (
    "ip_str,port,transport,org,isp,asn,hostnames,domains,product,version,cpe,tags,"
    "timestamp,http.title,http.status,http.server,http.waf,ssl.cert.subject.cn,"
    "ssl.cert.issuer.cn,ssl.cert.fingerprint.sha256,ssl.jarm,vulns"
)


class ShodanError(RuntimeError):
    """Raised for API, authentication, plan, or response failures."""


class ShodanNoData(ShodanError):
    """A valid host lookup with no Shodan record (HTTP 404)."""

    def __init__(self, ip: str, message: str = "No information available") -> None:
        super().__init__(message)
        self.ip = ip


@dataclass(slots=True)
class CreditLedger:
    configured_budget: int
    estimated_spent: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def remaining(self) -> int:
        return max(0, int(self.configured_budget) - int(self.estimated_spent))

    def can_spend(self, amount: int = 1) -> bool:
        return self.estimated_spent + max(0, int(amount)) <= max(0, int(self.configured_budget))

    def spend(self, *, operation: str, amount: int, detail: str) -> None:
        amount = max(0, int(amount))
        self.estimated_spent += amount
        self.events.append({"operation": operation, "estimated_query_credits": amount, "detail": detail})

    def to_dict(self) -> dict[str, Any]:
        return {
            "configured_budget": self.configured_budget,
            "estimated_spent": self.estimated_spent,
            "estimated_remaining": self.remaining,
            "events": self.events,
        }


class ShodanClient:
    def __init__(
        self,
        api_key: str,
        *,
        timeout: int = 20,
        api_rps: float = 1.0,
        cache_dir: Path | None = None,
        cache_ttl_hours: int = 24,
        user_agent: str = "SmartRecon/8.4 passive-shodan",
    ) -> None:
        if not api_key.strip():
            raise ValueError("Shodan API key is empty")
        self.api_key = api_key.strip()
        self.timeout = max(3, int(timeout))
        self.min_interval = 1.0 / max(0.1, float(api_rps))
        self.cache_dir = cache_dir
        self.cache_ttl_seconds = max(0, int(cache_ttl_hours)) * 3600
        self.user_agent = user_agent
        self._last_request = 0.0
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_key(self, path: str, params: dict[str, Any]) -> str:
        safe_params = {key: value for key, value in params.items() if key != "key"}
        material = json.dumps([path, safe_params], sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _cache_read(self, path: str, params: dict[str, Any]) -> Any | None:
        if not self.cache_dir or self.cache_ttl_seconds <= 0:
            return None
        cache_path = self.cache_dir / f"{self._cache_key(path, params)}.json"
        if not cache_path.exists():
            return None
        if time.time() - cache_path.stat().st_mtime > self.cache_ttl_seconds:
            return None
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _cache_write(self, path: str, params: dict[str, Any], value: Any) -> None:
        if not self.cache_dir:
            return
        cache_path = self.cache_dir / f"{self._cache_key(path, params)}.json"
        cache_path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def get(self, path: str, params: dict[str, Any] | None = None, *, use_cache: bool = True) -> Any:
        query = dict(params or {})
        query["key"] = self.api_key
        if use_cache:
            cached = self._cache_read(path, query)
            if cached is not None:
                return cached

        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

        url = f"{SHODAN_API_BASE}{path}?{urllib.parse.urlencode(query, doseq=True)}"
        request = urllib.request.Request(url, headers={"User-Agent": self.user_agent, "Accept": "application/json"})
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                self._last_request = time.monotonic()
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                value = json.loads(raw)
                if isinstance(value, dict) and value.get("error"):
                    raise ShodanError(str(value["error"]))
                if use_cache:
                    self._cache_write(path, query, value)
                return value
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
                try:
                    message = json.loads(body).get("error") if body else None
                except json.JSONDecodeError:
                    message = body[:500]
                if exc.code == 404 and path.startswith("/shodan/host/"):
                    ip = urllib.parse.unquote(path.rsplit("/", 1)[-1])
                    raise ShodanNoData(ip, str(message or exc.reason or "No information available"))
                last_error = ShodanError(f"HTTP {exc.code}: {message or exc.reason}")
                if exc.code not in {429, 500, 502, 503, 504}:
                    break
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ShodanError) as exc:
                last_error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
        raise ShodanError(str(last_error or "Shodan request failed"))

    def api_info(self) -> dict[str, Any]:
        value = self.get("/api-info", use_cache=False)
        return value if isinstance(value, dict) else {}

    def account_profile(self) -> dict[str, Any]:
        value = self.get("/account/profile", use_cache=False)
        return value if isinstance(value, dict) else {}

    def search_filters(self) -> list[str]:
        value = self.get("/shodan/host/search/filters")
        return [str(item) for item in value] if isinstance(value, list) else []

    def search_tokens(self, query: str) -> dict[str, Any]:
        value = self.get("/shodan/host/search/tokens", {"query": query})
        return value if isinstance(value, dict) else {}

    def count(self, query: str, facets: str = "port,org,product") -> dict[str, Any]:
        value = self.get("/shodan/host/count", {"query": query, "facets": facets})
        return value if isinstance(value, dict) else {}

    def search(self, query: str, *, page: int = 1, fields: str = DEFAULT_FIELDS) -> dict[str, Any]:
        # Shodan rejects fields with minify=true. Explicit minify=false is the
        # documented compatible form and preserves only the requested fields.
        value = self.get(
            "/shodan/host/search",
            {"query": query, "page": max(1, int(page)), "minify": "false", "fields": fields},
        )
        return value if isinstance(value, dict) else {}

    def domain(self, domain: str, *, page: int = 1, history: bool = False) -> dict[str, Any]:
        value = self.get(
            f"/dns/domain/{urllib.parse.quote(domain, safe='')}",
            {"page": max(1, int(page)), "history": str(bool(history)).lower()},
        )
        return value if isinstance(value, dict) else {}

    def host(self, ip: str, *, history: bool = False, minify: bool = False) -> dict[str, Any]:
        value = self.get(
            f"/shodan/host/{urllib.parse.quote(ip, safe='')}",
            {"history": str(bool(history)).lower(), "minify": str(bool(minify)).lower()},
        )
        return value if isinstance(value, dict) else {}

    def resolve(self, hostnames: Iterable[str]) -> dict[str, str]:
        values = sorted({normalize_hostname(host) for host in hostnames if host})
        if not values:
            return {}
        value = self.get("/dns/resolve", {"hostnames": ",".join(values)})
        return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}

    def reverse(self, ips: Iterable[str]) -> dict[str, list[str]]:
        values = sorted({str(ip) for ip in ips if ip})
        if not values:
            return {}
        value = self.get("/dns/reverse", {"ips": ",".join(values)})
        if not isinstance(value, dict):
            return {}
        return {str(k): [str(item) for item in (v or [])] for k, v in value.items()}


def _project_path(value: str | Path, project_root: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else project_root / path


def load_api_key(env_file: Path) -> tuple[str, dict[str, Any]]:
    loaded = load_env_file(env_file)
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    return key, {
        "env_file": str(env_file),
        "env_file_exists": env_file.exists(),
        "loaded_keys": sorted(key_name for key_name in loaded if key_name != "SHODAN_API_KEY"),
        "api_key_configured": bool(key),
    }


def load_dork_templates(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to load Shodan dorks file {path}: {exc}") from exc
    if not isinstance(value, list):
        raise ValueError("Shodan dorks file must contain a JSON array")
    return [dict(item) for item in value if isinstance(item, dict)]


def build_scopes(target: str, *, org: str | None = None, asn: str | None = None, net: str | None = None) -> list[dict[str, str]]:
    scopes = [
        {"scope_id": "target", "scope": "", "scope_value": target},
        {"scope_id": "hostname", "scope": f'hostname:"{target}"', "scope_value": target},
    ]
    if org and org.strip():
        scopes.append({"scope_id": "org", "scope": f'org:"{org.strip()}"', "scope_value": org.strip()})
    if asn and asn.strip():
        normalized_asn = asn.strip().upper()
        if not normalized_asn.startswith("AS"):
            normalized_asn = "AS" + normalized_asn
        scopes.append({"scope_id": "asn", "scope": f"asn:{normalized_asn}", "scope_value": normalized_asn})
    if net and net.strip():
        ipaddress.ip_network(net.strip(), strict=False)
        scopes.append({"scope_id": "net", "scope": f"net:{net.strip()}", "scope_value": net.strip()})
    return scopes


def render_dork_plan(
    templates: list[dict[str, Any]],
    *,
    target: str,
    org: str | None,
    asn: str | None,
    net: str | None,
    include_disabled: bool,
    max_dorks: int,
) -> list[dict[str, Any]]:
    rendered: list[dict[str, Any]] = []
    scopes = build_scopes(target, org=org, asn=asn, net=net)
    for template in templates:
        enabled = bool(template.get("enabled_by_default", True))
        if not enabled and not include_disabled:
            continue
        scope_ids = {str(value) for value in (template.get("scope_types") or ["hostname"])}
        for scope in scopes:
            if scope["scope_id"] not in scope_ids:
                continue
            query_template = str(template.get("query_template") or "{scope}").strip()
            query = query_template.format(scope=scope["scope"], target=target, org=org or "", asn=asn or "", net=net or "")
            if "{" in query or "}" in query:
                continue
            rendered.append({
                "id": f"{template.get('id', 'query')}__{scope['scope_id']}",
                "template_id": template.get("id"),
                "category": template.get("category", "general"),
                "purpose": template.get("purpose", ""),
                "scope_id": scope["scope_id"],
                "scope_value": scope["scope_value"],
                "query": " ".join(query.split()),
                "facets": template.get("facets", "port,org,product"),
                "enabled_by_default": enabled,
                "risk": template.get("risk", "passive"),
            })
            if len(rendered) >= max(1, int(max_dorks)):
                return rendered
    return rendered


def _safe_host(value: Any, target: str) -> str | None:
    host = normalize_hostname(value or "")
    if host and is_valid_hostname(host) and is_in_scope_host(host, target):
        return host
    return None


def extract_domain_hosts(response: dict[str, Any], target: str) -> tuple[set[str], list[dict[str, Any]], set[str]]:
    hosts: set[str] = set()
    records: list[dict[str, Any]] = []
    ips: set[str] = set()
    for item in response.get("data") or []:
        if not isinstance(item, dict):
            continue
        subdomain = str(item.get("subdomain") or "").strip(".")
        host = target if not subdomain else f"{subdomain}.{target}"
        normalized = _safe_host(host, target)
        if not normalized:
            continue
        record = {
            "host": normalized,
            "type": str(item.get("type") or ""),
            "value": item.get("value"),
            "last_seen": item.get("last_seen"),
            "source": "shodan_dns_domain",
        }
        records.append(record)
        if normalized != target:
            hosts.add(normalized)
        if record["type"] in {"A", "AAAA"}:
            try:
                ips.add(str(ipaddress.ip_address(str(record["value"]))))
            except ValueError:
                pass
    return hosts, records, ips


def extract_hosts_from_banner(banner: dict[str, Any], target: str) -> set[str]:
    candidates: set[str] = set()
    for key in ("hostnames", "domains"):
        for value in banner.get(key) or []:
            host = _safe_host(value, target)
            if host and host != target:
                candidates.add(host)
    ssl = banner.get("ssl") or {}
    cert = ssl.get("cert") or {} if isinstance(ssl, dict) else {}
    subject = cert.get("subject") or {} if isinstance(cert, dict) else {}
    cn = subject.get("CN") or subject.get("cn") if isinstance(subject, dict) else None
    host = _safe_host(cn, target)
    if host and host != target:
        candidates.add(host)
    extensions = cert.get("extensions") or [] if isinstance(cert, dict) else []
    for extension in extensions if isinstance(extensions, list) else []:
        if not isinstance(extension, dict):
            continue
        if str(extension.get("name") or "").lower() not in {"subjectaltname", "subject alternative name"}:
            continue
        data = str(extension.get("data") or "")
        for value in re.findall(r"DNS:([A-Za-z0-9.*_-]+(?:\.[A-Za-z0-9_-]+)+)", data, re.IGNORECASE):
            host = _safe_host(value.lstrip("*."), target)
            if host and host != target:
                candidates.add(host)
    return candidates


def normalize_banner(banner: dict[str, Any], *, query_id: str | None = None, source: str = "shodan_search") -> dict[str, Any]:
    ssl = banner.get("ssl") or {}
    cert = ssl.get("cert") or {} if isinstance(ssl, dict) else {}
    subject = cert.get("subject") or {} if isinstance(cert, dict) else {}
    issuer = cert.get("issuer") or {} if isinstance(cert, dict) else {}
    http = banner.get("http") or {}
    vulns_value = banner.get("vulns") or []
    if isinstance(vulns_value, dict):
        vulns = sorted(str(key) for key in vulns_value)
    else:
        vulns = sorted(str(value) for value in vulns_value) if isinstance(vulns_value, list) else []
    return {
        "source": source,
        "query_id": query_id,
        "ip": banner.get("ip_str") or banner.get("ip"),
        "port": banner.get("port"),
        "transport": banner.get("transport"),
        "timestamp": banner.get("timestamp"),
        "org": banner.get("org"),
        "isp": banner.get("isp"),
        "asn": banner.get("asn"),
        "hostnames": banner.get("hostnames") or [],
        "domains": banner.get("domains") or [],
        "product": banner.get("product"),
        "version": banner.get("version"),
        "cpe": banner.get("cpe") or [],
        "tags": banner.get("tags") or [],
        "http_title": http.get("title") if isinstance(http, dict) else None,
        "http_status": http.get("status") if isinstance(http, dict) else None,
        "http_server": http.get("server") if isinstance(http, dict) else None,
        "http_waf": http.get("waf") if isinstance(http, dict) else None,
        "ssl_subject_cn": subject.get("CN") or subject.get("cn") if isinstance(subject, dict) else None,
        "ssl_issuer_cn": issuer.get("CN") or issuer.get("cn") if isinstance(issuer, dict) else None,
        "ssl_jarm": ssl.get("jarm") if isinstance(ssl, dict) else None,
        "vulnerabilities": vulns,
    }


def _write_ports_csv(path: Path, services: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "ip", "port", "transport", "timestamp", "org", "asn", "product", "version", "hostnames", "vulnerabilities", "source", "query_id"
        ])
        writer.writeheader()
        for row in services:
            writer.writerow({
                **{key: row.get(key, "") for key in writer.fieldnames},
                "hostnames": ",".join(row.get("hostnames") or []),
                "vulnerabilities": ",".join(row.get("vulnerabilities") or []),
            })


def _aggregate_assets(services: list[dict[str, Any]], target: str) -> dict[str, Any]:
    assets: dict[str, dict[str, Any]] = {}
    for service in services:
        ip = str(service.get("ip") or "")
        if not ip:
            continue
        asset = assets.setdefault(ip, {
            "ip": ip, "ports": [], "hostnames": [], "products": [], "organizations": [],
            "asns": [], "tags": [], "vulnerabilities": [], "last_seen": [], "sources": [],
        })
        if service.get("port") is not None:
            asset["ports"].append(int(service["port"]))
        asset["hostnames"].extend(
            host for host in (service.get("hostnames") or []) if _safe_host(host, target)
        )
        if service.get("product"):
            value = str(service["product"])
            if service.get("version"):
                value += f" {service['version']}"
            asset["products"].append(value)
        if service.get("org"):
            asset["organizations"].append(str(service["org"]))
        if service.get("asn"):
            asset["asns"].append(str(service["asn"]))
        asset["tags"].extend(str(value) for value in (service.get("tags") or []))
        asset["vulnerabilities"].extend(str(value) for value in (service.get("vulnerabilities") or []))
        if service.get("timestamp"):
            asset["last_seen"].append(str(service["timestamp"]))
        asset["sources"].append(str(service.get("source") or "shodan"))
    for asset in assets.values():
        for key in ("ports", "hostnames", "products", "organizations", "asns", "tags", "vulnerabilities", "last_seen", "sources"):
            asset[key] = sorted(set(asset[key]))
    return dict(sorted(assets.items()))


def prepare_shodan_context(
    *,
    project_root: Path,
    output_root: Path,
    args: Any,
) -> dict[str, Any]:
    env_file = _project_path(args.env_file, project_root)
    api_key, env_status = load_api_key(env_file)
    cache_dir = output_root / ".shodan_cache"
    return {
        "enabled": bool(args.shodan_passive),
        "api_key": api_key,
        "env_status": env_status,
        "cache_dir": cache_dir,
        "dorks_file": _project_path(args.shodan_dorks_file, project_root),
    }


def run_shodan_discovery(
    *,
    target: str,
    run_dir: Path,
    context: dict[str, Any],
    args: Any,
) -> dict[str, Any]:
    """Run credit-aware domain discovery and scoped dork planning/search."""
    result: dict[str, Any] = {
        "requested": bool(args.shodan_passive),
        "status": "NOT_REQUESTED",
        "api_key_configured": bool(context.get("api_key")),
        "discovered_hosts": [],
        "discovered_ips": [],
        "services": [],
        "errors": [],
        "warnings": [],
    }
    for filename, default in (
        ("shodan_dns_domain.jsonl", []), ("shodan_search_results.jsonl", []),
        ("shodan_dork_counts.json", []), ("shodan_dork_plan.json", []),
        ("shodan_discovered_hosts.txt", []), ("shodan_host_lookups.jsonl", []),
        ("shodan_host_no_data.jsonl", []),
    ):
        path = run_dir / filename
        if filename.endswith(".jsonl"):
            write_jsonl(path, default)
        elif filename.endswith(".txt"):
            write_lines(path, default)
        else:
            write_json(path, default)
    if not args.shodan_passive:
        write_json(run_dir / "shodan_summary.json", result)
        return result
    if not context.get("api_key"):
        result["status"] = "NOT_CONFIGURED"
        result["warnings"].append("SHODAN_API_KEY is empty; passive Shodan stage was skipped.")
        write_json(run_dir / "shodan_summary.json", result)
        return result

    client = ShodanClient(
        str(context["api_key"]),
        timeout=args.shodan_timeout,
        api_rps=args.shodan_api_rps,
        cache_dir=Path(context["cache_dir"]),
        cache_ttl_hours=args.shodan_cache_ttl_hours,
    )
    ledger = CreditLedger(args.shodan_max_query_credits)
    discovered_hosts: set[str] = set()
    discovered_ips: set[str] = set()
    dns_records: list[dict[str, Any]] = []
    search_services: list[dict[str, Any]] = []

    try:
        api_info_before = client.api_info()
        profile = client.account_profile()
        filters = client.search_filters()
        write_json(run_dir / "shodan_api_info.json", {
            "plan": api_info_before.get("plan"),
            "query_credits": api_info_before.get("query_credits"),
            "scan_credits": api_info_before.get("scan_credits"),
            "usage_limits": api_info_before.get("usage_limits"),
            "profile": {"member": profile.get("member"), "created": profile.get("created")},
        })
        write_json(run_dir / "shodan_search_filters.json", filters)
    except ShodanError as exc:
        result["status"] = "FAILED"
        result["errors"].append(str(exc))
        write_json(run_dir / "shodan_summary.json", result)
        return result

    # Domain endpoint: documented as one query credit per page.
    for page in range(1, max(1, args.shodan_domain_pages) + 1):
        if not ledger.can_spend(1):
            result["warnings"].append("Shodan query-credit budget reached before all domain pages were requested.")
            break
        try:
            response = client.domain(target, page=page, history=bool(args.shodan_history))
            ledger.spend(operation="dns_domain", amount=1, detail=f"{target} page {page}")
            hosts, records, ips = extract_domain_hosts(response, target)
            discovered_hosts |= hosts
            discovered_ips |= ips
            dns_records.extend(records)
            if not response.get("more"):
                break
        except ShodanError as exc:
            result["errors"].append(f"dns/domain page {page}: {exc}")
            break
    write_jsonl(run_dir / "shodan_dns_domain.jsonl", dns_records)

    try:
        templates = load_dork_templates(Path(context["dorks_file"]))
        plan = render_dork_plan(
            templates,
            target=target,
            org=args.shodan_org,
            asn=args.shodan_asn,
            net=args.shodan_net,
            include_disabled=bool(args.shodan_include_disabled_dorks),
            max_dorks=args.shodan_max_dorks,
        )
    except (ValueError, OSError) as exc:
        plan = []
        result["errors"].append(str(exc))
    write_json(run_dir / "shodan_dork_plan.json", plan)

    counts: list[dict[str, Any]] = []
    valid_plan: list[dict[str, Any]] = []
    for item in plan:
        try:
            tokens = client.search_tokens(item["query"])
            errors = tokens.get("errors") or []
            item["tokens"] = tokens
            item["valid"] = not errors
            if errors:
                item["validation_errors"] = errors
                counts.append({"id": item["id"], "query": item["query"], "valid": False, "errors": errors, "total": 0})
                continue
            count = client.count(item["query"], str(item.get("facets") or "port,org,product"))
            total = int(count.get("total") or 0)
            counts.append({"id": item["id"], "query": item["query"], "valid": True, "total": total, "facets": count.get("facets") or {}})
            if total > 0:
                valid_plan.append(item)
        except ShodanError as exc:
            counts.append({"id": item["id"], "query": item["query"], "valid": False, "errors": [str(exc)], "total": 0})
    write_json(run_dir / "shodan_dork_plan.json", plan)
    write_json(run_dir / "shodan_dork_counts.json", counts)

    if not args.shodan_count_only and not args.shodan_skip_search:
        for item in valid_plan:
            for page in range(1, max(1, args.shodan_pages_per_query) + 1):
                if not ledger.can_spend(1):
                    result["warnings"].append("Shodan query-credit budget reached; remaining dork result searches were skipped.")
                    break
                try:
                    response = client.search(item["query"], page=page)
                    ledger.spend(operation="host_search", amount=1, detail=f"{item['id']} page {page}")
                    matches = response.get("matches") or []
                    for match in matches[: max(1, args.shodan_results_per_query)]:
                        if not isinstance(match, dict):
                            continue
                        service = normalize_banner(match, query_id=item["id"], source="shodan_dork_search")
                        search_services.append(service)
                        discovered_hosts |= extract_hosts_from_banner(match, target)
                        if service.get("ip"):
                            try:
                                discovered_ips.add(str(ipaddress.ip_address(str(service["ip"]))))
                            except ValueError:
                                pass
                    if len(matches) < 100:
                        break
                except ShodanError as exc:
                    result["errors"].append(f"search {item['id']} page {page}: {exc}")
                    break
            if not ledger.can_spend(1):
                break
    write_jsonl(run_dir / "shodan_search_results.jsonl", search_services)
    write_lines(run_dir / "shodan_discovered_hosts.txt", discovered_hosts)

    try:
        api_info_after = client.api_info()
    except ShodanError:
        api_info_after = {}
    before_credits = api_info_before.get("query_credits")
    after_credits = api_info_after.get("query_credits")
    actual_delta = None
    if isinstance(before_credits, int) and isinstance(after_credits, int):
        actual_delta = max(0, before_credits - after_credits)

    result.update({
        "status": "COMPLETE" if not result["errors"] else "PARTIAL",
        "discovered_hosts": sorted(discovered_hosts),
        "discovered_ips": sorted(discovered_ips),
        "services": search_services,
        "dns_records": len(dns_records),
        "dorks_planned": len(plan),
        "dorks_with_results": len(valid_plan),
        "count_only": bool(args.shodan_count_only),
        "credit_ledger": ledger.to_dict(),
        "api_query_credits_before": before_credits,
        "api_query_credits_after": after_credits,
        "api_query_credits_actual_delta": actual_delta,
    })
    write_json(run_dir / "shodan_credit_ledger.json", result["credit_ledger"])
    write_json(run_dir / "shodan_summary.json", {key: value for key, value in result.items() if key != "services"})
    return result


def run_shodan_host_enrichment(
    *,
    target: str,
    run_dir: Path,
    context: dict[str, Any],
    args: Any,
    discovery: dict[str, Any],
    validated_dns: dict[str, dict[str, Any]],
    classified_assets: list[dict[str, Any]],
) -> dict[str, Any]:
    """Enrich first-party/unknown IPs with Shodan host information."""
    if not args.shodan_passive or not context.get("api_key"):
        summary = dict(discovery)
        summary.pop("services", None)
        write_json(run_dir / "shodan_summary.json", summary)
        return summary

    client = ShodanClient(
        str(context["api_key"]),
        timeout=args.shodan_timeout,
        api_rps=args.shodan_api_rps,
        cache_dir=Path(context["cache_dir"]),
        cache_ttl_hours=args.shodan_cache_ttl_hours,
    )
    excluded_hosts = {
        str(asset.get("host") or "") for asset in classified_assets
        if str(asset.get("ownership") or "") == "third_party_saas"
        or bool((asset.get("cdn_detection") or {}).get("detected"))
    }
    excluded_ips: set[str] = set()
    if not args.shodan_include_edge_ips:
        for host in excluded_hosts:
            record = validated_dns.get(host) or {}
            for key in ("a", "aaaa"):
                for value in record.get(key) or []:
                    try:
                        excluded_ips.add(str(ipaddress.ip_address(str(value))))
                    except ValueError:
                        pass
    ips: set[str] = {
        str(value) for value in (discovery.get("discovered_ips") or [])
        if str(value) not in excluded_ips
    }
    for host, record in validated_dns.items():
        if host in excluded_hosts and not args.shodan_include_edge_ips:
            continue
        for key in ("a", "aaaa"):
            for value in record.get(key) or []:
                try:
                    ips.add(str(ipaddress.ip_address(str(value))))
                except ValueError:
                    pass
    selected_ips = sorted(ips)[: max(0, args.shodan_max_host_lookups)]
    host_records: list[dict[str, Any]] = []
    no_data_records: list[dict[str, Any]] = []
    services = list(discovery.get("services") or [])
    discovered_hosts = set(discovery.get("discovered_hosts") or [])
    errors = list(discovery.get("errors") or [])

    for ip in selected_ips:
        try:
            response = client.host(ip, history=bool(args.shodan_history), minify=False)
        except ShodanNoData as exc:
            no_data_records.append({"ip": ip, "status": "no_data", "message": str(exc)})
            continue
        except ShodanError as exc:
            errors.append(f"host {ip}: {exc}")
            continue
        host_records.append(response)
        for banner in response.get("data") or []:
            if not isinstance(banner, dict):
                continue
            banner.setdefault("ip_str", response.get("ip_str") or ip)
            banner.setdefault("org", response.get("org"))
            banner.setdefault("isp", response.get("isp"))
            banner.setdefault("asn", response.get("asn"))
            banner.setdefault("hostnames", response.get("hostnames") or [])
            service = normalize_banner(banner, source="shodan_host_lookup")
            services.append(service)
            discovered_hosts |= extract_hosts_from_banner(banner, target)
    write_jsonl(run_dir / "shodan_host_lookups.jsonl", host_records)
    write_jsonl(run_dir / "shodan_host_no_data.jsonl", no_data_records)
    write_jsonl(run_dir / "shodan_services.jsonl", services)
    assets = _aggregate_assets(services, target)
    write_json(run_dir / "shodan_assets.json", assets)
    _write_ports_csv(run_dir / "shodan_ports.csv", services)
    vulnerabilities = sorted({vuln for service in services for vuln in (service.get("vulnerabilities") or [])})
    write_json(run_dir / "shodan_vulnerabilities.json", vulnerabilities)
    write_lines(run_dir / "shodan_discovered_hosts.txt", discovered_hosts)

    summary = {key: value for key, value in discovery.items() if key != "services"}
    summary.update({
        "status": "COMPLETE" if not errors else "PARTIAL",
        "errors": errors,
        "host_lookups_requested": len(selected_ips),
        "host_lookups_completed": len(host_records),
        "host_lookups_no_data": len(no_data_records),
        "looked_up_ips": sorted(selected_ips),
        "services_collected": len(services),
        "assets_enriched": len(assets),
        "unique_vulnerabilities_observed": len(vulnerabilities),
        "discovered_hosts": sorted(discovered_hosts),
        "discovered_ips": sorted(ips),
        "include_edge_ips": bool(args.shodan_include_edge_ips),
        "history_requested": bool(args.shodan_history),
    })
    write_json(run_dir / "shodan_summary.json", summary)
    return summary


def run_shodan_incremental_host_enrichment(
    *,
    target: str,
    run_dir: Path,
    context: dict[str, Any],
    args: Any,
    validated_dns: dict[str, dict[str, Any]],
    classified_assets: list[dict[str, Any]],
    hosts: set[str],
    already_looked_up_ips: set[str],
    level_label: str,
) -> dict[str, Any]:
    """Enrich only newly encountered recursive hosts and merge aggregate files.

    This endpoint reads Shodan's existing host database. A 404 is normal
    ``no_data`` evidence and does not make the passive stage partial.
    """
    result: dict[str, Any] = {
        "requested": bool(args.shodan_passive),
        "status": "NOT_REQUESTED",
        "hosts_considered": len(hosts),
        "looked_up_ips": [],
        "completed": 0,
        "no_data": 0,
        "discovered_hosts": [],
        "errors": [],
    }
    if not args.shodan_passive or not context.get("api_key"):
        return result

    asset_by_host = {
        normalize_hostname(asset.get("host") or ""): asset
        for asset in classified_assets
        if normalize_hostname(asset.get("host") or "")
    }
    ips: set[str] = set()
    for host in hosts:
        normalized = normalize_hostname(host)
        if not normalized or not is_in_scope_host(normalized, target):
            continue
        asset = asset_by_host.get(normalized) or {}
        if not args.shodan_include_edge_ips:
            if str(asset.get("ownership") or "") == "third_party_saas":
                continue
            if bool((asset.get("cdn_detection") or {}).get("detected")):
                continue
        record = validated_dns.get(normalized) or {}
        for key in ("a", "aaaa"):
            for value in record.get(key) or []:
                try:
                    ip = str(ipaddress.ip_address(str(value)))
                except ValueError:
                    continue
                if ip not in already_looked_up_ips:
                    ips.add(ip)

    selected_ips = sorted(ips)[: max(0, int(args.shodan_max_host_lookups))]
    result["looked_up_ips"] = selected_ips
    if not selected_ips:
        result["status"] = "COMPLETE"
        return result

    client = ShodanClient(
        str(context["api_key"]),
        timeout=args.shodan_timeout,
        api_rps=args.shodan_api_rps,
        cache_dir=Path(context["cache_dir"]),
        cache_ttl_hours=args.shodan_cache_ttl_hours,
    )
    host_records: list[dict[str, Any]] = []
    no_data_records: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    discovered_hosts: set[str] = set()

    for ip in selected_ips:
        try:
            response = client.host(ip, history=bool(args.shodan_history), minify=False)
        except ShodanNoData as exc:
            no_data_records.append({"ip": ip, "status": "no_data", "message": str(exc), "level": level_label})
            continue
        except ShodanError as exc:
            result["errors"].append(f"host {ip}: {exc}")
            continue
        response = dict(response)
        response["recursive_level"] = level_label
        host_records.append(response)
        for banner in response.get("data") or []:
            if not isinstance(banner, dict):
                continue
            banner = dict(banner)
            banner.setdefault("ip_str", response.get("ip_str") or ip)
            banner.setdefault("org", response.get("org"))
            banner.setdefault("isp", response.get("isp"))
            banner.setdefault("asn", response.get("asn"))
            banner.setdefault("hostnames", response.get("hostnames") or [])
            service = normalize_banner(banner, source=f"shodan_recursive_{level_label}")
            services.append(service)
            discovered_hosts |= extract_hosts_from_banner(banner, target)

    level_dir = run_dir / "recursive" / level_label
    level_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(level_dir / "shodan_host_lookups.jsonl", host_records)
    write_jsonl(level_dir / "shodan_no_data.jsonl", no_data_records)
    write_jsonl(level_dir / "shodan_services.jsonl", services)

    aggregate_host_records = read_jsonl(run_dir / "shodan_host_lookups.jsonl") + host_records
    aggregate_no_data = read_jsonl(run_dir / "shodan_host_no_data.jsonl") + no_data_records
    aggregate_services = read_jsonl(run_dir / "shodan_services.jsonl") + services

    # Deduplicate aggregate records deterministically.
    host_map: dict[str, dict[str, Any]] = {}
    for record in aggregate_host_records:
        ip = str(record.get("ip_str") or record.get("ip") or "")
        if ip:
            host_map[ip] = record
    no_data_map: dict[str, dict[str, Any]] = {}
    for record in aggregate_no_data:
        ip = str(record.get("ip") or "")
        if ip:
            no_data_map[ip] = record
    service_map: dict[tuple[str, int, str, str], dict[str, Any]] = {}
    for service in aggregate_services:
        key = (
            str(service.get("ip") or ""),
            int(service.get("port") or 0),
            str(service.get("transport") or ""),
            str(service.get("timestamp") or service.get("source") or ""),
        )
        service_map[key] = service

    aggregate_host_records = list(host_map.values())
    aggregate_no_data = list(no_data_map.values())
    aggregate_services = list(service_map.values())
    write_jsonl(run_dir / "shodan_host_lookups.jsonl", aggregate_host_records)
    write_jsonl(run_dir / "shodan_host_no_data.jsonl", aggregate_no_data)
    write_jsonl(run_dir / "shodan_services.jsonl", aggregate_services)

    existing_discovered = set(read_lines(run_dir / "shodan_discovered_hosts.txt"))
    existing_discovered |= discovered_hosts
    write_lines(run_dir / "shodan_discovered_hosts.txt", existing_discovered)

    assets = _aggregate_assets(aggregate_services, target)
    write_json(run_dir / "shodan_assets.json", assets)
    _write_ports_csv(run_dir / "shodan_ports.csv", aggregate_services)
    vulnerabilities = sorted({vuln for service in aggregate_services for vuln in (service.get("vulnerabilities") or [])})
    write_json(run_dir / "shodan_vulnerabilities.json", vulnerabilities)

    result.update({
        "status": "PARTIAL" if result["errors"] else "COMPLETE",
        "completed": len(host_records),
        "no_data": len(no_data_records),
        "services": len(services),
        "discovered_hosts": sorted(discovered_hosts),
        "aggregate_services": len(aggregate_services),
        "aggregate_assets": len(assets),
    })
    return result
