"""Discovery, DNS, previous-run, ownership, and private-IP parsers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urlsplit

from .config import THIRD_PARTY_PROVIDERS
from .io_utils import read_lines
from .validation import is_in_scope_host, is_valid_hostname, normalize_hostname

PRIVATE_IP_RE = re.compile(
    r"\b(?:(?:10)\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|"
    r"(?:127)\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|"
    r"(?:192\.168)\.(?:\d{1,3})\.(?:\d{1,3})|"
    r"(?:172)\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3}))\b"
)


def extract_domains_from_text(text: str, target: str) -> set[str]:
    # DNS labels may contain letters, numbers, and interior hyphens. Do not mutate underscores into hyphens.
    label = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    pattern = re.compile(rf"(?<!%)\b(?:{label}\.)+{re.escape(target)}\b", re.IGNORECASE)
    found = {normalize_hostname(match.group(0)) for match in pattern.finditer(text)}
    return {
        host for host in found
        if is_valid_hostname(host) and is_in_scope_host(host, target)
    }


def extract_in_scope_hosts_from_url(url: str, target: str) -> set[str]:
    """Extract hosts only from parsed URL authorities, including nested URL query values.

    Raw regex scanning of percent-encoded URLs can turn ``%2F%2Fadmin.example.com``
    into the false hostname ``2fadmin.example.com``. This helper parses the outer
    URL first and only inspects decoded query values when they are complete HTTP(S)
    URLs. Path fragments and arbitrary encoded text are never treated as hostnames.
    """
    raw = str(url or "").strip().replace("\\", "/")
    if not raw:
        return set()

    hosts: set[str] = set()

    def add_host(value: str | None) -> None:
        host = normalize_hostname(value or "")
        if host and is_valid_hostname(host) and is_in_scope_host(host, target):
            hosts.add(host)

    try:
        outer = urlsplit(raw)
    except ValueError:
        return hosts
    add_host(outer.hostname)

    for _, query_value in parse_qsl(outer.query, keep_blank_values=True):
        decoded = unquote(str(query_value or "")).strip().replace("\\", "/")
        if not decoded.lower().startswith(("http://", "https://")):
            continue
        try:
            nested = urlsplit(decoded)
        except ValueError:
            continue
        add_host(nested.hostname)

    fragment = unquote(str(outer.fragment or "")).strip().replace("\\", "/")
    if fragment.lower().startswith(("http://", "https://")):
        try:
            add_host(urlsplit(fragment).hostname)
        except ValueError:
            pass
    return hosts


def parse_gobuster(path: Path, target: str) -> set[str]:
    hosts: set[str] = set()
    for line in read_lines(path):
        hosts |= extract_domains_from_text(line, target)
    return hosts


def parse_gobuster_records(path: Path, target: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for line in read_lines(path):
        hosts = extract_domains_from_text(line, target)
        ips = sorted(set(ip_re.findall(line)))
        for host in hosts:
            if host == target:
                continue
            records[host] = {
                "host": host,
                "a": ips,
                "cname": [],
                "source_pipeline": "gobuster_dns",
                "source_file": path.name,
                "validation_state": "dns_resolved" if ips else "discovered",
            }
    return records


def collect_bbot_subdomains(bbot_dir: Path, target: str) -> set[str]:
    hosts: set[str] = set()
    for path in bbot_dir.rglob("subdomains.txt"):
        for line in read_lines(path):
            value = normalize_hostname(line)
            if is_valid_hostname(value) and is_in_scope_host(value, target):
                hosts.add(value)
    for path in bbot_dir.rglob("output.txt"):
        try:
            hosts |= extract_domains_from_text(path.read_text(encoding="utf-8", errors="replace"), target)
        except OSError:
            continue
    return hosts


def collect_bbot_dns_records(bbot_dir: Path, target: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for path in bbot_dir.rglob("output.json"):
        for line in read_lines(path):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "DNS_NAME":
                continue
            host = normalize_hostname(obj.get("host") or obj.get("data") or "")
            if host == target or not is_valid_hostname(host) or not is_in_scope_host(host, target):
                continue
            children = obj.get("dns_children") or {}
            a_records = sorted({
                str(value)
                for value in (children.get("A") or obj.get("resolved_hosts") or [])
                if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", str(value))
            })
            cnames = sorted({normalize_hostname(value) for value in (children.get("CNAME") or []) if value})
            if a_records or cnames:
                records[host] = {
                    "host": host,
                    "a": a_records,
                    "cname": cnames,
                    "source_pipeline": "bbot_dns",
                    "source_file": path.name,
                    "module": obj.get("module"),
                    "tags": obj.get("tags", []),
                    "validation_state": "dns_resolved" if a_records else "cname_only",
                }
    return records


def parse_dnsx_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for line in read_lines(path):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = normalize_hostname(obj.get("host", ""))
        if not host or not is_valid_hostname(host):
            continue
        a = obj.get("a") or []
        aaaa = obj.get("aaaa") or []
        cname = [normalize_hostname(value) for value in (obj.get("cname") or []) if value]
        if a or aaaa or cname:
            obj["host"] = host
            obj["cname"] = cname
            obj["validation_state"] = "dns_resolved" if (a or aaaa) else "cname_only"
            results[host] = obj
    return results


def merge_dns_records(*sources: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for source in sources:
        for host, record in source.items():
            current = merged.setdefault(host, {"host": host, "a": [], "aaaa": [], "cname": []})
            for key in ("a", "aaaa", "cname"):
                current[key] = sorted(set(current.get(key, []) or []) | set(record.get(key, []) or []))
            for key, value in record.items():
                if key not in {"a", "aaaa", "cname"} and value not in (None, "", [], {}):
                    current.setdefault(key, value)
            current["validation_state"] = "dns_resolved" if (current["a"] or current["aaaa"]) else "cname_only"
    return merged


def get_answer_signature(obj: dict[str, Any]) -> str:
    return json.dumps(
        {
            "a": sorted(str(value).lower() for value in obj.get("a", [])),
            "aaaa": sorted(str(value).lower() for value in obj.get("aaaa", [])),
            "cname": sorted(normalize_hostname(value) for value in obj.get("cname", [])),
        },
        sort_keys=True,
    )


def is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second, _, _ = [int(value) for value in parts]
    except ValueError:
        return False
    return first == 10 or first == 127 or (first == 192 and second == 168) or (first == 172 and 16 <= second <= 31)


def extract_internal_ip_leaks_from_lines(
    lines: Iterable[str],
    source: str,
    *,
    evidence_origin: str = "target_response",
) -> list[dict[str, str]]:
    """Extract private IPs only when the caller can identify the evidence origin."""
    leaks: dict[tuple[str, str], dict[str, str]] = {}
    for line in lines:
        text = str(line).strip()
        if not text:
            continue
        for match in PRIVATE_IP_RE.finditer(text):
            ip = match.group(0)
            if not is_private_ip(ip):
                continue
            key = (ip, text[:500])
            leaks[key] = {
                "ip": ip,
                "source": source,
                "evidence_origin": evidence_origin,
                "evidence": text[:500],
                "risk_note": (
                    "Private/internal IP reference was observed in target-controlled content. "
                    "Verify manually; this is not automatically a vulnerability."
                ),
            }
    return list(leaks.values())


def extract_internal_ip_leaks_from_http_records(records: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    """Scan only target response fields, never browser/container connection metadata."""
    target_fields = ("body", "response_body", "header", "headers", "response_headers", "csp")
    lines: list[str] = []
    for record in records:
        for field in target_fields:
            value = record.get(field)
            if isinstance(value, str):
                lines.append(value)
            elif isinstance(value, (dict, list)):
                lines.append(json.dumps(value, ensure_ascii=False))
    return extract_internal_ip_leaks_from_lines(lines, "httpx_target_response", evidence_origin="target_response")


def classify_cname_ownership(cnames: Iterable[str]) -> tuple[str, str | None]:
    for cname in cnames:
        normalized = normalize_hostname(cname)
        for suffix, provider in THIRD_PARTY_PROVIDERS.items():
            if normalized == suffix or normalized.endswith("." + suffix):
                return "third_party_saas", provider
    return "first_party_or_unknown", None


def load_previous_confirmed(
    target: str,
    output_root: Path,
    current_run_dir: Path,
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    records: dict[str, dict[str, Any]] = {}
    hosts: set[str] = set()
    if not output_root.exists():
        return records, hosts
    for run_dir in sorted(output_root.glob(f"{target}-*")):
        try:
            if run_dir.resolve() == current_run_dir.resolve():
                continue
        except OSError:
            pass
        if not run_dir.is_dir():
            continue
        json_path = run_dir / "validated_dns_hosts.json"
        legacy_json_path = run_dir / "confirmed_subdomains.json"
        txt_path = run_dir / "validated_dns_hosts.txt"
        legacy_txt_path = run_dir / "confirmed_subdomains.txt"
        chosen_json = json_path if json_path.exists() else legacy_json_path
        chosen_txt = txt_path if txt_path.exists() else legacy_txt_path
        if chosen_json.exists():
            try:
                data = json.loads(chosen_json.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                data = {}
            if isinstance(data, dict):
                for host, obj in data.items():
                    normalized = normalize_hostname(host)
                    if is_valid_hostname(normalized) and is_in_scope_host(normalized, target):
                        hosts.add(normalized)
                        item = dict(obj) if isinstance(obj, dict) else {"host": normalized}
                        item.setdefault("host", normalized)
                        item["previous_run_dir"] = str(run_dir)
                        records[normalized] = item
        if chosen_txt.exists():
            for line in read_lines(chosen_txt):
                normalized = normalize_hostname(line)
                if is_valid_hostname(normalized) and is_in_scope_host(normalized, target):
                    hosts.add(normalized)
                    records.setdefault(normalized, {"host": normalized, "previous_run_dir": str(run_dir)})
    return records, hosts
