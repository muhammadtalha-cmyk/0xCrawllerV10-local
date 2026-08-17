from __future__ import annotations

import hashlib
import re
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookies import SimpleCookie
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


VERSION_TOKEN = r"([0-9]+(?:\.[0-9A-Za-z_-]+){0,5})"
SERVER_PATTERNS = [
    ("Nginx", "Web Server", re.compile(rf"\bnginx/?{VERSION_TOKEN}?", re.I)),
    ("Apache HTTP Server", "Web Server", re.compile(rf"\bApache/?{VERSION_TOKEN}?", re.I)),
    ("Microsoft IIS", "Web Server", re.compile(rf"\bMicrosoft-IIS/?{VERSION_TOKEN}?", re.I)),
    ("OpenResty", "Web Server", re.compile(rf"\bopenresty/?{VERSION_TOKEN}?", re.I)),
    ("Caddy", "Web Server", re.compile(rf"\bCaddy/?{VERSION_TOKEN}?", re.I)),
    ("LiteSpeed", "Web Server", re.compile(rf"\b(?:LiteSpeed|OpenLiteSpeed)/?{VERSION_TOKEN}?", re.I)),
    ("Gunicorn", "Application Server", re.compile(rf"\bgunicorn/?{VERSION_TOKEN}?", re.I)),
    ("Uvicorn", "Application Server", re.compile(rf"\buvicorn/?{VERSION_TOKEN}?", re.I)),
    ("Werkzeug", "Application Server", re.compile(rf"\bWerkzeug/?{VERSION_TOKEN}?", re.I)),
    ("Jetty", "Application Server", re.compile(rf"\bJetty\(?/?{VERSION_TOKEN}?", re.I)),
    ("Apache Tomcat", "Application Server", re.compile(rf"\bApache-Coyote/?{VERSION_TOKEN}?", re.I)),
]

SCRIPT_PATTERNS = [
    ("jQuery", "JavaScript Library", re.compile(r"jquery(?:-|\.min\.|\.)([0-9]+(?:\.[0-9]+){1,3})", re.I)),
    ("Bootstrap", "UI Framework", re.compile(r"bootstrap(?:-|\.bundle(?:\.min)?\.|\.min\.|\.)([0-9]+(?:\.[0-9]+){1,3})", re.I)),
    ("Lodash", "JavaScript Library", re.compile(r"lodash(?:\.min)?[-.]([0-9]+(?:\.[0-9]+){1,3})", re.I)),
    ("Moment.js", "JavaScript Library", re.compile(r"moment(?:\.min)?[-.]([0-9]+(?:\.[0-9]+){1,3})", re.I)),
    ("AngularJS", "Web Framework", re.compile(r"angular(?:\.min)?[-.]([0-9]+(?:\.[0-9]+){1,3})", re.I)),
    ("Vue.js", "Web Framework", re.compile(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?[-.]([0-9]+(?:\.[0-9]+){1,3})", re.I)),
    ("React", "Web Framework", re.compile(r"react(?:-dom)?(?:\.production\.min)?[-.]([0-9]+(?:\.[0-9]+){1,3})", re.I)),
]

REFERENCE_PATTERNS = [
    ("MySQL", "Database", re.compile(r"\b(?:MySQL|mysqli|SQLSTATE\[HY000\]).{0,80}", re.I)),
    ("PostgreSQL", "Database", re.compile(r"\b(?:PostgreSQL|psycopg2|PG::|SQLSTATE\[42P)\w*", re.I)),
    ("Microsoft SQL Server", "Database", re.compile(r"\b(?:SQL Server|SqlException|ODBC Driver \d+ for SQL Server)\b", re.I)),
    ("Oracle Database", "Database", re.compile(r"\b(?:ORA-\d{5}|Oracle Database)\b", re.I)),
    ("MongoDB", "Database", re.compile(r"\b(?:MongoDB|MongoServerError|MongooseError)\b", re.I)),
    ("Redis", "Database / Cache", re.compile(r"\b(?:Redis|WRONGTYPE Operation against a key|NOAUTH Authentication required)\b", re.I)),
    ("Elasticsearch", "Search / Database", re.compile(r"\b(?:Elasticsearch|You Know, for Search)\b", re.I)),
    ("RabbitMQ", "Message Queue", re.compile(r"\b(?:RabbitMQ|AMQP 0-9-1)\b", re.I)),
    ("Apache Kafka", "Message Queue", re.compile(r"\b(?:Apache Kafka|KafkaJS|org\.apache\.kafka)\b", re.I)),
    ("Celery", "Task Queue", re.compile(r"\bCelery\b", re.I)),
    ("Sidekiq", "Task Queue", re.compile(r"\bSidekiq\b", re.I)),
]


def _evidence(name: str, category: str, *, version: str | None, evidence_type: str, value: str, confidence: float, scope: str = "web_application") -> dict[str, Any]:
    return {
        "name": name,
        "category": category,
        "version": version,
        "scope": scope,
        "source": "custom_http_evidence",
        "confidence_score": confidence,
        "evidence_type": evidence_type,
        "value": value[:500],
    }


def _parse_cookies(headers: dict[str, list[str]]) -> set[str]:
    names: set[str] = set()
    for raw in headers.get("set-cookie", []):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
            names.update(cookie.keys())
        except Exception:
            first = raw.split(";", 1)[0].split("=", 1)[0].strip()
            if first:
                names.add(first)
    return names


def extract_http_technologies(record: dict[str, Any]) -> list[dict[str, Any]]:
    headers = record.get("headers") or {}
    header_flat = "\n".join(f"{key}: {value}" for key, values in headers.items() for value in values)
    body = str(record.get("body_text") or "")
    combined = header_flat + "\n" + body
    result: list[dict[str, Any]] = []

    server_values = headers.get("server", [])
    for server in server_values:
        for name, category, pattern in SERVER_PATTERNS:
            match = pattern.search(server)
            if match:
                version = match.group(1) if match.lastindex else None
                result.append(_evidence(name, category, version=version, evidence_type="response_header", value=f"Server: {server}", confidence=0.96 if version else 0.90))

    powered = " ".join(headers.get("x-powered-by", []))
    for name, category, pattern in [
        ("PHP", "Programming Language", re.compile(rf"PHP/?{VERSION_TOKEN}?", re.I)),
        ("ASP.NET", "Web Framework", re.compile(rf"ASP\.NET/?{VERSION_TOKEN}?", re.I)),
        ("Express", "Web Framework", re.compile(r"\bExpress\b", re.I)),
        ("Next.js", "Web Framework", re.compile(rf"\bNext\.js/?{VERSION_TOKEN}?", re.I)),
        ("Phusion Passenger", "Application Server", re.compile(rf"Phusion Passenger(?:/|\s){VERSION_TOKEN}?", re.I)),
    ]:
        match = pattern.search(powered)
        if match:
            version = match.group(1) if match.lastindex else None
            result.append(_evidence(name, category, version=version, evidence_type="response_header", value=f"X-Powered-By: {powered}", confidence=0.96 if version else 0.88))

    explicit_headers = [
        ("x-aspnet-version", "ASP.NET", "Web Framework"),
        ("x-aspnetmvc-version", "ASP.NET MVC", "Web Framework"),
        ("x-drupal-cache", "Drupal", "CMS"),
    ]
    for header, name, category in explicit_headers:
        for value in headers.get(header, []):
            version_match = re.search(VERSION_TOKEN, value)
            result.append(_evidence(name, category, version=version_match.group(1) if version_match else None, evidence_type="response_header", value=f"{header}: {value}", confidence=0.94 if version_match else 0.78))

    for value in headers.get("x-elastic-product", []):
        if "elasticsearch" in value.lower():
            result.append(_evidence("Elasticsearch", "Search / Database", version=None, evidence_type="response_header", value=f"X-Elastic-Product: {value}", confidence=0.98, scope="network_service_or_web_api"))

    generators = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, flags=re.I)
    generators += re.findall(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', body, flags=re.I)
    for generator in generators:
        match = re.match(r"\s*(WordPress|Drupal|Joomla!?|Ghost|TYPO3|Hugo|Gatsby)(?:\s+|/)?([0-9][\w.\-]*)?", generator, re.I)
        if match:
            name = match.group(1).replace("!", "")
            result.append(_evidence(name, "CMS / Site Generator", version=match.group(2), evidence_type="meta_generator", value=generator, confidence=0.96 if match.group(2) else 0.90))

    cookies = _parse_cookies(headers)
    cookie_rules = [
        ({"csrftoken", "sessionid"}, "Django", "Web Framework", 0.86),
        ({"laravel_session"}, "Laravel", "Web Framework", 0.90),
        ({"_rails_session"}, "Ruby on Rails", "Web Framework", 0.90),
        ({"connect.sid"}, "Express", "Web Framework", 0.82),
        ({"JSESSIONID"}, "Java Servlet", "Web Runtime", 0.82),
        ({"ASP.NET_SessionId"}, "ASP.NET", "Web Framework", 0.90),
        ({"PHPSESSID"}, "PHP", "Programming Language", 0.84),
    ]
    for required, name, category, confidence in cookie_rules:
        if required.issubset(cookies) or (len(required) == 1 and required & cookies):
            result.append(_evidence(name, category, version=None, evidence_type="cookie_name", value=", ".join(sorted(required & cookies or required)), confidence=confidence))

    body_rules = [
        ("Django", "Web Framework", re.compile(r"(?:csrfmiddlewaretoken|django-admin-form|Log in \| Django site admin|/static/admin/css/base\.css)", re.I), 0.88),
        ("Flask", "Web Framework", re.compile(r"(?:werkzeug\.debug|flask\.app|The debugger caught an exception in your WSGI application)", re.I), 0.88),
        ("Laravel", "Web Framework", re.compile(r"(?:laravel_session|Illuminate\\|Whoops, looks like something went wrong)", re.I), 0.86),
        ("Ruby on Rails", "Web Framework", re.compile(r"(?:ActionController::|ActiveRecord::|Ruby on Rails)", re.I), 0.88),
        ("WordPress", "CMS", re.compile(r"(?:/wp-content/|/wp-includes/|wp-json)", re.I), 0.90),
        ("Next.js", "Web Framework", re.compile(r"(?:/_next/static/|__NEXT_DATA__)", re.I), 0.92),
        ("Nuxt.js", "Web Framework", re.compile(r"(?:/_nuxt/|__NUXT__)", re.I), 0.90),
        ("SvelteKit", "Web Framework", re.compile(r"(?:__sveltekit|/_app/immutable/)", re.I), 0.90),
    ]
    for name, category, pattern, confidence in body_rules:
        match = pattern.search(body)
        if match:
            result.append(_evidence(name, category, version=None, evidence_type="html_signature", value=match.group(0), confidence=confidence))

    for name, category, pattern in SCRIPT_PATTERNS:
        for match in pattern.finditer(combined):
            result.append(_evidence(name, category, version=match.group(1), evidence_type="asset_url", value=match.group(0), confidence=0.90))

    for name, category, pattern in REFERENCE_PATTERNS:
        match = pattern.search(combined)
        if match:
            result.append(_evidence(name, category, version=None, evidence_type="application_reference", value=match.group(0), confidence=0.58, scope="application_reference_not_service_confirmation"))

    # Explicit generic product/version phrases in error/debug pages.
    explicit = re.finditer(r"\b(Django|Flask|Werkzeug|Laravel|Symfony|Spring Boot|Ruby on Rails|Node\.js|Express|RabbitMQ|Elasticsearch|Redis|MongoDB|PostgreSQL|MySQL)\s*(?:version|v|/)?\s*([0-9]+(?:\.[0-9A-Za-z_-]+){1,5})\b", combined, re.I)
    for match in explicit:
        result.append(_evidence(match.group(1), "Explicit Product Evidence", version=match.group(2), evidence_type="explicit_version_string", value=match.group(0), confidence=0.94))

    dedup: dict[tuple[str, str | None, str, str], dict[str, Any]] = {}
    for item in result:
        key = (item["name"].lower(), item.get("version"), item["evidence_type"], item["value"])
        dedup[key] = item
    return list(dedup.values())


def fetch_http_target(target: dict[str, Any], *, timeout: float, max_bytes: int, user_agent: str) -> dict[str, Any]:
    url = target["url"]
    started = time.monotonic()
    request = Request(url, headers={"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5"})
    context = ssl.create_default_context()
    try:
        response = urlopen(request, timeout=timeout, context=context)
        status = getattr(response, "status", 200)
        raw = response.read(max_bytes + 1)
        truncated = len(raw) > max_bytes
        raw = raw[:max_bytes]
        header_pairs = response.headers.items()
        final_url = response.geturl()
        error = None
    except HTTPError as exc:
        status = exc.code
        raw = exc.read(max_bytes + 1)[:max_bytes]
        truncated = len(raw) > max_bytes
        header_pairs = exc.headers.items() if exc.headers else []
        final_url = exc.geturl()
        error = f"HTTP {exc.code}"
    except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        return {**target, "ok": False, "error": str(exc), "seconds": round(time.monotonic() - started, 3), "technologies": []}

    headers: dict[str, list[str]] = {}
    for key, value in header_pairs:
        headers.setdefault(str(key).lower(), []).append(str(value))
    content_type = " ".join(headers.get("content-type", []))
    charset_match = re.search(r"charset=([\w\-]+)", content_type, re.I)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        body_text = raw.decode(charset, errors="replace")
    except LookupError:
        body_text = raw.decode("utf-8", errors="replace")
    record = {
        **target,
        "ok": True,
        "status_code": status,
        "final_url": final_url,
        "headers": headers,
        "content_type": content_type,
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "body_bytes": len(raw),
        "body_truncated": truncated,
        "body_text": body_text,
        "error": error,
        "seconds": round(time.monotonic() - started, 3),
    }
    record["technologies"] = extract_http_technologies(record)
    return record


def run_http_evidence(targets: list[dict[str, Any]], *, workers: int, timeout: float, max_bytes: int, user_agent: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(fetch_http_target, target, timeout=timeout, max_bytes=max_bytes, user_agent=user_agent) for target in targets]
        for future in as_completed(futures):
            records.append(future.result())
    records.sort(key=lambda x: x.get("host", ""))
    # Do not retain full bodies in machine output; only fingerprints and bounded metadata.
    public_records: list[dict[str, Any]] = []
    for record in records:
        cleaned = dict(record)
        cleaned.pop("body_text", None)
        public_records.append(cleaned)
    return {
        "status": "COMPLETE" if all(r.get("ok") for r in records) else "PARTIAL",
        "targets": len(targets),
        "successful": sum(bool(r.get("ok")) for r in records),
        "records": public_records,
    }
