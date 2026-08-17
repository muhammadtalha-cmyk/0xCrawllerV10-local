"""Command-line interface."""

from __future__ import annotations

import argparse
from typing import Sequence

from .config import (
    DEFAULT_DNSX_CHUNK_SIZE,
    DEFAULT_DNSX_RATE_LIMIT,
    DEFAULT_DNSX_RETRIES,
    DEFAULT_DNSX_THREADS,
    DEFAULT_DNSX_WORKERS,
    DEFAULT_KATANA_CONCURRENCY,
    DEFAULT_KATANA_DURATION,
    DEFAULT_KATANA_RATE_LIMIT,
    DEFAULT_MAX_WILDCARD_ZONES,
    DEFAULT_WILDCARD_PROBES,
    DEFAULT_WAF_LIMIT,
    DEFAULT_WAF_REQUEST_TIMEOUT,
    DEFAULT_WAF_STAGE_TIMEOUT,
    DEFAULT_PORT_SCAN_LIMIT,
    DEFAULT_NAABU_TOP_PORTS,
    DEFAULT_NAABU_RATE,
    DEFAULT_NAABU_THREADS,
    DEFAULT_NAABU_RETRIES,
    DEFAULT_NAABU_SOCKET_TIMEOUT_MS,
    DEFAULT_PORT_SCAN_STAGE_TIMEOUT,
    DEFAULT_NMAP_WORKERS,
    DEFAULT_NMAP_HOST_TIMEOUT,
    DEFAULT_SHODAN_MAX_QUERY_CREDITS,
    DEFAULT_SHODAN_DOMAIN_PAGES,
    DEFAULT_SHODAN_MAX_DORKS,
    DEFAULT_SHODAN_PAGES_PER_QUERY,
    DEFAULT_SHODAN_RESULTS_PER_QUERY,
    DEFAULT_SHODAN_MAX_HOST_LOOKUPS,
    DEFAULT_SHODAN_TIMEOUT,
    DEFAULT_SHODAN_API_RPS,
    DEFAULT_SHODAN_CACHE_TTL_HOURS,
    DEFAULT_RECURSIVE_DEPTH,
    DEFAULT_RECURSIVE_WORKERS,
    DEFAULT_RECURSIVE_MAX_HOSTS,
    DEFAULT_RECURSIVE_KATANA_DEPTH,
    DEFAULT_RECURSIVE_KATANA_DURATION,
    DEFAULT_RECURSIVE_KATANA_CONCURRENCY,
    DEFAULT_RECURSIVE_KATANA_RATE_LIMIT,
    DEFAULT_RECURSIVE_STAGE_TIMEOUT,
)
from .pipeline import run_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Smart Docker-based reconnaissance pipeline v8.5.1 with recursive recon, passive Shodan, edge/CDN/WAF, and reconciled port validation"
    )
    parser.add_argument("--target", required=True, help="Root domain, e.g. hiapp.pk")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Required. Confirms you are allowed to test this domain.",
    )
    parser.add_argument("--output-root", default="recon_runs", help="Output root directory")
    parser.add_argument("--wordlist", help="Optional extra wordlist file, one word per line")
    parser.add_argument("--max", action="store_true", help="Deep but bounded discovery mode")
    parser.add_argument(
        "--exhaustive",
        action="store_true",
        help="Enable low-confidence pair permutations. This can create a very large DNS workload.",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        help="Override the candidate cap. Exact discoveries and priority candidates are never dropped.",
    )
    parser.add_argument(
        "--workers",
        default="auto",
        help="Parallel independent-tool workers. auto is safely capped; max/all forces CPU count.",
    )
    parser.add_argument("--timeout", type=int, default=1800, help="Timeout per ordinary Docker tool, seconds")
    parser.add_argument("--no-pull", action="store_true", help="Do not auto-pull missing Docker images")
    parser.add_argument("--no-carry-forward", action="store_true", help="Do not retain previous validated hosts")
    parser.add_argument("--skip-bbot", action="store_true", help="Skip BBOT")
    parser.add_argument("--skip-amass", action="store_true", help="Skip OWASP Amass")
    parser.add_argument(
        "--amass-active",
        action="store_true",
        help="Use Amass active/brute mode. Otherwise Amass stays passive; --exhaustive also enables active mode.",
    )
    parser.add_argument("--skip-gobuster", action="store_true", help="Skip Gobuster DNS")
    parser.add_argument("--skip-subfinder", action="store_true", help="Skip Subfinder")
    parser.add_argument("--skip-katana", action="store_true", help="Skip Katana endpoint crawling")

    parser.add_argument("--dnsx-workers", type=int, default=DEFAULT_DNSX_WORKERS)
    parser.add_argument("--dnsx-chunk-size", type=int, default=DEFAULT_DNSX_CHUNK_SIZE)
    parser.add_argument("--dnsx-threads", type=int, default=DEFAULT_DNSX_THREADS)
    parser.add_argument("--dnsx-rate-limit", type=int, default=DEFAULT_DNSX_RATE_LIMIT)
    parser.add_argument("--dnsx-retries", type=int, default=DEFAULT_DNSX_RETRIES)
    parser.add_argument(
        "--dnsx-chunk-timeout",
        type=int,
        default=1800,
        help="Timeout for each DNSX chunk, seconds.",
    )
    parser.add_argument(
        "--dnsx-retry-failed-chunks",
        type=int,
        default=1,
        help="Pipeline-level retries for failed DNSX chunks.",
    )

    parser.add_argument("--wildcard-probes", type=int, default=DEFAULT_WILDCARD_PROBES)
    parser.add_argument("--max-wildcard-zones", type=int, default=DEFAULT_MAX_WILDCARD_ZONES)

    parser.add_argument("--katana-depth", type=int, help="Override Katana depth")
    parser.add_argument("--katana-concurrency", type=int, default=DEFAULT_KATANA_CONCURRENCY)
    parser.add_argument("--katana-rate-limit", type=int, default=DEFAULT_KATANA_RATE_LIMIT)
    parser.add_argument("--katana-duration", default=DEFAULT_KATANA_DURATION)

    parser.add_argument(
        "--recursive-recon",
        action="store_true",
        help="Recursively crawl and revalidate newly discovered in-scope web hosts. Automatically enabled by --max/--exhaustive.",
    )
    parser.add_argument(
        "--recursive-depth",
        type=int,
        choices=[1, 2, 3],
        default=DEFAULT_RECURSIVE_DEPTH,
        help="Maximum descendant levels below the canonical root; hard-capped at 3.",
    )
    parser.add_argument("--recursive-workers", type=int, default=DEFAULT_RECURSIVE_WORKERS, help="Parallel Katana workers per recursive level")
    parser.add_argument("--recursive-max-hosts", type=int, default=DEFAULT_RECURSIVE_MAX_HOSTS, help="Maximum total hosts crawled recursively")
    parser.add_argument("--recursive-katana-depth", type=int, default=DEFAULT_RECURSIVE_KATANA_DEPTH)
    parser.add_argument("--recursive-katana-duration", default=DEFAULT_RECURSIVE_KATANA_DURATION)
    parser.add_argument("--recursive-katana-concurrency", type=int, default=DEFAULT_RECURSIVE_KATANA_CONCURRENCY)
    parser.add_argument("--recursive-katana-rate-limit", type=int, default=DEFAULT_RECURSIVE_KATANA_RATE_LIMIT)
    parser.add_argument("--recursive-stage-timeout", type=int, default=DEFAULT_RECURSIVE_STAGE_TIMEOUT)

    parser.add_argument(
        "--shodan-passive",
        action="store_true",
        help="Enable passive Shodan DNS, scoped dork, search, and host enrichment. Never submits Shodan scans.",
    )
    parser.add_argument("--env-file", default=".env", help="Environment file containing SHODAN_API_KEY")
    parser.add_argument("--shodan-dorks-file", default="shodan_dorks.json", help="JSON file of scoped Shodan dork templates")
    parser.add_argument("--shodan-max-query-credits", type=int, default=DEFAULT_SHODAN_MAX_QUERY_CREDITS)
    parser.add_argument("--shodan-domain-pages", type=int, default=DEFAULT_SHODAN_DOMAIN_PAGES)
    parser.add_argument("--shodan-max-dorks", type=int, default=DEFAULT_SHODAN_MAX_DORKS)
    parser.add_argument("--shodan-pages-per-query", type=int, default=DEFAULT_SHODAN_PAGES_PER_QUERY)
    parser.add_argument("--shodan-results-per-query", type=int, default=DEFAULT_SHODAN_RESULTS_PER_QUERY)
    parser.add_argument("--shodan-max-host-lookups", type=int, default=DEFAULT_SHODAN_MAX_HOST_LOOKUPS)
    parser.add_argument("--shodan-timeout", type=int, default=DEFAULT_SHODAN_TIMEOUT)
    parser.add_argument("--shodan-api-rps", type=float, default=DEFAULT_SHODAN_API_RPS)
    parser.add_argument("--shodan-cache-ttl-hours", type=int, default=DEFAULT_SHODAN_CACHE_TTL_HOURS)
    parser.add_argument("--shodan-history", action="store_true", help="Request historical Shodan DNS/host data when the plan permits")
    parser.add_argument("--shodan-count-only", action="store_true", help="Run free dork counts without downloading search results")
    parser.add_argument("--shodan-skip-search", action="store_true", help="Use Shodan domain/host lookups but skip dork result searches")
    parser.add_argument("--shodan-include-disabled-dorks", action="store_true", help="Enable advanced plan-dependent dorks from the dorks file")
    parser.add_argument("--shodan-include-edge-ips", action="store_true", help="Enrich CDN/WAF and third-party IPs; disabled by default to avoid shared-edge noise")
    parser.add_argument("--shodan-org", help="Explicit authorized organization name for org-scoped dorks")
    parser.add_argument("--shodan-asn", help="Explicit authorized ASN for ASN-scoped dorks, for example AS12345")
    parser.add_argument("--shodan-net", help="Explicit authorized CIDR for net-scoped dorks, for example 203.0.113.0/24")

    parser.add_argument(
        "--active-waf", "--wafw00f",
        action="store_true",
        help=(
            "Enable WAFW00F active WAF fingerprinting after passive HTTPX/Wappalyzer/CDN detection. "
            "This sends payload-like requests and must only be used with explicit authorization."
        ),
    )
    parser.add_argument("--waf-limit", type=int, default=DEFAULT_WAF_LIMIT, help="Maximum live first-party hosts for WAFW00F")
    parser.add_argument(
        "--waf-request-timeout",
        type=int,
        default=DEFAULT_WAF_REQUEST_TIMEOUT,
        help="Per-request timeout passed to WAFW00F, seconds",
    )
    parser.add_argument(
        "--waf-stage-timeout",
        type=int,
        default=DEFAULT_WAF_STAGE_TIMEOUT,
        help="Maximum runtime for the WAFW00F stage, seconds",
    )
    parser.add_argument("--waf-find-all", action="store_true", help="Ask WAFW00F to report every matching WAF signature")
    parser.add_argument(
        "--waf-include-third-party",
        action="store_true",
        help="Include third-party SaaS hosts in WAFW00F targets. Requires explicit authorization for those providers.",
    )

    parser.add_argument(
        "--port-scan", "--naabu",
        action="store_true",
        help=(
            "Enable bounded active TCP port enumeration with Naabu CONNECT scans. "
            "CDN/WAF edges and third-party SaaS hosts are excluded by default."
        ),
    )
    parser.add_argument("--port-scan-limit", type=int, default=DEFAULT_PORT_SCAN_LIMIT)
    parser.add_argument(
        "--naabu-top-ports",
        choices=["100", "1000"],
        default=DEFAULT_NAABU_TOP_PORTS,
        help="Naabu built-in top-port profile when --naabu-ports is not supplied.",
    )
    parser.add_argument(
        "--naabu-ports",
        help="Optional explicit TCP ports/ranges, for example 22,80,443,8000-8100.",
    )
    parser.add_argument("--naabu-rate", type=int, default=DEFAULT_NAABU_RATE)
    parser.add_argument("--naabu-threads", type=int, default=DEFAULT_NAABU_THREADS)
    parser.add_argument("--naabu-retries", type=int, default=DEFAULT_NAABU_RETRIES)
    parser.add_argument("--naabu-socket-timeout", type=int, default=DEFAULT_NAABU_SOCKET_TIMEOUT_MS, help="Naabu socket timeout in milliseconds")
    parser.add_argument("--naabu-scan-all-ips", action="store_true", help="Scan every IPv4 address resolved for each selected hostname")
    parser.add_argument("--port-scan-timeout", type=int, default=DEFAULT_PORT_SCAN_STAGE_TIMEOUT, help="Maximum Naabu stage runtime in seconds")
    parser.add_argument(
        "--port-scan-include-cdn",
        action="store_true",
        help="Include detected CDN/WAF hosts; Naabu still applies -exclude-cdn and limits recognized edges to 80/443.",
    )
    parser.add_argument(
        "--port-scan-include-third-party",
        action="store_true",
        help="Include third-party SaaS hosts. Use only when those providers/services are explicitly authorized.",
    )
    parser.add_argument(
        "--nmap-service-scan", "--nmap",
        action="store_true",
        help="After Naabu, independently recheck valid Naabu-reported TCP candidates with light Nmap service/version probes.",
    )
    parser.add_argument("--nmap-workers", type=int, default=DEFAULT_NMAP_WORKERS)
    parser.add_argument("--nmap-host-timeout", default=DEFAULT_NMAP_HOST_TIMEOUT)

    parser.add_argument("--no-screenshots", action="store_true", help="Skip httpx screenshot capture")
    parser.add_argument("--screenshot-limit", type=int, default=30, help="Maximum live URLs to screenshot")
    parser.add_argument("--screenshot-timeout", type=int, default=1800, help="Screenshot-stage timeout, seconds")
    parser.add_argument(
        "--fail-on-partial",
        action="store_true",
        help="Return exit code 3 when a required stage is partial or failed.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run_pipeline(args)
