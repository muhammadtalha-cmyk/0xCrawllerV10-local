"""Docker command construction for Smart Recon V8.5.1.

Tool flags live here so parsers, reporting, and orchestration remain independent.
"""

from __future__ import annotations

import re
from pathlib import Path

from .config import (
    DEFAULT_KATANA_MAX_RESPONSE_SIZE,
    IMAGES,
    KATANA_EXCLUDED_EXTENSIONS,
)
from .edge_detection import WAFW00F_IMAGE
from .runtime import volume_arg

KATANA_DURATION_RE = re.compile(r"^[1-9]\d*(?:s|m|h|d)$", re.IGNORECASE)


def normalize_katana_config(
    *,
    depth: int,
    crawl_duration: str,
    known_files: str = "all",
) -> dict[str, object]:
    """Return a Katana configuration that is valid for the installed v1.6 CLI."""
    requested_depth = max(1, int(depth))
    duration = str(crawl_duration or "").strip().lower()
    if not KATANA_DURATION_RE.fullmatch(duration):
        raise ValueError("Katana crawl duration must be a positive integer followed by s, m, h, or d (for example, 2m)")
    if known_files not in {"", "all", "robotstxt", "sitemapxml"}:
        raise ValueError("Katana known-files must be one of: all, robotstxt, sitemapxml")

    effective_depth = max(3, requested_depth) if known_files else requested_depth
    notes: list[str] = []
    if effective_depth != requested_depth:
        notes.append(
            f"Katana depth raised from {requested_depth} to {effective_depth} because known-file crawling requires depth 3 or greater."
        )
    return {
        "requested": {
            "depth": requested_depth,
            "crawl_duration": str(crawl_duration),
            "known_files": known_files,
        },
        "effective": {
            "depth": effective_depth,
            "crawl_duration": duration,
            "known_files": known_files,
            "scope": "fqdn",
        },
        "notes": notes,
    }


def _detailed_httpx_flags() -> list[str]:
    return [
        "-silent", "-json", "-status-code", "-title", "-tech-detect", "-follow-redirects",
        "-content-length", "-content-type", "-response-time", "-web-server",
        "-ip", "-cname", "-asn", "-cdn", "-favicon", "-jarm",
        "-hash", "sha256", "-probe", "-include-chain",
    ]


def _root_httpx_flags() -> list[str]:
    """Fast root probe with Wappalyzer and CDN/WAF evidence, without costly unique probes."""
    return [
        "-silent", "-json", "-status-code", "-title", "-tech-detect", "-follow-redirects",
        "-content-length", "-content-type", "-response-time", "-web-server",
        "-ip", "-cname", "-asn", "-cdn", "-probe", "-include-chain",
    ]


def build_commands(target: str, run_dir: Path, max_mode: bool, *, amass_active: bool = False) -> dict[str, list[str]]:
    vol = volume_arg(run_dir)
    gobuster_threads = "40" if max_mode else "25"

    amass_flags = ["enum", "-active", "-brute", "-d", target] if amass_active else ["enum", "-passive", "-d", target]

    return {
        "subfinder": [
            "docker", "run", "--rm", "-v", vol, IMAGES["subfinder"],
            "-d", target, "-all", "-recursive", "-silent",
            "-o", "/output/subfinder_subdomains.txt",
        ],
        "amass": [
            "docker", "run", "--rm", "-v", vol, IMAGES["amass"],
            *amass_flags,
        ],
        "gobuster_base": [
            "docker", "run", "--rm", "-v", vol, IMAGES["gobuster"],
            "dns", "--domain", target, "-w", "/output/base_wordlist.txt",
            "-t", gobuster_threads, "--timeout", "5s",
            "-o", "/output/gobuster_base.txt", "--no-color",
        ],
        "bbot": [
            "docker", "run", "--rm", "-v",
            f"{str((run_dir / 'bbot_home').resolve())}:/root/.bbot",
            IMAGES["bbot"], "-t", target, "-p", "subdomain-enum",
        ],
        "httpx_root_probe": [
            "docker", "run", "--rm", "-v", vol, IMAGES["httpx"],
            "-l", "/output/root_probe_input.txt", *_root_httpx_flags(),
            "-location", "-o", "/output/httpx_root_probe.jsonl",
        ],
        "gobuster_custom": [
            "docker", "run", "--rm", "-v", vol, IMAGES["gobuster"],
            "dns", "--domain", target, "-w", "/output/custom_wordlist.txt",
            "-t", gobuster_threads, "--timeout", "5s",
            "-o", "/output/gobuster_custom.txt", "--no-color",
        ],
        "httpx_probe": [
            "docker", "run", "--rm", "-v", vol, IMAGES["httpx"],
            "-l", "/output/validated_dns_hosts.txt", *_detailed_httpx_flags(),
            "-o", "/output/httpx_probe.jsonl",
        ],
        "httpx_screenshot": [
            "docker", "run", "--rm", "-v", vol, IMAGES["httpx"],
            "-l", "/output/live_urls_for_screenshot.txt", "-silent", "-json",
            "-screenshot", "-exclude-screenshot-bytes", "-exclude-headless-body",
            "-srd", "/output/httpx_screenshots", "-o", "/output/httpx_screenshots.jsonl",
        ],
        "httpx_browser_discovered": [
            "docker", "run", "--rm", "-v", vol, IMAGES["httpx"],
            "-l", "/output/browser_validated_subdomains.txt", *_detailed_httpx_flags(),
            "-o", "/output/httpx_browser_discovered.jsonl",
        ],
    }


def build_katana_command(
    canonical_url: str,
    run_dir: Path,
    *,
    max_mode: bool,
    depth: int,
    concurrency: int,
    rate_limit: int,
    crawl_duration: str,
    output_file: str = "katana_urls.txt",
) -> list[str]:
    vol = volume_arg(run_dir)
    config = normalize_katana_config(
        depth=depth,
        crawl_duration=crawl_duration,
        known_files="all",
    )
    effective = config["effective"]
    return [
        "docker", "run", "--rm", "-v", vol, IMAGES["katana"],
        "-u", canonical_url,
        "-d", str(effective["depth"]),
        "-jc",
        "-kf", str(effective["known_files"]),
        "-fs", "fqdn",
        "-iqp",
        "-ct", str(effective["crawl_duration"]),
        "-c", str(max(1, concurrency)),
        "-rl", str(max(1, rate_limit)),
        "-mrs", str(DEFAULT_KATANA_MAX_RESPONSE_SIZE),
        "-ef", KATANA_EXCLUDED_EXTENSIONS,
        "-silent",
        "-o", f"/output/{output_file}",
    ]


def build_httpx_file_command(
    run_dir: Path,
    *,
    input_file: str,
    output_file: str,
) -> list[str]:
    """Build a detailed HTTPX probe for an arbitrary run-relative input file."""
    vol = volume_arg(run_dir)
    return [
        "docker", "run", "--rm", "-v", vol, IMAGES["httpx"],
        "-l", f"/output/{input_file}", *_detailed_httpx_flags(),
        "-o", f"/output/{output_file}",
    ]


def build_httpx_screenshot_file_command(
    run_dir: Path,
    *,
    input_file: str,
    output_file: str,
    screenshot_dir: str,
) -> list[str]:
    """Build a screenshot/browser-observation HTTPX command for a custom list."""
    vol = volume_arg(run_dir)
    return [
        "docker", "run", "--rm", "-v", vol, IMAGES["httpx"],
        "-l", f"/output/{input_file}", "-silent", "-json",
        "-screenshot", "-exclude-screenshot-bytes", "-exclude-headless-body",
        "-srd", f"/output/{screenshot_dir}", "-o", f"/output/{output_file}",
    ]


def build_dnsx_command(
    run_dir: Path,
    *,
    input_file: str,
    output_file: str,
    threads: int,
    rate_limit: int,
    retries: int,
) -> list[str]:
    vol = volume_arg(run_dir)
    return [
        "docker", "run", "--rm", "-v", vol, IMAGES["dnsx"],
        "-l", f"/output/{input_file}",
        "-a", "-aaaa", "-cname", "-resp",
        "-t", str(max(1, threads)),
        "-rl", str(max(1, rate_limit)),
        "-retry", str(max(1, retries)),
        "-j", "-omit-raw", "-silent",
        "-o", f"/output/{output_file}",
    ]


def build_wafw00f_command(
    run_dir: Path,
    *,
    request_timeout: int,
    find_all: bool = False,
) -> list[str]:
    """Build the optional active WAF fingerprinting command.

    WAFW00F reads a bounded target list and writes structured JSON. The stage is
    intentionally explicit because the tool sends payload-like requests.
    """
    vol = volume_arg(run_dir)
    command = [
        "docker", "run", "--rm", "-v", vol, WAFW00F_IMAGE,
        "-i", "/output/waf_targets.txt",
        "-o", "/output/wafw00f.json",
        "-f", "json",
        "-T", str(max(1, int(request_timeout))),
        "--no-colors",
    ]
    if find_all:
        command.append("-a")
    return command


def build_naabu_command(
    run_dir: Path,
    *,
    top_ports: str,
    ports: str | None,
    rate: int,
    threads: int,
    retries: int,
    socket_timeout_ms: int,
    scan_all_ips: bool = False,
) -> list[str]:
    """Build a bounded Naabu TCP CONNECT command.

    ``-ec`` is always enabled as defense in depth: if a CDN/WAF host slips past
    target selection, Naabu limits it to ports 80 and 443 instead of scanning the
    complete requested port profile.
    """
    from .config import NAABU_IMAGE

    vol = volume_arg(run_dir)
    command = [
        "docker", "run", "--rm", "-v", vol, NAABU_IMAGE,
        "-l", "/output/port_scan_targets.txt",
        "-s", "c",
        "-iv", "4",
        "-c", str(max(1, int(threads))),
        "-rate", str(max(1, int(rate))),
        "-retries", str(max(1, int(retries))),
        "-timeout", str(max(100, int(socket_timeout_ms))),
        "-verify",
        "-ec",
        "-j", "-silent", "-nc",
        "-o", "/output/naabu_ports.jsonl",
    ]
    if ports:
        command.extend(["-p", str(ports)])
    else:
        command.extend(["-tp", str(top_ports)])
    if scan_all_ips:
        command.append("-sa")
    return command


def build_nmap_command(
    run_dir: Path,
    *,
    target: str,
    ports: list[int],
    output_file: str,
    host_timeout: str,
) -> list[str]:
    """Recheck only Naabu-reported TCP candidates with light Nmap service probes."""
    from .config import NMAP_IMAGE

    vol = volume_arg(run_dir)
    normalized_ports = sorted({int(value) for value in ports if 1 <= int(value) <= 65535})
    if not normalized_ports:
        raise ValueError("Nmap requires at least one valid TCP port in range 1-65535")
    port_value = ",".join(str(port) for port in normalized_ports)
    return [
        "docker", "run", "--rm", "-v", vol, NMAP_IMAGE,
        "-sT", "-Pn", "-n",
        "-sV", "--version-light",
        "--reason",
        "-T3", "--max-retries", "2",
        "--host-timeout", str(host_timeout),
        "-p", port_value,
        "-oX", f"/output/{output_file}",
        target,
    ]
