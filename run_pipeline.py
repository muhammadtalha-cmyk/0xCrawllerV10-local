#!/usr/bin/env python3
"""
0xCrawllerV10 - Cross-platform pipeline runner (macOS / Linux / Windows)

Replaces the 4 Windows .cmd launchers with a single Python script.
Runs the same 4 stages, in the same order, with the same flags:

  1. run-max-v8.5.1-recursive.cmd  -> smart_subdomain_pipeline_v8_modular.py
  2. run-v9-normalize.cmd          -> vapt_asset_normalizer_v9.py
  3. run-v9.2-tech-max.cmd         -> vapt_technology_enricher_v9_2.py
  4. run-v10-combined-report.cmd   -> vapt_combined_report_v10.py

Usage:
    python3 run_pipeline.py hiapp.pk
    python3 run_pipeline.py hiapp.pk --skip-shodan
    python3 run_pipeline.py hiapp.pk --recon-root ./recon_runs

Requirements:
    - Docker Desktop installed and RUNNING (the pipeline shells out to
      `docker run` for subfinder/amass/bbot/dnsx/httpx/katana/gobuster/
      naabu/nmap/wafw00f; Docker will auto-pull any image it doesn't
      already have locally).
    - Python 3.11+ (the pipeline itself uses only the standard library,
      no pip install needed).
    - Run this script from the project root (same folder that contains
      smart_subdomain_pipeline_v8_modular.py, vapt_asset_normalizer_v9.py,
      etc.)
"""

from __future__ import annotations

import argparse
import functools
import shutil
import subprocess
import sys
from pathlib import Path

print = functools.partial(print, flush=True)  # noqa: A001 - stream output live when piped (e.g. by the web orchestrator)

PROJECT_ROOT = Path(__file__).resolve().parent


def check_docker() -> None:
    if shutil.which("docker") is None:
        sys.exit(
            "[ERROR] Docker CLI not found on PATH.\n"
            "        Install Docker Desktop for Mac and make sure it's running."
        )
    result = subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if result.returncode != 0:
        sys.exit(
            "[ERROR] Docker daemon is not running.\n"
            "        Open Docker Desktop and wait for it to fully start, then retry."
        )
    print("[OK] Docker is installed and running.")


def check_required_files() -> None:
    required = [
        "smart_subdomain_pipeline_v8_modular.py",
        "vapt_asset_normalizer_v9.py",
        "vapt_technology_enricher_v9_2.py",
        "vapt_cve_detector.py",
        "vapt_combined_report_v10.py",
    ]
    missing = [name for name in required if not (PROJECT_ROOT / name).is_file()]
    if missing:
        sys.exit(
            "[ERROR] This script must be placed in the project root. Missing: "
            + ", ".join(missing)
        )


def run_stage(label: str, args: list[str], allowed_exit_codes: set[int]) -> None:
    print("\n" + "=" * 70)
    print(f"STAGE: {label}")
    print("=" * 70)
    print(" ".join(args))
    print()
    process = subprocess.run(args, cwd=str(PROJECT_ROOT))
    if process.returncode not in allowed_exit_codes:
        sys.exit(
            f"\n[FAILED] {label} exited with code {process.returncode}. Stopping pipeline."
        )
    if process.returncode == 3:
        print(f"\n[PARTIAL] {label} completed with partial coverage (exit code 3).")
    else:
        print(f"\n[COMPLETE] {label} finished.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the full 0xCrawllerV10 pipeline (macOS/Linux/Windows).")
    parser.add_argument("target", help="Root domain to scan, e.g. hiapp.pk")
    parser.add_argument(
        "--recon-root",
        default="./recon_runs",
        help="Folder where run outputs are stored (default: ./recon_runs)",
    )
    parser.add_argument(
        "--skip-shodan",
        action="store_true",
        help="Skip passive Shodan enrichment (no SHODAN_API_KEY / .env required).",
    )
    parser.add_argument(
        "--run-dir",
        help="Explicit run directory. If set, this replaces --latest-root for stages 2-4 and passes down.",
    )
    parser.add_argument(
        "--stage",
        choices=["recon", "normalization", "technology", "cve", "report"],
        default=None,
        help="Run only one stage instead of the full chain (used by the web orchestrator).",
    )
    args = parser.parse_args()

    check_required_files()
    check_docker()

    py = sys.executable  # use the same python3 interpreter you're running this with
    target = args.target
    recon_root = args.recon_root
    only_stage = args.stage
    explicit_run_dir = getattr(args, "run_dir", None)

    # ---- Stage 1: Recon ----
    recon_args = [
        py, "-u", "smart_subdomain_pipeline_v8_modular.py",
        "--target", target,
    ]
    if explicit_run_dir:
        recon_args.extend(["--run-dir", explicit_run_dir])
        
    recon_args.extend([
        "--authorized",
        "--max",
        "--workers", "auto",
        "--timeout", "1800",
        "--dnsx-workers", "3",
        "--dnsx-chunk-size", "25000",
        "--dnsx-threads", "50",
        "--dnsx-rate-limit", "100",
        "--dnsx-retries", "2",
        "--dnsx-chunk-timeout", "1800",
        "--dnsx-retry-failed-chunks", "1",
        "--wildcard-probes", "3",
        "--max-wildcard-zones", "50",
        "--katana-depth", "5",
        "--katana-concurrency", "10",
        "--katana-rate-limit", "50",
        "--katana-duration", "10m",
        "--recursive-recon",
        "--recursive-depth", "3",
        "--recursive-workers", "4",
        "--recursive-max-hosts", "250",
        "--recursive-katana-depth", "3",
        "--recursive-katana-duration", "2m",
        "--recursive-katana-concurrency", "5",
        "--recursive-katana-rate-limit", "20",
        "--recursive-stage-timeout", "900",
        "--active-waf",
        "--waf-limit", "30",
        "--waf-request-timeout", "7",
        "--waf-stage-timeout", "900",
        "--port-scan",
        "--port-scan-limit", "75",
        "--naabu-top-ports", "1000",
        "--naabu-rate", "100",
        "--naabu-threads", "25",
        "--naabu-retries", "2",
        "--naabu-socket-timeout", "1500",
        "--port-scan-timeout", "1800",
        "--nmap-service-scan",
        "--nmap-workers", "2",
        "--nmap-host-timeout", "5m",
        "--screenshot-limit", "50",
        "--screenshot-timeout", "1800",
    ])
    if not args.skip_shodan:
        recon_args += [
            "--shodan-passive",
            "--env-file", ".env",
            "--shodan-dorks-file", "shodan_dorks.json",
            "--shodan-max-query-credits", "10",
            "--shodan-domain-pages", "1",
            "--shodan-max-dorks", "12",
            "--shodan-pages-per-query", "1",
            "--shodan-results-per-query", "100",
            "--shodan-max-host-lookups", "100",
            "--shodan-timeout", "20",
            "--shodan-api-rps", "1",
            "--shodan-cache-ttl-hours", "24",
        ]
    if only_stage in (None, "recon"):
        run_stage("1/5 Recon (V8.5.1)", recon_args, allowed_exit_codes={0, 3})
        if only_stage == "recon":
            return

    # ---- Stage 2: Normalization ----
    normalize_args = [
        py, "-u", "vapt_asset_normalizer_v9.py",
        "--target", target,
    ]
    if explicit_run_dir:
        normalize_args.extend(["--run-dir", explicit_run_dir])
    else:
        normalize_args.extend(["--latest-root", recon_root, "--overwrite"])

    if only_stage in (None, "normalization"):
        run_stage("2/5 Asset Normalization (V9)", normalize_args, allowed_exit_codes={0})
        if only_stage == "normalization":
            return

    # ---- Stage 3: Technology intelligence ----
    tech_args = [
        py, "-u", "vapt_technology_enricher_v9_2.py",
        "--target", target,
        "--normalize-if-missing",
        "--authorized",
        "--max",
    ]
    if explicit_run_dir:
        tech_args.extend(["--run-dir", explicit_run_dir])
    else:
        tech_args.extend(["--latest-root", recon_root, "--overwrite"])
    tech_args.extend([
        "--workers", "5",
        "--http-workers", "8",
        "--js-workers", "10",
        "--service-workers", "4",
        "--whatweb-threads", "12",
        "--wappalyzer-next-workers", "3",
        "--wappalyzer-next-balanced-workers", "10",
        "--wappalyzer-next-full-target-cap", "30",
        "--wappalyzer-next-page-timeout", "25",
        "--request-timeout", "10",
        "--lane-timeout", "1800",
    ])
    if only_stage in (None, "technology"):
        run_stage("3/5 Technology Intelligence (V9.2, incl. nuclei)", tech_args, allowed_exit_codes={0})
        if only_stage == "technology":
            return

    # ---- Stage 4: CVE intelligence ----
    cve_args = [
        py, "-u", "vapt_cve_detector.py",
        "--target", target,
    ]
    if explicit_run_dir:
        cve_args.extend(["--run-dir", explicit_run_dir])
    else:
        cve_args.extend(["--latest-root", recon_root, "--overwrite"])

    if only_stage in (None, "cve"):
        run_stage("4/5 CVE Intelligence (V1.0)", cve_args, allowed_exit_codes={0})
        if only_stage == "cve":
            return

    # ---- Stage 5: Combined report ----
    report_args = [
        py, "-u", "vapt_combined_report_v10.py",
        "--target", target,
    ]
    if explicit_run_dir:
        report_args.extend(["--run-dir", explicit_run_dir])
    else:
        report_args.extend(["--latest-root", recon_root, "--overwrite"])

    if only_stage in (None, "report"):
        run_stage("5/5 Combined VAPT Report (V10)", report_args, allowed_exit_codes={0})
        if only_stage == "report":
            return

    print("\n" + "=" * 70)
    print(f"[ALL COMPLETE] Full pipeline finished for {target}.")
    print(f"Open the latest run folder inside {recon_root} and read combined_vapt_intelligence_report.md")
    print("=" * 70)


if __name__ == "__main__":
    main()