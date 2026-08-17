from __future__ import annotations

import argparse
from pathlib import Path

from asset_normalization.io_utils import latest_run

from . import __version__
from .config import EnrichmentConfig
from .engine import enrich_run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run V9.2 parallel technology, framework, database, queue, JavaScript, and service-version enrichment.")
    parser.add_argument("--run-dir", help="Exact completed recon run folder")
    parser.add_argument("--target", help="Target domain used to select its latest run")
    parser.add_argument("--latest-root", default="recon_runs", help="Recon-runs root used with --target")
    parser.add_argument("--normalization-dir", help="Existing V9 normalization directory; default: <run>/normalization_v9")
    parser.add_argument("--output-dir", help="Output directory; default: <run>/technology_enrichment_v9_2")
    parser.add_argument("--authorized", action="store_true", help="Confirm active remote fingerprinting is explicitly authorized")
    parser.add_argument("--offline", action="store_true", help="Reconcile existing V9/Wappalyzer/Nmap evidence without new requests or Docker tools")
    parser.add_argument("--normalize-if-missing", action="store_true", help="Create V9 normalization output when it is missing")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--max", action="store_true", help="Use bounded high-coverage settings: WhatWeb aggression 3 and larger target caps")
    parser.add_argument("--workers", default="auto", help="Parallel independent lanes; max 5")
    parser.add_argument("--http-workers", default="auto")
    parser.add_argument("--js-workers", default="auto")
    parser.add_argument("--service-workers", default="auto")
    parser.add_argument("--whatweb-threads", default="auto")
    parser.add_argument("--wappalyzer-next-workers", default="auto", help="Chromium workers for full dynamic scans; hard cap 3")
    parser.add_argument("--wappalyzer-next-balanced-workers", default="auto", help="Workers for HTTP-based balanced overflow scans")
    parser.add_argument("--wappalyzer-next-full-target-cap", type=int, default=None, help="Maximum browser-backed targets; default 30 in --max, otherwise 12")
    parser.add_argument("--wappalyzer-next-page-timeout", type=int, default=25)
    parser.add_argument("--request-timeout", type=float, default=10.0)
    parser.add_argument("--lane-timeout", type=int, default=900)
    parser.add_argument("--whatweb-image", default=None)
    parser.add_argument("--retirejs-image", default=None)
    parser.add_argument("--zgrab2-image", default=None)
    parser.add_argument("--wappalyzer-next-image", default=None)
    parser.add_argument("--nuclei-image", default=None)
    parser.add_argument("--nuclei-workers", default="auto")
    parser.add_argument("--nuclei-severity", default=None, help="Comma-separated severities, e.g. medium,high,critical")
    parser.add_argument("--nuclei-templates", default=None, help="Custom Nuclei templates directory")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.offline and not args.authorized:
        print("[ERROR] Active enrichment requires --authorized. Use --offline for local evidence reconciliation only.")
        return 2
    if args.run_dir:
        run_dir = Path(args.run_dir)
    elif args.target:
        selected = latest_run(Path(args.latest_root), args.target)
        if selected is None:
            print(f"[ERROR] No run found for {args.target!r} under {args.latest_root}")
            return 2
        run_dir = selected
    else:
        print("[ERROR] Provide --run-dir or --target")
        return 2
    output_dir = Path(args.output_dir) if args.output_dir else run_dir / "technology_enrichment_v9_2"
    normalization_dir = Path(args.normalization_dir) if args.normalization_dir else None
    config = EnrichmentConfig.create(
        max_mode=args.max,
        workers=args.workers,
        http_workers=args.http_workers,
        js_workers=args.js_workers,
        service_workers=args.service_workers,
        whatweb_threads=args.whatweb_threads,
        request_timeout=args.request_timeout,
        lane_timeout=args.lane_timeout,
        whatweb_image=args.whatweb_image,
        retirejs_image=args.retirejs_image,
        zgrab2_image=args.zgrab2_image,
        wappalyzer_next_image=args.wappalyzer_next_image,
        wappalyzer_next_workers=args.wappalyzer_next_workers,
        wappalyzer_next_balanced_workers=args.wappalyzer_next_balanced_workers,
        wappalyzer_next_full_target_cap=args.wappalyzer_next_full_target_cap,
        wappalyzer_next_page_timeout=args.wappalyzer_next_page_timeout,
        nuclei_image=args.nuclei_image,
        nuclei_workers=args.nuclei_workers,
        nuclei_severity=[s.strip() for s in args.nuclei_severity.split(",") if s.strip()] if args.nuclei_severity else None,
        nuclei_templates=args.nuclei_templates,
    )
    try:
        result = enrich_run(
            run_dir, output_dir,
            config=config,
            overwrite=args.overwrite,
            normalize_if_missing=args.normalize_if_missing,
            normalization_dir=normalization_dir,
            offline=args.offline,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"[ERROR] {exc}")
        return 2
    counts = result.summary["counts"]
    print("[COMPLETE] V9.2 technology enrichment finished")
    print(f"Status: {result.summary['status']}")
    print(f"Run: {run_dir.resolve()}")
    print(f"Output: {result.output_dir}")
    print(f"Technologies: {counts['technologies']}")
    print(f"Exact versions: {counts['exact_versions']}")
    print(f"Service fingerprints: {counts['service_fingerprints']}")
    print(f"Revalidation items: {counts['revalidation_items']}")
    print(f"Vulnerability findings: {counts.get('vulnerability_findings', 0)} (high/critical: {counts.get('vulnerability_findings_high_or_critical', 0)})")
    return 0
