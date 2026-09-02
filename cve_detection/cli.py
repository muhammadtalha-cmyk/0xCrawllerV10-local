"""Command line interface for 0xCrawller CVE Detection Module."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import CveConfig
from .engine import detect_cves


def find_latest_run(target: str, root_dir: Path) -> Path:
    root = root_dir.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Recon root does not exist: {root}")

    prefix = f"{target.lower()}-"
    candidates = [
        path for path in root.iterdir()
        if path.is_dir() and path.name.lower().startswith(prefix)
    ]
    if not candidates:
        raise FileNotFoundError(f"No run folder matching {prefix}* was found in {root}")

    return max(candidates, key=lambda p: p.stat().st_mtime)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve_detection",
        description="Run isolated CVE Detection & Vulnerability Intelligence matching software versions against NVD database.",
    )
    parser.add_argument("--run-dir", help="Exact completed recon run directory")
    parser.add_argument("--target", help="Target domain used to select its latest run directory")
    parser.add_argument("--latest-root", default="recon_runs", help="Recon-runs root used with --target (default: recon_runs)")
    parser.add_argument("--tech-dir", help="Explicit technology enrichment directory; default: <run>/technology_enrichment_v9_2")
    parser.add_argument("--output-dir", help="Output directory; default: <run>/cve_detection")
    parser.add_argument("--api-key", help="Optional NVD REST API key (increases rate limit)")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing CVE findings")
    parser.add_argument("--offline", action="store_true", help="Run in offline mode using curated vulnerability catalog")
    parser.add_argument("--timeout", type=float, default=20.0, help="NVD HTTP request timeout in seconds (default: 20.0)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    run_dir: Optional[Path] = None
    if args.run_dir:
        run_dir = Path(args.run_dir).expanduser().resolve()
        if not run_dir.is_dir():
            print(f"[ERROR] Run directory not found: {run_dir}", file=sys.stderr)
            return 1
    elif args.target:
        try:
            run_dir = find_latest_run(args.target, Path(args.latest_root))
        except Exception as exc:
            print(f"[ERROR] Unable to resolve latest run for target '{args.target}': {exc}", file=sys.stderr)
            return 1
    else:
        print("[ERROR] Either --run-dir or --target must be supplied.", file=sys.stderr)
        parser.print_help()
        return 1

    config = CveConfig(
        run_dir=run_dir,
        target=args.target,
        latest_root=Path(args.latest_root),
        tech_dir=Path(args.tech_dir).expanduser().resolve() if args.tech_dir else None,
        output_dir=Path(args.output_dir).expanduser().resolve() if args.output_dir else None,
        api_key=args.api_key,
        overwrite=args.overwrite,
        offline=args.offline,
        request_timeout=args.timeout,
    )

    try:
        detect_cves(config)
        return 0
    except Exception as exc:
        print(f"[FAILED] CVE detection encountered an error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
