from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .engine import normalize_run
from .io_utils import latest_run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize a completed V8.5.1 recon run into a canonical V9 asset inventory.")
    parser.add_argument("--run-dir", help="Exact V8.5.1 run folder to normalize")
    parser.add_argument("--latest-root", default="recon_runs", help="Recon-runs root used with --target to select the latest matching run")
    parser.add_argument("--target", help="Target domain used to select its latest run under --latest-root")
    parser.add_argument("--output-dir", help="Output directory; default: <run-dir>/normalization_v9")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite an existing non-empty V9 output directory")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
    output_dir = Path(args.output_dir) if args.output_dir else run_dir / "normalization_v9"
    try:
        result = normalize_run(run_dir, output_dir, overwrite=args.overwrite)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"[ERROR] {exc}")
        return 2
    counts = result.summary["counts"]
    print("[COMPLETE] V9 asset normalization finished")
    print(f"Run: {run_dir.resolve()}")
    print(f"Output: {result.output_dir}")
    print(f"Assets: {counts['assets']}")
    print(f"Services: {counts['services']}")
    print(f"Endpoints: {counts['endpoints']}")
    print(f"Conflicts: {counts['conflicts']}")
    print(f"Revalidation items: {counts['revalidation_items']}")
    return 0
