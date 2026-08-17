#!/usr/bin/env python3
"""Compatibility entry point.

Existing commands that reference smart_subdomain_pipeline_v7_render.py can keep
working. The V8.1 implementation now lives under the smart_recon package.
"""

from smart_recon.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
