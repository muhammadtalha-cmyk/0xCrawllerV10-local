#!/usr/bin/env python3
"""Compatibility entry point; V9.1 users are routed to the V9.2 engine."""
from technology_enrichment.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
