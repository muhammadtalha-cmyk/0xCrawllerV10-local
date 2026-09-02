"""Configuration for 0xCrawller CVE Detection Module."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CveConfig:
    run_dir: Optional[Path] = None
    target: Optional[str] = None
    latest_root: Path = field(default_factory=lambda: Path("recon_runs"))
    tech_dir: Optional[Path] = None
    output_dir: Optional[Path] = None
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    request_timeout: float = 20.0
    rate_limit_delay: float = 6.0
    results_per_product: int = 10
    overwrite: bool = False
    offline: bool = False

    def resolve_paths(self) -> None:
        if self.run_dir is not None:
            self.run_dir = Path(self.run_dir).expanduser().resolve()
            if self.tech_dir is None:
                self.tech_dir = self.run_dir / "technology_enrichment_v9_2"
            if self.output_dir is None:
                self.output_dir = self.run_dir / "cve_detection"
        if self.api_key:
            # Faster rate limit allowed when official API key is supplied
            self.rate_limit_delay = 1.5
