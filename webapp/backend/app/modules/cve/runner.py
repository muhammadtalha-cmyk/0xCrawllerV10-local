from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Awaitable

from ..base import BaseModule

logger = logging.getLogger("crawller.modules.cve")

def get_project_root() -> Path:
    curr = Path(__file__).resolve().parent
    for _ in range(7):
        if (curr / "vapt_cve_detector.py").is_file():
            return curr
        curr = curr.parent
    return Path(os.getenv("CRAWLLER_PROJECT_ROOT", "/home/talha-crawller/0xCrawllerV10-local")).resolve()

PROJECT_ROOT = get_project_root()


class CVEDetectionModule(BaseModule):
    id = "cve"
    name = "CVE Detection"
    description = "Audit detected software frameworks and versions against the National Vulnerability Database (NVD) for known CVEs."
    category = "Vulnerability Assessment"
    icon = "ShieldAlertIcon"

    async def run(
        self,
        job_id: str,
        target: str,
        output_dir: Path,
        update_progress: Callable[[int, str], Awaitable[None]],
    ) -> dict[str, Any]:
        started = time.monotonic()
        clean_target = (
            target.strip().lower()
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .split(":")[0]
            .rstrip(".")
        )

        if not clean_target:
            raise ValueError("Target domain must not be empty.")

        output_dir.mkdir(parents=True, exist_ok=True)
        log_file = output_dir / "execution.log"
        tech_dir = output_dir / "tech"
        tech_dir.mkdir(parents=True, exist_ok=True)

        await update_progress(10, f"Initializing CVE detection for {clean_target}...")

        # Step 1: Check if a full recon run already exists for this target
        recon_runs_dir = PROJECT_ROOT / "recon_runs"
        existing_runs = sorted(recon_runs_dir.glob(f"{clean_target}-*")) if recon_runs_dir.is_dir() else []

        tech_inventory_file = None
        if existing_runs:
            latest_run = existing_runs[-1]
            candidate_tech = latest_run / "technology_enrichment_v9_2"
            if (candidate_tech / "technology_inventory.json").is_file():
                tech_inventory_file = candidate_tech / "technology_inventory.json"
                logger.info(f"Using existing technology inventory from {tech_inventory_file}")

        # If no prior run exists, run a fast WhatWeb discovery to extract versioned technologies
        if not tech_inventory_file:
            await update_progress(20, "Extracting live software versions via WhatWeb...")
            whatweb_out = tech_dir / "whatweb.json"
            target_urls = [f"https://{clean_target}", f"http://{clean_target}"]
            whatweb_cmd = [
                "docker", "run", "--rm",
                "-v", f"{str(tech_dir.resolve())}:/output",
                "0xcrawller/whatweb:0.6.4",
                f"--log-json=/output/whatweb.json",
                "-a", "3",
                "--color=never",
                *target_urls,
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *whatweb_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                await proc.communicate()
            except Exception as e:
                logger.warning(f"WhatWeb execution error: {e}")

            # Normalize permissions
            try:
                subprocess.run(
                    ["docker", "run", "--rm", "-v", f"{str(tech_dir.resolve())}:/output", "alpine", "sh", "-c", "chmod -R a+rX /output 2>/dev/null || true"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                )
            except Exception:
                pass

            # Convert WhatWeb output to technology_inventory.json
            tech_items = []
            if whatweb_out.is_file():
                try:
                    data = json.loads(whatweb_out.read_text(encoding="utf-8", errors="replace"))
                    if isinstance(data, list):
                        for entry in data:
                            plugins = entry.get("plugins", {})
                            for p_name, p_info in plugins.items():
                                if isinstance(p_info, dict) and p_info.get("version"):
                                    v = p_info["version"]
                                    ver = v[0] if isinstance(v, list) else str(v)
                                    tech_items.append({
                                        "name": p_name,
                                        "version": ver,
                                        "host": clean_target,
                                    })
                except Exception:
                    pass

            generated_tech_file = tech_dir / "technology_inventory.json"
            generated_tech_file.write_text(json.dumps(tech_items, indent=2), encoding="utf-8")
            tech_inventory_file = generated_tech_file

        await update_progress(50, "Correlating software components against NVD database...")

        # Step 2: Run vapt_cve_detector.py
        cve_script = PROJECT_ROOT / "vapt_cve_detector.py"
        cve_out_dir = output_dir / "cve_output"
        cve_out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            "-u",
            str(cve_script),
            "--tech-dir",
            str(tech_inventory_file.parent),
            "--output-dir",
            str(cve_out_dir),
            "--timeout",
            "15",
        ]

        logger.info(f"Running CVE detector for job {job_id}: {' '.join(cmd)}")

        with log_file.open("w", encoding="utf-8") as lf:
            lf.write(f"=== CVE Detection Job: {job_id} ===\n")
            lf.write(f"Target: {clean_target}\n\n")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(PROJECT_ROOT),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            lf.write(stdout.decode("utf-8", errors="replace"))

        await update_progress(85, "Parsing vulnerability findings...")

        # Read results
        cve_findings_file = cve_out_dir / "cve_findings.json"
        cve_summary_file = cve_out_dir / "cve_summary.json"

        findings: list[dict[str, Any]] = []
        if cve_findings_file.is_file():
            try:
                findings_data = json.loads(cve_findings_file.read_text(encoding="utf-8", errors="replace"))
                if isinstance(findings_data, list):
                    for item in findings_data:
                        findings.append({
                            "cve_id": item.get("cve_id", ""),
                            "product": item.get("product", ""),
                            "version": item.get("version", ""),
                            "severity": (item.get("severity") or "UNKNOWN").upper(),
                            "cvss_score": item.get("cvss_score"),
                            "description": item.get("description", ""),
                            "source_url": item.get("source_url") or f"https://nvd.nist.gov/vuln/detail/{item.get('cve_id')}",
                            "affected_hosts": item.get("affected_hosts", [clean_target]),
                        })
            except Exception as e:
                logger.warning(f"Error parsing cve findings: {e}")

        summary: dict[str, Any] = {}
        if cve_summary_file.is_file():
            try:
                summary = json.loads(cve_summary_file.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass

        duration = round(time.monotonic() - started, 2)
        await update_progress(100, f"Completed: Cross-referenced components against NVD ({len(findings)} CVEs identified)")

        return {
            "module": self.id,
            "target": clean_target,
            "job_id": job_id,
            "duration_seconds": duration,
            "total_findings": len(findings),
            "severity_counts": summary.get("severity_counts", {
                "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
                "low": sum(1 for f in findings if f["severity"] == "LOW"),
            }),
            "findings": findings,
            "total_products_scanned": summary.get("total_products_queried", 0),
        }
