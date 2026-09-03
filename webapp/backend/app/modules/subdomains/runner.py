from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Awaitable

from ..base import BaseModule

logger = logging.getLogger("crawller.modules.subdomains")

def get_project_root() -> Path:
    curr = Path(__file__).resolve().parent
    for _ in range(7):
        if (curr / "smart_subdomain_pipeline_v8_modular.py").is_file():
            return curr
        curr = curr.parent
    return Path(os.getenv("CRAWLLER_PROJECT_ROOT", "/home/talha-crawller/0xCrawllerV10-local")).resolve()

PROJECT_ROOT = get_project_root()


class SubdomainDiscoveryModule(BaseModule):
    id = "subdomains"
    name = "Subdomain Discovery"
    description = "Discover subdomains and validate DNS assets using Subfinder, Amass, BBOT, and DNSX."
    category = "Reconnaissance"
    icon = "GlobeIcon"

    async def run(
        self,
        job_id: str,
        target: str,
        output_dir: Path,
        update_progress: Callable[[int, str], Awaitable[None]],
    ) -> dict[str, Any]:
        started_time = time.monotonic()
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

        raw_output = output_dir / "raw"
        raw_output.mkdir(parents=True, exist_ok=True)
        log_file = output_dir / "execution.log"

        await update_progress(5, f"Initializing Subdomain Discovery for {clean_target}...")

        script_path = PROJECT_ROOT / "smart_subdomain_pipeline_v8_modular.py"
        if not script_path.is_file():
            raise FileNotFoundError(f"Underlying recon script not found at {script_path}")

        cmd = [
            sys.executable,
            "-u",
            str(script_path),
            "--target",
            clean_target,
            "--authorized",
            "--output-root",
            str(raw_output),
            "--no-screenshots",
            "--skip-katana",
            "--timeout",
            "900",
        ]

        logger.info(f"Starting subdomain discovery job {job_id}: {' '.join(cmd)}")

        with log_file.open("w", encoding="utf-8") as lf:
            lf.write(f"=== Subdomain Discovery Job: {job_id} ===\n")
            lf.write(f"Target: {clean_target}\n")
            lf.write(f"Command: {' '.join(cmd)}\n\n")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(PROJECT_ROOT),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            current_progress = 10
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace")
                lf.write(text)
                lf.flush()

                # Dynamic progress parsing from script output
                lower = text.lower()
                if "subfinder" in lower and current_progress < 25:
                    current_progress = 25
                    await update_progress(25, "Running Subfinder enumeration...")
                elif "amass" in lower and current_progress < 40:
                    current_progress = 40
                    await update_progress(40, "Running OWASP Amass discovery...")
                elif "bbot" in lower and current_progress < 55:
                    current_progress = 55
                    await update_progress(55, "Running BBOT recursive discovery...")
                elif "gobuster" in lower and current_progress < 70:
                    current_progress = 70
                    await update_progress(70, "Executing DNS permutation and bruteforce...")
                elif "dnsx" in lower and current_progress < 85:
                    current_progress = 85
                    await update_progress(85, "Resolving and validating discovered hosts with DNSX...")

            returncode = await proc.wait()
            if returncode not in (0, 3):
                raise RuntimeError(f"Subdomain discovery failed with exit code {returncode}. See execution.log for details.")

        await update_progress(90, "Normalizing file permissions and parsing results...")

        # Normalize permissions for container-created files
        try:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{str(raw_output)}:/output", "alpine", "sh", "-c", "chmod -R a+rX /output 2>/dev/null || true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
            )
        except Exception:
            pass

        # Locate run directory created by the script inside raw_output
        candidates = sorted(raw_output.glob(f"{clean_target}-*"))
        target_dir = candidates[-1] if candidates else raw_output

        # Parse DNS records & validated subdomains
        dns_records_file = target_dir / "all_dns_records.json"
        validated_hosts_file = target_dir / "validated_dns_hosts.txt"
        summary_file = target_dir / "summary.json"

        all_dns: dict[str, Any] = {}
        if dns_records_file.is_file():
            try:
                with dns_records_file.open("r", encoding="utf-8") as f:
                    all_dns = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read {dns_records_file}: {e}")

        validated_hosts: set[str] = set()
        if validated_hosts_file.is_file():
            try:
                validated_hosts = {
                    line.strip().lower()
                    for line in validated_hosts_file.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip()
                }
            except Exception as e:
                logger.warning(f"Failed to read {validated_hosts_file}: {e}")

        summary_data: dict[str, Any] = {}
        if summary_file.is_file():
            try:
                with summary_file.open("r", encoding="utf-8") as f:
                    summary_data = json.load(f)
            except Exception:
                pass

        # Assemble structured subdomain inventory
        subdomains: list[dict[str, Any]] = []
        seen_hosts = set()

        for host, data in all_dns.items():
            norm_host = host.strip().lower()
            seen_hosts.add(norm_host)
            ips = []
            if isinstance(data, dict):
                ips = data.get("a", []) + data.get("aaaa", [])
                cname = data.get("cname", [None])[0] if data.get("cname") else None
            elif isinstance(data, list):
                ips = data
                cname = None
            else:
                cname = None

            subdomains.append({
                "subdomain": norm_host,
                "ips": ips if isinstance(ips, list) else [str(ips)],
                "cname": cname,
                "dns_type": "A" if ips else ("CNAME" if cname else "DNS"),
                "status": "active" if ips or norm_host in validated_hosts else "unresolved",
            })

        for host in validated_hosts:
            if host not in seen_hosts:
                subdomains.append({
                    "subdomain": host,
                    "ips": [],
                    "cname": None,
                    "dns_type": "A",
                    "status": "active",
                })
                seen_hosts.add(host)

        # Sort: active first, then alphabetical
        subdomains.sort(key=lambda x: (0 if x["status"] == "active" else 1, x["subdomain"]))

        duration_sec = round(time.monotonic() - started_time, 2)
        await update_progress(100, f"Completed: Discovered {len(subdomains)} subdomains ({sum(1 for s in subdomains if s['status'] == 'active')} active)")

        return {
            "module": self.id,
            "target": clean_target,
            "job_id": job_id,
            "duration_seconds": duration_sec,
            "total_subdomains": len(subdomains),
            "active_subdomains": sum(1 for s in subdomains if s["status"] == "active"),
            "subdomains": subdomains,
            "counts": summary_data.get("counts", {}),
        }
