from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Awaitable, Dict
from ..base import BaseModule


class WAFDetectionModule(BaseModule):
    id = "waf"
    name = "WAF & CDN Detection"
    description = "Detect and fingerprint 150+ Web Application Firewalls (Cloudflare, AWS WAF, Akamai, etc.) using WAFW00F."
    category = "Perimeter Defense"
    icon = "🛡️"

    async def run(
        self,
        job_id: str,
        target: str,
        output_dir: Path,
        update_progress: Callable[[int, str], Awaitable[None]],
    ) -> dict[str, Any]:
        await update_progress(10, "Initializing WAFW00F engine...")

        clean_target = target.strip()
        if clean_target.startswith("https://") or clean_target.startswith("http://"):
            url = clean_target
        else:
            url = f"https://{clean_target}"

        log_file = output_dir / "execution.log"
        waf_json_file = output_dir / "waf.json"

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{output_dir}:/output",
            "smartrecon/wafw00f:2.4.2",
            url,
            "-o", "/output/waf.json",
            "-f", "json",
        ]

        with open(log_file, "a") as f:
            f.write(f"=== WAF & CDN Detection Job: {job_id} ===\nTarget: {url}\nCommand: {' '.join(cmd)}\n\n")

        await update_progress(30, "Fingerprinting perimeter firewalls...")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        stdout_data, _ = await proc.communicate()
        raw_output = stdout_data.decode(errors="ignore") if stdout_data else ""

        with open(log_file, "a") as f:
            f.write(raw_output)

        await update_progress(80, "Analyzing detection signatures...")

        waf_detected = False
        firewall_name = "None"
        manufacturer = "None"
        results_list = []

        if waf_json_file.exists():
            try:
                with open(waf_json_file, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list) and len(data) > 0:
                        first = data[0]
                        waf_detected = bool(first.get("detected", False))
                        firewall_name = first.get("firewall", "None")
                        manufacturer = first.get("manufacturer", "None")
                        results_list = data
            except Exception as e:
                with open(log_file, "a") as f:
                    f.write(f"\nFailed to parse waf.json: {e}\n")

        if not waf_detected:
            for line in raw_output.splitlines():
                if "is behind" in line:
                    waf_detected = True
                    parts = line.split("is behind")[-1].strip()
                    firewall_name = parts.replace("WAF.", "").replace("WAF", "").strip()
                    break

        await update_progress(100, "WAF detection completed.")

        results = {
            "module": self.id,
            "target": target,
            "job_id": job_id,
            "detected": waf_detected,
            "firewall": firewall_name,
            "manufacturer": manufacturer,
            "findings": results_list,
            "raw_log_summary": "\n".join([line for line in raw_output.splitlines() if line.startswith("[+]") or line.startswith("[~]") or line.startswith("[*]")]),
        }

        return results
