from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Awaitable

from ..base import BaseModule

logger = logging.getLogger("crawller.modules.technologies")


class TechnologyDetectionModule(BaseModule):
    id = "technologies"
    name = "Technology Detection"
    description = "Fingerprint web servers, frameworks, programming languages, and UI components using WhatWeb and Wappalyzer."
    category = "Fingerprinting"
    icon = "FingerprintIcon"

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
        whatweb_out = output_dir / "whatweb.json"

        await update_progress(10, f"Initializing technology fingerprinting for {clean_target}...")

        target_urls = [f"https://{clean_target}", f"http://{clean_target}"]
        whatweb_cmd = [
            "docker", "run", "--rm",
            "-v", f"{str(output_dir.resolve())}:/output",
            "0xcrawller/whatweb:0.6.4",
            f"--log-json=/output/whatweb.json",
            "-a", "3",
            "--color=never",
            *target_urls,
        ]

        logger.info(f"Running WhatWeb for job {job_id}: {' '.join(whatweb_cmd)}")
        await update_progress(25, "Running WhatWeb active fingerprinting...")

        with log_file.open("w", encoding="utf-8") as lf:
            lf.write(f"=== Technology Detection Job: {job_id} ===\n")
            lf.write(f"Target: {clean_target}\n\n")

            proc = await asyncio.create_subprocess_exec(
                *whatweb_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            lf.write(stdout.decode("utf-8", errors="replace"))

        # Normalize permissions
        try:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{str(output_dir.resolve())}:/output", "alpine", "sh", "-c", "chmod -R a+rX /output 2>/dev/null || true"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
        except Exception:
            pass

        await update_progress(70, "Parsing technology signatures...")

        technologies: list[dict[str, Any]] = []
        seen = set()

        if whatweb_out.is_file():
            try:
                data = json.loads(whatweb_out.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, list):
                    for entry in data:
                        plugins = entry.get("plugins", {})
                        target_url = entry.get("target", clean_target)
                        for plugin_name, plugin_info in plugins.items():
                            if plugin_name.lower() in ("country", "ip", "uncommonheaders", "title", "script"):
                                continue

                            version = None
                            categories = []
                            string_evidence = ""

                            if isinstance(plugin_info, dict):
                                if plugin_info.get("version"):
                                    v = plugin_info["version"]
                                    version = v[0] if isinstance(v, list) else str(v)
                                if plugin_info.get("string"):
                                    s = plugin_info["string"]
                                    string_evidence = s[0] if isinstance(s, list) else str(s)
                                if plugin_info.get("categories"):
                                    categories = plugin_info["categories"]

                            key = f"{plugin_name.lower()}:{version or ''}"
                            if key in seen:
                                continue
                            seen.add(key)

                            technologies.append({
                                "name": plugin_name,
                                "version": version,
                                "category": ", ".join(categories) if categories else "Software",
                                "evidence": string_evidence or "Observed HTTP response match",
                                "target": target_url,
                            })
            except Exception as e:
                logger.warning(f"Error parsing whatweb output: {e}")

        # Sort: items with exact version first, then alphabetical
        technologies.sort(key=lambda x: (0 if x["version"] else 1, x["name"]))

        duration = round(time.monotonic() - started, 2)
        await update_progress(100, f"Completed: Detected {len(technologies)} technologies ({sum(1 for t in technologies if t['version'])} with exact versions)")

        return {
            "module": self.id,
            "target": clean_target,
            "job_id": job_id,
            "duration_seconds": duration,
            "total_technologies": len(technologies),
            "versioned_technologies": sum(1 for t in technologies if t["version"]),
            "technologies": technologies,
        }
