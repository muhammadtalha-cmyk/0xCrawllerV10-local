from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Callable, Awaitable

from ..base import BaseModule

logger = logging.getLogger("crawller.modules.endpoints")


class EndpointDiscoveryModule(BaseModule):
    id = "endpoints"
    name = "Endpoint Discovery"
    description = "Crawl target web properties to discover APIs, scripts, endpoints, and hidden parameters using ProjectDiscovery Katana."
    category = "Web Application"
    icon = "LinkIcon"

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
        katana_out = output_dir / "katana.jsonl"

        await update_progress(10, f"Initializing Katana endpoint crawler for {clean_target}...")

        target_url = f"https://{clean_target}"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{str(output_dir.resolve())}:/output",
            "projectdiscovery/katana:latest",
            "-u", target_url,
            "-depth", "3",
            "-jc",
            "-jsonl",
            "-o", "/output/katana.jsonl",
            "-c", "10",
            "-timeout", "10",
        ]

        logger.info(f"Running Katana for job {job_id}: {' '.join(cmd)}")
        await update_progress(30, "Crawling pages and discovering endpoints with Katana...")

        with log_file.open("w", encoding="utf-8") as lf:
            lf.write(f"=== Endpoint Discovery Job: {job_id} ===\n")
            lf.write(f"Target: {clean_target}\n\n")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
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

        await update_progress(80, "Classifying discovered endpoints...")

        endpoints: list[dict[str, Any]] = []
        seen_urls = set()

        if katana_out.is_file():
            for line in katana_out.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    req = entry.get("request", {})
                    url = req.get("endpoint") or entry.get("endpoint") or ""
                    if not url or url in seen_urls:
                        continue
                    seen_urls.add(url)

                    parsed = urlparse(url)
                    path = parsed.path or "/"

                    # Categorize endpoint
                    category = "Web Page"
                    lower_path = path.lower()
                    if "/api/" in lower_path or "/v1/" in lower_path or "/v2/" in lower_path or "/graphql" in lower_path:
                        category = "API Endpoint"
                    elif lower_path.endswith((".js", ".mjs", ".ts")):
                        category = "JavaScript Asset"
                    elif lower_path.endswith((".json", ".xml", ".yaml", ".yml")):
                        category = "Data / Configuration"
                    elif lower_path.endswith((".css", ".svg", ".png", ".jpg", ".woff", ".woff2")):
                        category = "Static Asset"

                    endpoints.append({
                        "url": url,
                        "path": path,
                        "method": req.get("method", "GET"),
                        "category": category,
                        "tag": req.get("tag", ""),
                    })
                except Exception:
                    continue

        # Sort: APIs and Data first, then alphabetical
        endpoints.sort(key=lambda x: (0 if "API" in x["category"] else (1 if "Data" in x["category"] else 2), x["path"]))

        duration = round(time.monotonic() - started, 2)
        await update_progress(100, f"Completed: Discovered {len(endpoints)} unique endpoints ({sum(1 for e in endpoints if 'API' in e['category'])} APIs)")

        return {
            "module": self.id,
            "target": clean_target,
            "job_id": job_id,
            "duration_seconds": duration,
            "total_endpoints": len(endpoints),
            "api_endpoints": sum(1 for e in endpoints if "API" in e["category"]),
            "endpoints": endpoints,
        }
