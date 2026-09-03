from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Awaitable

from ..base import BaseModule

logger = logging.getLogger("crawller.modules.screenshots")


class ScreenshotCollectionModule(BaseModule):
    id = "screenshots"
    name = "Screenshot Intelligence"
    description = "Capture headless browser visual screenshots and HTTP service details using ProjectDiscovery HTTPX."
    category = "Visual Evidence"
    icon = "CameraIcon"

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
        httpx_out = output_dir / "httpx.jsonl"
        screenshot_dir = output_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        await update_progress(10, f"Initializing headless browser capture for {clean_target}...")

        targets_arg = f"https://{clean_target},http://{clean_target}"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{str(output_dir.resolve())}:/output",
            "projectdiscovery/httpx:latest",
            "-u", targets_arg,
            "-screenshot",
            "-srd", "/output/screenshots",
            "-timeout", "15",
            "-json",
            "-o", "/output/httpx.jsonl",
        ]

        logger.info(f"Running HTTPX screenshot for job {job_id}: {' '.join(cmd)}")
        await update_progress(30, "Rendering web page and capturing screenshot...")

        with log_file.open("w", encoding="utf-8") as lf:
            lf.write(f"=== Screenshot Intelligence Job: {job_id} ===\n")
            lf.write(f"Target: {clean_target}\n\n")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            lf.write(stdout.decode("utf-8", errors="replace"))

        # Normalize permissions immediately so non-root Python can read files
        try:
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{str(output_dir.resolve())}:/output", "alpine", "sh", "-c", "chmod -R a+rX /output 2>/dev/null || true"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
        except Exception:
            pass

        await update_progress(80, "Encoding captured screenshots...")

        screenshots: list[dict[str, Any]] = []

        # Find all png screenshot images in output_dir
        image_map: dict[str, str] = {}
        for p in output_dir.rglob("*.png"):
            if p.is_file() and p.stat().st_size > 0:
                try:
                    data = base64.b64encode(p.read_bytes()).decode("ascii")
                    image_map[p.name] = f"data:image/png;base64,{data}"
                except Exception as e:
                    logger.warning(f"Failed to read image {p}: {e}")

        # Correlate with httpx metadata if available
        seen_urls = set()
        if httpx_out.is_file():
            for line in httpx_out.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    url = entry.get("url") or entry.get("input") or ""
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)

                    # Look for associated screenshot
                    scr_path = entry.get("screenshot_path")
                    img_data = None
                    if scr_path:
                        fname = Path(scr_path).name
                        img_data = image_map.get(fname)
                    if not img_data and image_map:
                        # Fallback to any available image in map
                        img_data = next(iter(image_map.values()), None)

                    screenshots.append({
                        "host": clean_target,
                        "url": url,
                        "status_code": entry.get("status_code", 200),
                        "title": entry.get("title", ""),
                        "webserver": entry.get("webserver", ""),
                        "image_base64": img_data,
                    })
                except Exception:
                    continue

        # If HTTPX jsonl didn't produce entries but images exist on disk
        if not screenshots and image_map:
            for fname, b64 in image_map.items():
                screenshots.append({
                    "host": clean_target,
                    "url": f"https://{clean_target}",
                    "status_code": 200,
                    "title": clean_target,
                    "webserver": "",
                    "image_base64": b64,
                })

        duration = round(time.monotonic() - started, 2)
        await update_progress(100, f"Completed: Captured {len(screenshots)} screenshots for {clean_target}")

        return {
            "module": self.id,
            "target": clean_target,
            "job_id": job_id,
            "duration_seconds": duration,
            "total_screenshots": len(screenshots),
            "screenshots": screenshots,
        }
