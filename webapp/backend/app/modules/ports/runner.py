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

logger = logging.getLogger("crawller.modules.ports")

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9000: "fastcgi", 9200: "elasticsearch", 27017: "mongodb",
}


class PortScannerModule(BaseModule):
    id = "ports"
    name = "Port Scanner"
    description = "Discover open TCP ports and identify listening network services using ProjectDiscovery Naabu."
    category = "Network"
    icon = "ServerIcon"

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
        naabu_out = output_dir / "naabu.json"

        await update_progress(10, f"Initializing port scan for {clean_target}...")

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{str(output_dir.resolve())}:/output",
            "projectdiscovery/naabu:latest",
            "-host", clean_target,
            "-top-ports", "100",
            "-json",
            "-o", "/output/naabu.json",
        ]

        logger.info(f"Running Naabu for job {job_id}: {' '.join(cmd)}")
        await update_progress(30, "Scanning top 100 ports with Naabu...")

        with log_file.open("w", encoding="utf-8") as lf:
            lf.write(f"=== Port Scan Job: {job_id} ===\n")
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

        await update_progress(80, "Analyzing open ports and mapping services...")

        ports: list[dict[str, Any]] = []
        seen = set()

        if naabu_out.is_file():
            for line in naabu_out.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    port_num = entry.get("port")
                    if not port_num or port_num in seen:
                        continue
                    seen.add(port_num)

                    service = COMMON_SERVICES.get(port_num, "unknown")
                    ports.append({
                        "port": port_num,
                        "protocol": "tcp",
                        "service": service,
                        "state": "open",
                        "ip": entry.get("ip", ""),
                        "host": entry.get("host", clean_target),
                    })
                except Exception:
                    continue

        ports.sort(key=lambda x: x["port"])

        duration = round(time.monotonic() - started, 2)
        await update_progress(100, f"Completed: Found {len(ports)} open ports on {clean_target}")

        return {
            "module": self.id,
            "target": clean_target,
            "job_id": job_id,
            "duration_seconds": duration,
            "total_ports": len(ports),
            "ports": ports,
        }
