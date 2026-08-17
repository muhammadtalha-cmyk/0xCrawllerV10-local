from __future__ import annotations

import asyncio
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .artifacts import index_run_artifacts
from .config import Settings
from .database import Database, utc_now
from .events import EventBroker

TARGET_RE: Final = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

TOOL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.I), label)
    for pattern, label in (
        (r"subfinder", "Subfinder"),
        (r"\bamass\b", "Amass"),
        (r"\bbbot\b", "BBOT"),
        (r"\bdnsx\b", "DNSX"),
        (r"\bhttpx\b", "HTTPX"),
        (r"\bkatana\b", "Katana"),
        (r"gobuster", "Gobuster"),
        (r"\bnaabu\b", "Naabu"),
        (r"\bnmap\b", "Nmap"),
        (r"screenshot", "Screenshots"),
        (r"whatweb", "WhatWeb"),
        (r"wappalyzer", "Wappalyzer"),
        (r"retire", "Retire.js"),
        (r"zgrab", "ZGrab2"),
        (r"nuclei", "Nuclei"),
    )
)


@dataclass(frozen=True)
class PipelineStep:
    key: str
    allowed_exit_codes: frozenset[int]


# Stage keys match run_pipeline.py's --stage choices.
PIPELINE: tuple[PipelineStep, ...] = (
    PipelineStep("recon", frozenset({0, 3})),
    PipelineStep("normalization", frozenset({0})),
    PipelineStep("technology", frozenset({0})),
    PipelineStep("report", frozenset({0})),
)


class Orchestrator:
    def __init__(self, settings: Settings, db: Database, broker: EventBroker) -> None:
        self.settings = settings
        self.db = db
        self.broker = broker
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        self._lock = asyncio.Lock()

    @staticmethod
    def normalize_target(target: str) -> str:
        target = target.strip().lower().rstrip(".")
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                target = target[len(prefix):]
        target = target.split("/", 1)[0]
        if ":" in target:
            raise ValueError("Enter a domain only, without a port.")
        if not TARGET_RE.fullmatch(target):
            raise ValueError("Enter a valid domain such as example.com.")
        return target

    async def start(self, scan_id: str) -> None:
        async with self._lock:
            if scan_id in self._tasks and not self._tasks[scan_id].done():
                return
            self._tasks[scan_id] = asyncio.create_task(self._run(scan_id), name=f"scan-{scan_id}")

    async def cancel(self, scan_id: str) -> None:
        self.db.update_scan(scan_id, cancel_requested=1)
        process = self._processes.get(scan_id)
        if process and process.returncode is None:
            if os.name == "nt":
                killer = await asyncio.create_subprocess_exec(
                    "taskkill", "/PID", str(process.pid), "/T", "/F",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await killer.wait()
            else:
                process.terminate()
        await self._publish_snapshot(scan_id, "scan.cancel_requested")

    async def _run(self, scan_id: str) -> None:
        async with self._semaphore:
            scan = self.db.get_scan(scan_id)
            if not scan:
                return
            target = scan["target"]
            self.db.update_scan(scan_id, status="running", progress=0, error_message=None)
            self.db.append_log(scan_id, None, "info", f"Authorized scan started for {target}")
            await self._publish_snapshot(scan_id, "scan.started")

            monitor_task = asyncio.create_task(self._monitor_cancellation(scan_id))
            try:
                for index, step in enumerate(PIPELINE):
                    current = self.db.get_scan(scan_id)
                    if current and current["cancel_requested"]:
                        raise asyncio.CancelledError
                    await self._run_step(scan_id, target, step, index)
                self.db.update_scan(
                    scan_id,
                    status="completed",
                    current_step=None,
                    progress=100,
                    completed_at=utc_now(),
                )
                self.db.append_log(scan_id, None, "success", "All four modules completed successfully.")
                await self._publish_snapshot(scan_id, "scan.completed")
            except asyncio.CancelledError:
                current = self.db.get_scan(scan_id)
                step_key = current["current_step"] if current else None

                if step_key:
                    self.db.update_step(
                        scan_id,
                        step_key,
                        status="cancelled",
                        completed_at=utc_now(),
                        message="Cancelled by user.",
                    )

                self.db.update_scan(
                    scan_id,
                    status="cancelled",
                    current_step=None,
                    completed_at=utc_now(),
                )
                self.db.append_log(
                    scan_id,
                    step_key,
                    "warning",
                    "Scan cancelled by user.",
                )
                await self._publish_snapshot(scan_id, "scan.cancelled")
            except Exception as exc:
                current = self.db.get_scan(scan_id)
                step_key = current["current_step"] if current else None
                if step_key:
                    self.db.update_step(
                        scan_id, step_key, status="failed", completed_at=utc_now(), message=str(exc)
                    )
                self.db.update_scan(
                    scan_id,
                    status="failed",
                    completed_at=utc_now(),
                    error_message=str(exc),
                )
                self.db.append_log(scan_id, step_key, "error", str(exc))
                await self._publish_snapshot(scan_id, "scan.failed")
            finally:
                monitor_task.cancel()
                try:
                    await monitor_task
                except asyncio.CancelledError:
                    pass
                self._processes.pop(scan_id, None)

    async def _monitor_cancellation(self, scan_id: str) -> None:
        try:
            while True:
                await asyncio.sleep(1.0)
                scan = self.db.get_scan(scan_id)
                if scan and scan["cancel_requested"]:
                    await self.cancel(scan_id)
                    break
        except asyncio.CancelledError:
            pass

    async def _run_step(
        self, scan_id: str, target: str, step: PipelineStep, index: int
    ) -> None:
        base_progress = index * 25
        self.db.update_scan(
            scan_id, current_step=step.key, progress=base_progress, status="running"
        )
        self.db.update_step(
            scan_id,
            step.key,
            status="running",
            progress=5,
            started_at=utc_now(),
            completed_at=None,
            message="Starting",
        )
        self.db.append_log(scan_id, step.key, "info", f"Starting {step.key} module.")
        await self._publish_snapshot(scan_id, "step.started")

        if self.settings.mock_scanner:
            exit_code = await self._run_mock(scan_id, step, index)
        else:
            exit_code = await self._run_launcher(scan_id, target, step, index)

        if exit_code not in step.allowed_exit_codes:
            raise RuntimeError(f"{step.key} failed with exit code {exit_code}.")

        run_dir = self._find_latest_run(target)
        if run_dir:
            self.db.update_scan(scan_id, run_dir=str(run_dir))
            indexed = index_run_artifacts(
                self.db, self.settings.project_root, scan_id, run_dir
            )
            self.db.append_log(
                scan_id, step.key, "info", f"Indexed {indexed} report and evidence artifacts."
            )

        message = "Completed with partial recon coverage" if exit_code == 3 else "Completed"
        self.db.update_step(
            scan_id,
            step.key,
            status="completed",
            progress=100,
            completed_at=utc_now(),
            exit_code=exit_code,
            message=message,
        )
        self.db.update_scan(scan_id, progress=(index + 1) * 25)
        self.db.append_log(scan_id, step.key, "success", f"{step.key} module completed.")
        await self._publish_snapshot(scan_id, "step.completed")

    async def _run_launcher(
        self, scan_id: str, target: str, step: PipelineStep, index: int
    ) -> int:
        runner = (self.settings.project_root / "run_pipeline.py").resolve()
        if not runner.is_file():
            raise FileNotFoundError(
                f"run_pipeline.py not found at {runner}. Place it in the project root "
                "(same folder as smart_subdomain_pipeline_v8_modular.py)."
            )

        # Cross-platform: run the same Python interpreter running this backend,
        # unbuffered (-u) so log lines stream to the browser in real time.
        args = [
            sys.executable, "-u", str(runner),
            target,
            "--stage", step.key,
        ]
        if self.settings.skip_shodan:
            args.append("--skip-shodan")

        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=str(self.settings.project_root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._processes[scan_id] = process
        assert process.stdout is not None
        line_count = 0
        last_tool: str | None = None
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip()
            if not text:
                continue
            line_count += 1
            level = "error" if "[ERROR]" in text or "[FAILED]" in text else "info"
            if "[COMPLETE]" in text:
                level = "success"
            elif "[PARTIAL]" in text or "warning" in text.lower():
                level = "warning"
            log_id = self.db.append_log(scan_id, step.key, level, text)

            tool = self._detect_tool(text)
            if tool and tool != last_tool:
                last_tool = tool
                self.db.update_step(scan_id, step.key, message=f"Running {tool}")
            estimated = min(90, 5 + line_count // 20)
            self.db.update_step(scan_id, step.key, progress=estimated)
            self.db.update_scan(scan_id, progress=min(index * 25 + 22, index * 25 + estimated // 4))
            await self.broker.publish(
                scan_id,
                {
                    "type": "log",
                    "log": {
                        "id": log_id,
                        "scan_id": scan_id,
                        "step_key": step.key,
                        "level": level,
                        "message": text,
                        "created_at": utc_now(),
                    },
                },
            )
            if line_count % 25 == 0 or tool:
                await self._publish_snapshot(scan_id, "step.progress")

            current = self.db.get_scan(scan_id)
            if current and current["cancel_requested"]:
                await self.cancel(scan_id)
                raise asyncio.CancelledError

        return await process.wait()

    async def _run_mock(self, scan_id: str, step: PipelineStep, index: int) -> int:
        messages = {
            "recon": ["Subfinder discovery", "Amass discovery", "HTTPX probing", "Katana crawling", "Nmap reconciliation", "Screenshots collected"],
            "normalization": ["Merging discovered assets", "Removing duplicates", "Writing canonical inventory"],
            "technology": ["Collecting HTTP evidence", "Running WhatWeb", "Running Wappalyzer", "Running Nuclei", "Reconciling fingerprints"],
            "report": ["Loading module outputs", "Generating combined VAPT report"],
        }[step.key]
        for position, message in enumerate(messages, start=1):
            await asyncio.sleep(0.18)
            progress = int(position / len(messages) * 90)
            self.db.update_step(scan_id, step.key, progress=progress, message=message)
            self.db.update_scan(scan_id, progress=index * 25 + progress // 4)
            log_id = self.db.append_log(scan_id, step.key, "info", message)
            await self.broker.publish(
                scan_id,
                {"type": "log", "log": {"id": log_id, "scan_id": scan_id, "step_key": step.key, "level": "info", "message": message, "created_at": utc_now()}},
            )
            await self._publish_snapshot(scan_id, "step.progress")
        return 0

    @staticmethod
    def _detect_tool(text: str) -> str | None:
        for pattern, label in TOOL_PATTERNS:
            if pattern.search(text):
                return label
        return None

    def _find_latest_run(self, target: str) -> Path | None:
        if not self.settings.recon_root.is_dir():
            return None
        candidates = [
            path for path in self.settings.recon_root.iterdir()
            if path.is_dir() and path.name.lower().startswith(f"{target.lower()}-")
        ]
        return max(candidates, key=lambda path: path.stat().st_mtime) if candidates else None

    async def _publish_snapshot(self, scan_id: str, event_type: str) -> None:
        scan = self.db.get_scan(scan_id)
        if scan:
            await self.broker.publish(scan_id, {"type": event_type, "scan": scan})