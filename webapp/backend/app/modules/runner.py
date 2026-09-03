from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .registry import get_module
from ..database import Database, utc_now

logger = logging.getLogger("crawller.modules.runner")

def get_project_root() -> Path:
    curr = Path(__file__).resolve().parent
    for _ in range(7):
        if (curr / "smart_subdomain_pipeline_v8_modular.py").is_file():
            return curr
        curr = curr.parent
    return Path(os.getenv("CRAWLLER_PROJECT_ROOT", "/home/talha-crawller/0xCrawllerV10-local")).resolve()

PROJECT_ROOT = get_project_root()
MODULE_OUTPUT_ROOT = Path(os.getenv("MODULE_OUTPUT_ROOT", str(PROJECT_ROOT / "module_runs"))).resolve()


class ModuleExecutionRunner:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def run_job(self, job_id: str, module_name: str, target: str, user_id: Optional[str] = None) -> None:
        module = get_module(module_name)
        if not module:
            err_msg = f"Unknown module: {module_name}"
            logger.error(err_msg)
            self.db.update_module_job(
                job_id,
                status="failed",
                completed_at=utc_now(),
                error_message=err_msg,
            )
            return

        job_output_dir = MODULE_OUTPUT_ROOT / module.id / job_id
        job_output_dir.mkdir(parents=True, exist_ok=True)
        results_file = job_output_dir / "results.json"

        # Update job to running
        self.db.update_module_job(
            job_id,
            status="running",
            started_at=utc_now(),
            progress=5,
        )

        async def update_progress(pct: int, msg: str = "") -> None:
            self.db.update_module_job(
                job_id,
                progress=min(max(pct, 0), 100),
            )
            if msg:
                logger.info(f"[{module.name} - {job_id}] ({pct}%): {msg}")

        try:
            logger.info(f"Launching module execution: {module.name} on target: {target} (Job: {job_id})")
            results = await module.run(
                job_id=job_id,
                target=target,
                output_dir=job_output_dir,
                update_progress=update_progress,
            )

            # Write results.json
            with results_file.open("w", encoding="utf-8") as rf:
                json.dump(results, rf, indent=2, ensure_ascii=False)

            # Mark completed
            self.db.update_module_job(
                job_id,
                status="completed",
                progress=100,
                completed_at=utc_now(),
                result_location=str(results_file),
            )
            logger.info(f"Module job {job_id} ({module.name}) completed successfully.")

        except asyncio.CancelledError:
            logger.warning(f"Module job {job_id} was cancelled.")
            self.db.update_module_job(
                job_id,
                status="cancelled",
                completed_at=utc_now(),
                error_message="Job execution was cancelled.",
            )
        except Exception as exc:
            logger.exception(f"Module job {job_id} failed: {exc}")
            err_str = f"{type(exc).__name__}: {str(exc)}"
            self.db.update_module_job(
                job_id,
                status="failed",
                completed_at=utc_now(),
                error_message=err_str,
            )
