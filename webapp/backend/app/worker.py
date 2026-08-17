import asyncio
import logging
import os
import sys
import httpx
from datetime import datetime, timezone

from .config import settings
from .database import Database, utc_now
from .orchestrator import Orchestrator

# Configure logging to stdout so it's captured by parent process / startup scripts
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("crawller.worker")

db = Database(settings.database_path, settings.database_url)


class WorkerEventBroker:
    def __init__(self) -> None:
        self.backend_url = os.getenv("CRAWLLER_BACKEND_URL", "http://localhost:8000").rstrip("/")
        self.api_key = settings.api_key
        self.client = httpx.AsyncClient(timeout=10.0)

    async def publish(self, scan_id: str, event: dict) -> None:
        url = f"{self.backend_url}/api/internal/scans/{scan_id}/events"
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        try:
            response = await self.client.post(url, json=event, headers=headers)
            if response.status_code != 200:
                logger.error(f"Failed to forward event to backend: {response.status_code} {response.text}")
        except Exception as e:
            logger.exception("Network error forwarding event to backend")

    async def close(self) -> None:
        await self.client.aclose()


def claim_scan(scan_id: str) -> bool:
    """Claim a queued scan atomically to prevent duplicate execution."""
    with db._write_lock, db.connect() as connection:
        if db.is_postgres:
            cursor = connection.execute(
                "UPDATE scans SET status = 'running' WHERE id = %s AND status = 'queued'",
                (scan_id,)
            )
            connection.commit()
            return cursor.rowcount > 0
        else:
            # SQLite check-and-set within write lock to prevent race conditions
            row = connection.execute(
                "SELECT status FROM scans WHERE id = ?",
                (scan_id,)
            )
            result = row.fetchone()
            if result and result["status"] == "queued":
                connection.execute(
                    "UPDATE scans SET status = 'running' WHERE id = ?",
                    (scan_id,)
                )
                connection.commit()
                return True
            return False


def run_recovery() -> None:
    """Recover scans left running by a previous worker process."""
    logger.info("Running recovery checks for active scans...")
    now = utc_now()

    try:
        placeholder = "%s" if db.is_postgres else "?"

        with db.connect() as connection:
            running_scans = connection.execute(
                f"SELECT id FROM scans WHERE status = {placeholder}",
                ("running",)
            ).fetchall()

            logger.info(f"Recovery found {len(running_scans)} running scan(s).")

            for scan in running_scans:
                scan_id = scan["id"]
                logger.warning(
                    f"Recovering scan {scan_id}: marking status as failed "
                    "due to worker restart."
                )

                connection.execute(
                    f"""
                    UPDATE scans
                    SET status = {placeholder},
                        completed_at = {placeholder},
                        error_message = {placeholder}
                    WHERE id = {placeholder}
                    """,
                    (
                        "failed",
                        now,
                        "Scan execution interrupted due to worker process restart. "
                        "Output preserved.",
                        scan_id,
                    ),
                )

                connection.execute(
                    f"""
                    UPDATE steps
                    SET status = {placeholder},
                        completed_at = {placeholder},
                        message = {placeholder}
                    WHERE scan_id = {placeholder}
                      AND status = {placeholder}
                    """,
                    (
                        "failed",
                        now,
                        "Interrupted by worker restart",
                        scan_id,
                        "running",
                    ),
                )

            connection.commit()

        logger.info("Recovery checks completed successfully.")

    except Exception:
        logger.exception(
            "Recovery check failed. Continuing worker startup so queued scans "
            "can still be processed."
        )

async def run_scan_task(scan_id: str, orchestrator: Orchestrator) -> None:
    """Runs a single scan using the orchestrator, and handles cleanup."""
    logger.info(f"Scan {scan_id} execution started.")
    try:
        # Run orchestrator's existing execution logic
        await orchestrator._run(scan_id)
        logger.info(f"Scan {scan_id} execution completed.")
    except Exception as exc:
        logger.exception(f"Unexpected exception while running scan {scan_id}: {exc}")
    finally:
        # Final cleanup for orchestrator process mapping
        orchestrator._processes.pop(scan_id, None)


async def main() -> None:
    logger.info("0xCrawller persistent worker starting up...")
    
    # Clean up any leftover running scans from a previous crashed run
    run_recovery()
    
    broker = WorkerEventBroker()
    orchestrator = Orchestrator(settings, db, broker)
    
    active_tasks: dict[str, asyncio.Task] = {}
    
    try:
        while True:
            # Prune completed tasks
            for scan_id, task in list(active_tasks.items()):
                if task.done():
                    try:
                        await task  # raise any task errors
                    except Exception as e:
                        logger.error(f"Task error for scan {scan_id}: {e}")
                    active_tasks.pop(scan_id)
            
            # Check if we have capacity to claim a new scan
            if len(active_tasks) < settings.max_concurrent_scans:
                # Find the next queued scan
                placeholder = "%s" if db.is_postgres else "?"
                queued_scans = db.query_all(
                    f"SELECT id FROM scans WHERE status = {placeholder} ORDER BY started_at ASC LIMIT 1",
                    ("queued",)
                )
                
                if queued_scans:
                    scan_id = queued_scans[0]["id"]
                    if claim_scan(scan_id):
                        logger.info(f"Successfully claimed scan {scan_id}. Launching task...")
                        task = asyncio.create_task(run_scan_task(scan_id, orchestrator))
                        active_tasks[scan_id] = task
            
            await asyncio.sleep(1.0)
            
    except asyncio.CancelledError:
        logger.info("Worker received cancellation. Cleaning up running tasks...")
        for task in active_tasks.values():
            task.cancel()
        await asyncio.gather(*active_tasks.values(), return_exceptions=True)
    finally:
        await broker.close()
        logger.info("Worker stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Worker terminated by user.")
