from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


STEP_DEFINITIONS = (
    ("recon", "Reconnaissance", 1),
    ("normalization", "Asset normalization", 2),
    ("technology", "Technology intelligence", 3),
    ("cve", "CVE detection", 4),
    ("report", "Combined report", 5),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Database adapter supporting local SQLite and PostgreSQL."""

    def __init__(self, path: Path, database_url: str | None = None):
        self.path = path
        self.database_url = database_url.strip() if database_url else None

        if not self.database_url:
            self.path.parent.mkdir(parents=True, exist_ok=True)

        self._write_lock = threading.Lock()
        self._pool = None

        if self.database_url:
            try:
                from psycopg_pool import ConnectionPool
                from psycopg.rows import dict_row
                self._pool = ConnectionPool(
                    conninfo=self.database_url,
                    open=True,
                    min_size=2,
                    max_size=15,
                    kwargs={"row_factory": dict_row, "prepare_threshold": None}
                )
            except Exception as e:
                pass

        self.initialize()

    @property
    def is_postgres(self) -> bool:
        return bool(self.database_url)

    def _sql(self, sql: str) -> str:
        if self.is_postgres:
            return sql.replace("?", "%s")
        return sql

    def connect(self):
        if self.is_postgres:
            if self._pool is not None:
                return self._pool.connection()

            import psycopg
            from psycopg.rows import dict_row

            return psycopg.connect(
                self.database_url,
                row_factory=dict_row,
                prepare_threshold=None,
            )

        connection = sqlite3.connect(
            self.path,
            timeout=30,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    # ------------------------------------------------------------------
    # INITIALIZATION
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        if self.is_postgres:
            with self.connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'USER',
                        created_at TEXT NOT NULL
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scans (
                        id TEXT PRIMARY KEY,
                        user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
                        target TEXT NOT NULL,
                        status TEXT NOT NULL,
                        current_step TEXT,
                        progress INTEGER NOT NULL DEFAULT 0,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        error_message TEXT,
                        run_dir TEXT,
                        cancel_requested BOOLEAN NOT NULL DEFAULT FALSE
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS steps (
                        id BIGSERIAL PRIMARY KEY,
                        scan_id TEXT NOT NULL
                            REFERENCES scans(id)
                            ON DELETE CASCADE,
                        step_key TEXT NOT NULL,
                        name TEXT NOT NULL,
                        position INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        progress INTEGER NOT NULL DEFAULT 0,
                        started_at TEXT,
                        completed_at TEXT,
                        exit_code INTEGER,
                        message TEXT,
                        UNIQUE(scan_id, step_key)
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS logs (
                        id BIGSERIAL PRIMARY KEY,
                        scan_id TEXT NOT NULL
                            REFERENCES scans(id)
                            ON DELETE CASCADE,
                        step_key TEXT,
                        level TEXT NOT NULL,
                        message TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_logs_scan_id
                    ON logs(scan_id, id)
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS artifacts (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL
                            REFERENCES scans(id)
                            ON DELETE CASCADE,
                        step_key TEXT,
                        kind TEXT NOT NULL,
                        name TEXT NOT NULL,
                        relative_path TEXT NOT NULL,
                        mime_type TEXT,
                        size_bytes BIGINT NOT NULL DEFAULT 0,
                        cloudinary_url TEXT,
                        cloudinary_public_id TEXT,
                        created_at TEXT NOT NULL,
                        UNIQUE(scan_id, relative_path)
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_artifacts_scan_id
                    ON artifacts(scan_id, kind)
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS assets (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                        hostname TEXT,
                        fqdn TEXT,
                        asset_type TEXT,
                        ip_address TEXT,
                        status TEXT,
                        source TEXT,
                        metadata JSONB DEFAULT '{}'::jsonb
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dns_records (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                        asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
                        record_type TEXT,
                        value TEXT,
                        ttl INTEGER,
                        source TEXT
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ports (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                        asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
                        port INTEGER,
                        protocol TEXT,
                        state TEXT,
                        service TEXT,
                        banner TEXT
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS technologies (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                        asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
                        name TEXT,
                        category TEXT,
                        version TEXT,
                        confidence TEXT,
                        detection_source TEXT,
                        evidence JSONB DEFAULT '{}'::jsonb
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS endpoints (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                        asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
                        url TEXT,
                        path TEXT,
                        method TEXT,
                        status_code INTEGER,
                        content_type TEXT,
                        source TEXT
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS screenshots (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                        asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
                        url TEXT,
                        image_path TEXT,
                        captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS evidence (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                        asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
                        evidence_type TEXT,
                        source TEXT,
                        content JSONB
                    )
                    """
                )

                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS findings (
                        id SERIAL PRIMARY KEY,
                        scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                        asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
                        finding_type TEXT,
                        severity TEXT,
                        confidence TEXT,
                        description TEXT,
                        status TEXT DEFAULT 'needs_validation'
                    )
                    """
                )

                connection.commit()

            return

        with self.connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'USER',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_step TEXT,
                    progress INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_message TEXT,
                    run_dir TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL
                        REFERENCES scans(id)
                        ON DELETE CASCADE,
                    step_key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT,
                    completed_at TEXT,
                    exit_code INTEGER,
                    message TEXT,
                    UNIQUE(scan_id, step_key)
                );

                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL
                        REFERENCES scans(id)
                        ON DELETE CASCADE,
                    step_key TEXT,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_logs_scan_id
                ON logs(scan_id, id);

                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL
                        REFERENCES scans(id)
                        ON DELETE CASCADE,
                    step_key TEXT,
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    mime_type TEXT,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    cloudinary_url TEXT,
                    cloudinary_public_id TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(scan_id, relative_path)
                );

                CREATE INDEX IF NOT EXISTS idx_artifacts_scan_id
                ON artifacts(scan_id, kind);
                """
            )

    # ------------------------------------------------------------------
    # GENERIC DATABASE HELPERS
    # ------------------------------------------------------------------

    def execute(
        self,
        sql: str,
        params: Iterable[Any] = (),
    ) -> int:
        with self._write_lock, self.connect() as connection:
            cursor = connection.execute(
                self._sql(sql),
                tuple(params),
            )

            connection.commit()

            if self.is_postgres:
                return int(cursor.rowcount)

            return int(cursor.lastrowid or 0)

    def query_one(
        self,
        sql: str,
        params: Iterable[Any] = (),
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                self._sql(sql),
                tuple(params),
            ).fetchone()

            return dict(row) if row else None

    def query_all(
        self,
        sql: str,
        params: Iterable[Any] = (),
    ) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                self._sql(sql),
                tuple(params),
            ).fetchall()

            return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # SCANS
    # ------------------------------------------------------------------

    def create_scan(self, target: str, user_id: str | None = None) -> str:
        scan_id = str(uuid.uuid4())
        now = utc_now()

        with self._write_lock, self.connect() as connection:
            connection.execute(
                self._sql(
                    """
                    INSERT INTO scans(
                        id,
                        user_id,
                        target,
                        status,
                        progress,
                        started_at
                    )
                    VALUES(?, ?, ?, ?, ?, ?)
                    """
                ),
                (
                    scan_id,
                    user_id,
                    target,
                    "queued",
                    0,
                    now,
                ),
            )

            step_rows = [
                (
                    scan_id,
                    key,
                    name,
                    position,
                    "pending",
                    0,
                )
                for key, name, position in STEP_DEFINITIONS
            ]

            if self.is_postgres:
                # psycopg Connection has no executemany().
                # executemany() belongs to the Cursor.
                with connection.cursor() as cursor:
                    cursor.executemany(
                        """
                        INSERT INTO steps(
                            scan_id,
                            step_key,
                            name,
                            position,
                            status,
                            progress
                        )
                        VALUES(%s, %s, %s, %s, %s, %s)
                        """,
                        step_rows,
                    )
            else:
                connection.executemany(
                    """
                    INSERT INTO steps(
                        scan_id,
                        step_key,
                        name,
                        position,
                        status,
                        progress
                    )
                    VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    step_rows,
                )

            connection.commit()

        return scan_id

    def get_scan_owner(
        self,
        scan_id: str,
    ) -> dict[str, Any] | None:
        placeholder = "%s" if self.is_postgres else "?"
        return self.query_one(
            f"""
            SELECT id, user_id
            FROM scans
            WHERE id = {placeholder}
            """,
            (scan_id,),
        )

    def get_scan(
        self,
        scan_id: str,
    ) -> dict[str, Any] | None:
        placeholder = "%s" if self.is_postgres else "?"

        scan = self.query_one(
            f"""
            SELECT *
            FROM scans
            WHERE id = {placeholder}
            """,
            (scan_id,),
        )

        if not scan:
            return None

        scan["steps"] = self.query_all(
            f"""
            SELECT *
            FROM steps
            WHERE scan_id = {placeholder}
            ORDER BY position
            """,
            (scan_id,),
        )

        artifact_counts = self.query_all(
            f"""
            SELECT
                kind,
                COUNT(*) AS count
            FROM artifacts
            WHERE scan_id = {placeholder}
            GROUP BY kind
            ORDER BY kind
            """,
            (scan_id,),
        )

        scan["artifact_counts"] = {
            str(row["kind"]): int(row["count"])
            for row in artifact_counts
        }

        return scan

    def list_scans(
        self,
        limit: int = 50,
        user_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List scans visible to the requested user.

        user_id=None is used by ADMIN and returns all scans.
        user_id=<id> returns only scans owned by that user.
        """
        limit = max(1, min(int(limit), 200))
        placeholder = "%s" if self.is_postgres else "?"

        if user_id is not None:
            scans = self.query_all(
                f"""
                SELECT *
                FROM scans
                WHERE user_id = {placeholder}
                ORDER BY started_at DESC
                LIMIT {placeholder}
                """,
                (user_id, limit),
            )
        else:
            scans = self.query_all(
                f"""
                SELECT *
                FROM scans
                ORDER BY started_at DESC
                LIMIT {placeholder}
                """,
                (limit,),
            )

        if not scans:
            return []

        scan_ids = [scan["id"] for scan in scans]
        placeholders = ", ".join(placeholder for _ in scan_ids)

        all_steps = self.query_all(
            f"""
            SELECT *
            FROM steps
            WHERE scan_id IN ({placeholders})
            ORDER BY position
            """,
            scan_ids,
        )

        steps_by_scan: dict[str, list[dict[str, Any]]] = {}
        for step in all_steps:
            sid = step["scan_id"]
            if sid not in steps_by_scan:
                steps_by_scan[sid] = []
            steps_by_scan[sid].append(step)

        all_counts = self.query_all(
            f"""
            SELECT scan_id, kind, COUNT(*) AS count
            FROM artifacts
            WHERE scan_id IN ({placeholders})
            GROUP BY scan_id, kind
            """,
            scan_ids,
        )

        counts_by_scan: dict[str, dict[str, int]] = {}
        for row in all_counts:
            sid = row["scan_id"]
            if sid not in counts_by_scan:
                counts_by_scan[sid] = {}
            counts_by_scan[sid][str(row["kind"])] = int(row["count"])

        for scan in scans:
            sid = scan["id"]
            scan["steps"] = steps_by_scan.get(sid, [])
            scan["artifact_counts"] = counts_by_scan.get(sid, {})

        return scans

    def update_scan(
        self,
        scan_id: str,
        **fields: Any,
    ) -> None:
        allowed = {
            "status",
            "current_step",
            "progress",
            "completed_at",
            "error_message",
            "run_dir",
            "cancel_requested",
        }

        updates = [
            (key, value)
            for key, value in fields.items()
            if key in allowed
        ]

        if not updates:
            return

        if self.is_postgres:
            clean_updates = []
            for key, value in updates:
                if key == "cancel_requested":
                    clean_updates.append((key, bool(value)))
                else:
                    clean_updates.append((key, value))
            updates = clean_updates

        assignments = ", ".join(
            f"{key} = {'%s' if self.is_postgres else '?'}"
            for key, _ in updates
        )

        params = [value for _, value in updates]
        params.append(scan_id)

        placeholder = "%s" if self.is_postgres else "?"

        with self._write_lock, self.connect() as connection:
            connection.execute(
                f"""
                UPDATE scans
                SET {assignments}
                WHERE id = {placeholder}
                """,
                tuple(params),
            )
            connection.commit()

    def update_step(
        self,
        scan_id: str,
        step_key: str,
        **fields: Any,
    ) -> None:
        allowed = {
            "status",
            "progress",
            "started_at",
            "completed_at",
            "exit_code",
            "message",
        }

        updates = [
            (key, value)
            for key, value in fields.items()
            if key in allowed
        ]

        if not updates:
            return

        assignments = ", ".join(
            f"{key} = {'%s' if self.is_postgres else '?'}"
            for key, _ in updates
        )

        params = [value for _, value in updates]
        params.extend([scan_id, step_key])

        placeholder = "%s" if self.is_postgres else "?"

        with self._write_lock, self.connect() as connection:
            connection.execute(
                f"""
                UPDATE steps
                SET {assignments}
                WHERE scan_id = {placeholder}
                  AND step_key = {placeholder}
                """,
                tuple(params),
            )
            connection.commit()

    # ------------------------------------------------------------------
    # LOGS
    # ------------------------------------------------------------------

    def append_log(
        self,
        scan_id: str,
        step_key: str | None,
        level: str,
        message: str,
    ) -> int:
        log_id = None
        now = utc_now()

        with self._write_lock, self.connect() as connection:
            if self.is_postgres:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO logs(
                            scan_id,
                            step_key,
                            level,
                            message,
                            created_at
                        )
                        VALUES(%s, %s, %s, %s, %s)
                        RETURNING id
                        """,
                        (
                            scan_id,
                            step_key,
                            level,
                            message,
                            now,
                        ),
                    )
                    row = cursor.fetchone()
                    if row:
                        # connect() uses psycopg's dict_row row_factory, so
                        # rows are dict-like (row["id"]), not positional
                        # (row[0]). Positional access raises KeyError: 0.
                        log_id = row["id"]
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO logs(
                        scan_id,
                        step_key,
                        level,
                        message,
                        created_at
                    )
                    VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        step_key,
                        level,
                        message,
                        now,
                    ),
                )
                log_id = cursor.lastrowid

            connection.commit()

        return int(log_id or 0)

    def get_logs(
        self,
        scan_id: str,
        after_id: int = 0,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        after_id = max(0, int(after_id))
        limit = max(1, min(int(limit), 5000))

        placeholder = "%s" if self.is_postgres else "?"

        return self.query_all(
            f"""
            SELECT *
            FROM logs
            WHERE scan_id = {placeholder}
              AND id > {placeholder}
            ORDER BY id
            LIMIT {placeholder}
            """,
            (
                scan_id,
                after_id,
                limit,
            ),
        )

    # ------------------------------------------------------------------
    # ARTIFACTS
    # ------------------------------------------------------------------

    def get_artifacts(
        self,
        scan_id: str,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        placeholder = "%s" if self.is_postgres else "?"

        if kind:
            return self.query_all(
                f"""
                SELECT *
                FROM artifacts
                WHERE scan_id = {placeholder}
                  AND kind = {placeholder}
                ORDER BY name
                """,
                (
                    scan_id,
                    kind,
                ),
            )

        return self.query_all(
            f"""
            SELECT *
            FROM artifacts
            WHERE scan_id = {placeholder}
            ORDER BY kind, name
            """,
            (scan_id,),
        )

    def get_artifact(
        self,
        artifact_id: str,
    ) -> dict[str, Any] | None:
        placeholder = "%s" if self.is_postgres else "?"

        return self.query_one(
            f"""
            SELECT *
            FROM artifacts
            WHERE id = {placeholder}
            """,
            (artifact_id,),
        )

    def upsert_artifact(
        self,
        scan_id: str,
        step_key: str | None,
        kind: str,
        name: str,
        relative_path: str,
        mime_type: str | None,
        size_bytes: int,
        cloudinary_url: str | None = None,
        cloudinary_public_id: str | None = None,
        created_at: str | None = None,
    ) -> str:
        artifact_id = str(uuid.uuid4())
        created_at = created_at or utc_now()

        with self._write_lock, self.connect() as connection:
            if self.is_postgres:
                connection.execute(
                    """
                    INSERT INTO artifacts(
                        id,
                        scan_id,
                        step_key,
                        kind,
                        name,
                        relative_path,
                        mime_type,
                        size_bytes,
                        cloudinary_url,
                        cloudinary_public_id,
                        created_at
                    )
                    VALUES(
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT(scan_id, relative_path)
                    DO UPDATE SET
                        step_key = EXCLUDED.step_key,
                        kind = EXCLUDED.kind,
                        name = EXCLUDED.name,
                        mime_type = EXCLUDED.mime_type,
                        size_bytes = EXCLUDED.size_bytes,
                        cloudinary_url = EXCLUDED.cloudinary_url,
                        cloudinary_public_id = EXCLUDED.cloudinary_public_id,
                        created_at = EXCLUDED.created_at
                    """,
                    (
                        artifact_id,
                        scan_id,
                        step_key,
                        kind,
                        name,
                        relative_path,
                        mime_type,
                        int(size_bytes),
                        cloudinary_url,
                        cloudinary_public_id,
                        created_at,
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO artifacts(
                        id,
                        scan_id,
                        step_key,
                        kind,
                        name,
                        relative_path,
                        mime_type,
                        size_bytes,
                        cloudinary_url,
                        cloudinary_public_id,
                        created_at
                    )
                    VALUES(
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(scan_id, relative_path)
                    DO UPDATE SET
                        step_key = excluded.step_key,
                        kind = excluded.kind,
                        name = excluded.name,
                        mime_type = excluded.mime_type,
                        size_bytes = excluded.size_bytes,
                        cloudinary_url = excluded.cloudinary_url,
                        cloudinary_public_id = excluded.cloudinary_public_id,
                        created_at = excluded.created_at
                    """,
                    (
                        artifact_id,
                        scan_id,
                        step_key,
                        kind,
                        name,
                        relative_path,
                        mime_type,
                        int(size_bytes),
                        cloudinary_url,
                        cloudinary_public_id,
                        created_at,
                    ),
                )

            connection.commit()

        existing = self.query_one(
            f"""
            SELECT id
            FROM artifacts
            WHERE scan_id = {"%s" if self.is_postgres else "?"}
              AND relative_path = {"%s" if self.is_postgres else "?"}
            """,
            (
                scan_id,
                relative_path,
            ),
        )

        return str(existing["id"]) if existing else artifact_id

    def get_assets_paginated(self, scan_id: str, limit: int, offset: int, host_filter: str = "") -> dict:
        placeholder = "%s" if self.is_postgres else "?"
        params = [scan_id]
        where_clause = f"WHERE scan_id = {placeholder}"
        if host_filter:
            where_clause += f" AND hostname ILIKE {placeholder}"
            params.append(f"%{host_filter}%")
        
        count_sql = f"SELECT COUNT(*) as total FROM assets {where_clause}"
        total = self.query_one(count_sql, params)["total"]

        data_sql = f"SELECT * FROM assets {where_clause} ORDER BY hostname LIMIT {placeholder} OFFSET {placeholder}"
        params.extend([limit, offset])
        data = self.query_all(data_sql, params)
        return {"total": total, "items": data}

    def get_services_paginated(self, scan_id: str, limit: int, offset: int) -> dict:
        placeholder = "%s" if self.is_postgres else "?"
        total = self.query_one(f"SELECT COUNT(*) as total FROM ports WHERE scan_id = {placeholder}", (scan_id,))["total"]
        data_sql = f"""
            SELECT p.*, a.hostname, a.ip_address 
            FROM ports p
            LEFT JOIN assets a ON p.asset_id = a.id
            WHERE p.scan_id = {placeholder}
            ORDER BY a.hostname, p.port
            LIMIT {placeholder} OFFSET {placeholder}
        """
        data = self.query_all(data_sql, (scan_id, limit, offset))
        return {"total": total, "items": data}

    def get_technologies_paginated(self, scan_id: str, limit: int, offset: int) -> dict:
        placeholder = "%s" if self.is_postgres else "?"
        total = self.query_one(f"SELECT COUNT(*) as total FROM technologies WHERE scan_id = {placeholder}", (scan_id,))["total"]
        data_sql = f"""
            SELECT t.*, a.hostname 
            FROM technologies t
            LEFT JOIN assets a ON t.asset_id = a.id
            WHERE t.scan_id = {placeholder}
            ORDER BY t.name, a.hostname
            LIMIT {placeholder} OFFSET {placeholder}
        """
        data = self.query_all(data_sql, (scan_id, limit, offset))
        return {"total": total, "items": data}

    def get_endpoints_paginated(self, scan_id: str, limit: int, offset: int) -> dict:
        placeholder = "%s" if self.is_postgres else "?"
        total = self.query_one(f"SELECT COUNT(*) as total FROM endpoints WHERE scan_id = {placeholder}", (scan_id,))["total"]
        data_sql = f"""
            SELECT e.*, a.hostname 
            FROM endpoints e
            LEFT JOIN assets a ON e.asset_id = a.id
            WHERE e.scan_id = {placeholder}
            ORDER BY e.url
            LIMIT {placeholder} OFFSET {placeholder}
        """
        data = self.query_all(data_sql, (scan_id, limit, offset))
        return {"total": total, "items": data}

    def get_findings_paginated(self, scan_id: str, limit: int, offset: int) -> dict:
        placeholder = "%s" if self.is_postgres else "?"
        total = self.query_one(f"SELECT COUNT(*) as total FROM findings WHERE scan_id = {placeholder}", (scan_id,))["total"]
        data_sql = f"""
            SELECT f.*, a.hostname 
            FROM findings f
            LEFT JOIN assets a ON f.asset_id = a.id
            WHERE f.scan_id = {placeholder}
            ORDER BY f.severity DESC, f.finding_type
            LIMIT {placeholder} OFFSET {placeholder}
        """
        data = self.query_all(data_sql, (scan_id, limit, offset))
        return {"total": total, "items": data}

    def get_relationships_paginated(self, scan_id: str, limit: int, offset: int) -> dict:
        placeholder = "%s" if self.is_postgres else "?"
        total = self.query_one(f"SELECT COUNT(*) as total FROM relationships WHERE scan_id = {placeholder}", (scan_id,))["total"]
        data_sql = f"""
            SELECT r.*, a_src.hostname as source_hostname, a_tgt.hostname as target_hostname
            FROM relationships r
            LEFT JOIN assets a_src ON r.source_asset_id = a_src.id
            LEFT JOIN assets a_tgt ON r.target_asset_id = a_tgt.id
            WHERE r.scan_id = {placeholder}
            ORDER BY r.id
            LIMIT {placeholder} OFFSET {placeholder}
        """
        data = self.query_all(data_sql, (scan_id, limit, offset))
        return {"total": total, "items": data}

    def get_cve_findings_paginated(self, scan_id: str, limit: int, offset: int) -> dict:
        placeholder = "%s" if self.is_postgres else "?"
        total = self.query_one(f"SELECT COUNT(*) as total FROM cve_findings WHERE scan_id = {placeholder}", (scan_id,))["total"]
        data_sql = f"""
            SELECT cv.*, a.hostname
            FROM cve_findings cv
            LEFT JOIN assets a ON cv.asset_id = a.id
            WHERE cv.scan_id = {placeholder}
            ORDER BY cv.cvss_score DESC NULLS LAST, cv.severity
            LIMIT {placeholder} OFFSET {placeholder}
        """
        data = self.query_all(data_sql, (scan_id, limit, offset))
        return {"total": total, "items": data}

    def get_scan_metrics(self, scan_id: str) -> dict:
        placeholder = "%s" if self.is_postgres else "?"
        return self.query_one(f"SELECT * FROM scan_metrics WHERE scan_id = {placeholder}", (scan_id,))

    def get_report_sections(self, scan_id: str, report_type: str) -> list[dict]:
        placeholder = "%s" if self.is_postgres else "?"
        return self.query_all(
            f"SELECT * FROM report_sections WHERE scan_id = {placeholder} AND report_type = {placeholder} ORDER BY section_index",
            (scan_id, report_type)
        )
