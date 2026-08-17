from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row


TABLES = ("scans", "steps", "logs", "artifacts")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Copy the existing 0xCrawller SQLite database to PostgreSQL."
    )
    parser.add_argument(
        "--sqlite",
        default="data/crawller_web.db",
        help="Path to the existing SQLite database.",
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("CRAWLLER_DATABASE_URL"),
        help="Supabase/PostgreSQL connection string. "
             "Can also be supplied through CRAWLLER_DATABASE_URL.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create a local SQLite backup before migration.",
    )
    return parser.parse_args()


def require_database_url(value: str | None) -> str:
    if not value:
        raise SystemExit(
            "ERROR: CRAWLLER_DATABASE_URL is not set. "
            "Set it to the Supabase PostgreSQL connection string."
        )
    return value.strip()


def backup_sqlite(source: Path) -> Path:
    backup = source.with_suffix(source.suffix + ".pre-postgres.bak")
    shutil.copy2(source, backup)
    return backup


def sqlite_rows(connection: sqlite3.Connection, table: str):
    connection.row_factory = sqlite3.Row
    return connection.execute(
        f"SELECT * FROM {table}"
    ).fetchall()


def create_schema(connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            current_step TEXT,
            progress INTEGER NOT NULL DEFAULT 0,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            error_message TEXT,
            run_dir TEXT,
            cancel_requested BOOLEAN NOT NULL DEFAULT FALSE
        );

        CREATE TABLE IF NOT EXISTS steps (
            id BIGSERIAL PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
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
            id BIGSERIAL PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            step_key TEXT,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_logs_scan_id
            ON logs(scan_id, id);

        CREATE TABLE IF NOT EXISTS artifacts (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            step_key TEXT,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            mime_type TEXT,
            size_bytes BIGINT NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            UNIQUE(scan_id, relative_path)
        );

        CREATE INDEX IF NOT EXISTS idx_artifacts_scan_id
            ON artifacts(scan_id, kind);
        """
    )


def migrate(sqlite_path: Path, database_url: str, make_backup: bool) -> None:
    if not sqlite_path.is_file():
        raise SystemExit(f"ERROR: SQLite database not found: {sqlite_path}")

    if make_backup:
        backup = backup_sqlite(sqlite_path)
        print(f"SQLite backup: {backup}")

    sqlite = sqlite3.connect(sqlite_path)
    sqlite.row_factory = sqlite3.Row

    counts = {}
    for table in TABLES:
        counts[table] = sqlite.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]

    print("SQLite source counts:")
    for table in TABLES:
        print(f"  {table}: {counts[table]}")

    with psycopg.connect(
        database_url,
        row_factory=dict_row,
        prepare_threshold=None,
    ) as pg:
        create_schema(pg)

        # Preserve existing primary IDs. This means frontend log pagination
        # and artifact URLs remain stable after migration.
        for row in sqlite_rows(sqlite, "scans"):
            pg.execute(
                """
                INSERT INTO scans(
                    id,target,status,current_step,progress,started_at,
                    completed_at,error_message,run_dir,cancel_requested
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(id) DO UPDATE SET
                    target=EXCLUDED.target,
                    status=EXCLUDED.status,
                    current_step=EXCLUDED.current_step,
                    progress=EXCLUDED.progress,
                    started_at=EXCLUDED.started_at,
                    completed_at=EXCLUDED.completed_at,
                    error_message=EXCLUDED.error_message,
                    run_dir=EXCLUDED.run_dir,
                    cancel_requested=EXCLUDED.cancel_requested
                """,
                
(
    row[0],
    row[1],
    row[2],
    row[3],
    row[4],
    row[5],
    row[6],
    row[7],
    row[8],
    bool(row[9]),
),            )

        for row in sqlite_rows(sqlite, "steps"):
            pg.execute(
                """
                INSERT INTO steps(
                    id,scan_id,step_key,name,position,status,progress,
                    started_at,completed_at,exit_code,message
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(id) DO UPDATE SET
                    scan_id=EXCLUDED.scan_id,
                    step_key=EXCLUDED.step_key,
                    name=EXCLUDED.name,
                    position=EXCLUDED.position,
                    status=EXCLUDED.status,
                    progress=EXCLUDED.progress,
                    started_at=EXCLUDED.started_at,
                    completed_at=EXCLUDED.completed_at,
                    exit_code=EXCLUDED.exit_code,
                    message=EXCLUDED.message
                """,
                tuple(row),
            )

        for row in sqlite_rows(sqlite, "logs"):
            pg.execute(
                """
                INSERT INTO logs(
                    id,scan_id,step_key,level,message,created_at
                )
                VALUES(%s,%s,%s,%s,%s,%s)
                ON CONFLICT(id) DO UPDATE SET
                    scan_id=EXCLUDED.scan_id,
                    step_key=EXCLUDED.step_key,
                    level=EXCLUDED.level,
                    message=EXCLUDED.message,
                    created_at=EXCLUDED.created_at
                """,
                tuple(row),
            )

        for row in sqlite_rows(sqlite, "artifacts"):
            pg.execute(
                """
                INSERT INTO artifacts(
                    id,scan_id,step_key,kind,name,relative_path,
                    mime_type,size_bytes,created_at
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(id) DO UPDATE SET
                    scan_id=EXCLUDED.scan_id,
                    step_key=EXCLUDED.step_key,
                    kind=EXCLUDED.kind,
                    name=EXCLUDED.name,
                    relative_path=EXCLUDED.relative_path,
                    mime_type=EXCLUDED.mime_type,
                    size_bytes=EXCLUDED.size_bytes,
                    created_at=EXCLUDED.created_at
                """,
                tuple(row),
            )

        # Keep BIGSERIAL generators above the migrated explicit IDs.
        pg.execute(
            """
            SELECT setval(
                pg_get_serial_sequence('steps','id'),
                COALESCE((SELECT MAX(id) FROM steps), 1),
                (SELECT COUNT(*) > 0 FROM steps)
            )
            """
        )
        pg.execute(
            """
            SELECT setval(
                pg_get_serial_sequence('logs','id'),
                COALESCE((SELECT MAX(id) FROM logs), 1),
                (SELECT COUNT(*) > 0 FROM logs)
            )
            """
        )

        verification = {}
        for table in TABLES:
            verification[table] = pg.execute(
                f"SELECT COUNT(*) AS count FROM {table}"
            ).fetchone()["count"]

        print("PostgreSQL counts:")
        for table in TABLES:
            print(f"  {table}: {verification[table]}")

        # PostgreSQL may already contain records created before migration.
    # Verify that all SQLite records are present, while allowing extra PostgreSQL records.
    mismatches = [
        table
        for table in TABLES
        if int(verification[table]) < int(counts[table])
    ]

    if mismatches:
        raise RuntimeError(
            "Migration verification failed: PostgreSQL is missing records from: "
            + ", ".join(mismatches)
        )

    print("MIGRATION VERIFIED: all SQLite records are present in PostgreSQL.")

    sqlite.close()


def main() -> int:
    args = parse_args()
    database_url = require_database_url(args.database_url)

    migrate(
        Path(args.sqlite).resolve(),
        database_url,
        make_backup=not args.no_backup,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
