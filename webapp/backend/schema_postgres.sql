-- 0xCrawller V10 production PostgreSQL schema.
-- The backend also creates these tables automatically, but keeping the
-- schema here gives us an explicit migration/deployment artifact.

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
    cloudinary_url TEXT,
    cloudinary_public_id TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(scan_id, relative_path)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_scan_id
    ON artifacts(scan_id, kind);
