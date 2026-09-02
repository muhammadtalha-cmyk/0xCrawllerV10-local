-- 0xCrawller V10 production PostgreSQL schema.

-- Core Webapp Tables
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

CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON logs(scan_id, id);

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

CREATE INDEX IF NOT EXISTS idx_artifacts_scan_id ON artifacts(scan_id, kind);


-- Extracted Data Entities for UI

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    fqdn TEXT,
    asset_type TEXT,
    ip_address TEXT,
    status TEXT,
    source TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);

CREATE TABLE IF NOT EXISTS dns_records (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    record_type TEXT,
    value TEXT,
    ttl INTEGER,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_scan_id ON dns_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_dns_asset_id ON dns_records(asset_id);

CREATE TABLE IF NOT EXISTS ports (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    port INTEGER,
    protocol TEXT,
    state TEXT,
    service TEXT,
    banner TEXT
);
CREATE INDEX IF NOT EXISTS idx_ports_scan_id ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_asset_id ON ports(asset_id);

CREATE TABLE IF NOT EXISTS technologies (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT,
    version TEXT,
    confidence TEXT,
    detection_source TEXT,
    evidence JSONB DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_tech_scan_id ON technologies(scan_id);
CREATE INDEX IF NOT EXISTS idx_tech_asset_id ON technologies(asset_id);

CREATE TABLE IF NOT EXISTS endpoints (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    url TEXT,
    path TEXT,
    method TEXT,
    status_code INTEGER,
    content_type TEXT,
    source TEXT
);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_asset_id ON endpoints(asset_id);

CREATE TABLE IF NOT EXISTS screenshots (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    url TEXT,
    image_path TEXT,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_screenshots_scan_id ON screenshots(scan_id);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    finding_type TEXT,
    severity TEXT,
    confidence TEXT,
    description TEXT,
    status TEXT DEFAULT 'needs_validation'
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);

CREATE TABLE IF NOT EXISTS evidence (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    evidence_type TEXT,
    source TEXT,
    content JSONB
);

-- New tables for massive JSONs and Markdown reports

CREATE TABLE IF NOT EXISTS relationships (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_relationships_scan_id ON relationships(scan_id);
CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships(target_asset_id);

CREATE TABLE IF NOT EXISTS report_sections (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    report_type TEXT NOT NULL, -- e.g., 'combined_intelligence', 'technology_enrichment'
    section_index INTEGER NOT NULL,
    header TEXT,
    level INTEGER,
    content TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_report_sections_scan_id ON report_sections(scan_id, report_type, section_index);

CREATE TABLE IF NOT EXISTS scan_metrics (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    total_assets INTEGER DEFAULT 0,
    total_services INTEGER DEFAULT 0,
    total_endpoints INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    total_technologies INTEGER DEFAULT 0,
    severity_critical INTEGER DEFAULT 0,
    severity_high INTEGER DEFAULT 0,
    severity_medium INTEGER DEFAULT 0,
    severity_low INTEGER DEFAULT 0,
    severity_info INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
