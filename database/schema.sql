CREATE TABLE IF NOT EXISTS scan_runs (
 id SERIAL PRIMARY KEY,
 target TEXT NOT NULL,
 pipeline_version TEXT,
 started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 status TEXT
);

CREATE TABLE IF NOT EXISTS assets (
 id SERIAL PRIMARY KEY,
 scan_id INTEGER REFERENCES scan_runs(id),
 hostname TEXT,
 fqdn TEXT,
 asset_type TEXT,
 ip_address TEXT,
 status TEXT,
 source TEXT,
 metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS dns_records (
 id SERIAL PRIMARY KEY,
 asset_id INTEGER REFERENCES assets(id),
 record_type TEXT,
 value TEXT,
 ttl INTEGER,
 source TEXT
);

CREATE TABLE IF NOT EXISTS ports (
 id SERIAL PRIMARY KEY,
 asset_id INTEGER REFERENCES assets(id),
 port INTEGER,
 protocol TEXT,
 state TEXT,
 service TEXT,
 banner TEXT
);

CREATE TABLE IF NOT EXISTS technologies (
 id SERIAL PRIMARY KEY,
 asset_id INTEGER REFERENCES assets(id),
 name TEXT,
 category TEXT,
 version TEXT,
 confidence TEXT,
 detection_source TEXT,
 evidence JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS endpoints (
 id SERIAL PRIMARY KEY,
 asset_id INTEGER REFERENCES assets(id),
 url TEXT,
 path TEXT,
 method TEXT,
 status_code INTEGER,
 content_type TEXT,
 source TEXT
);

CREATE TABLE IF NOT EXISTS screenshots (
 id SERIAL PRIMARY KEY,
 asset_id INTEGER REFERENCES assets(id),
 url TEXT,
 image_path TEXT,
 captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence (
 id SERIAL PRIMARY KEY,
 asset_id INTEGER REFERENCES assets(id),
 evidence_type TEXT,
 source TEXT,
 content JSONB
);

CREATE TABLE IF NOT EXISTS findings (
 id SERIAL PRIMARY KEY,
 asset_id INTEGER REFERENCES assets(id),
 finding_type TEXT,
 severity TEXT,
 confidence TEXT,
 description TEXT,
 status TEXT DEFAULT 'needs_validation'
);
