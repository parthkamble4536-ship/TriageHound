-- schema.sql

CREATE TABLE evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Type of artifact: 'browser', 'usb', 'process', etc.
    artifact_type TEXT NOT NULL,
    -- Source module: e.g. 'Chrome', 'Registry'
    source TEXT,
    description TEXT,
    -- ISO format timestamp, feeds the timeline
    timestamp TEXT,
    -- JSON blob of full artifact details
    raw_data TEXT,
    -- SHA-256 hash of raw_data for integrity verification
    sha256_hash TEXT,
    -- When the tool collected this evidence
    collected_at TEXT,
    case_id TEXT
);

CREATE TABLE case_metadata (
    case_id TEXT PRIMARY KEY,
    investigator_name TEXT,
    case_name TEXT,
    start_time TEXT,
    target_system TEXT
);

CREATE TABLE file_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filepath TEXT,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    file_size INTEGER,
    hashed_at TEXT
);

-- ==============================================================================
-- TriageHound v2.0 Tables
-- ==============================================================================

CREATE TABLE entities (
    entity_id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL, -- e.g., 'Process', 'File', 'User', 'Network'
    name TEXT,
    path TEXT,
    timestamp TEXT,
    evidence_id INTEGER,       -- Foreign key back to evidence_items
    raw_attributes TEXT,       -- JSON blob of normalized properties
    FOREIGN KEY(evidence_id) REFERENCES evidence_items(id)
);

CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    severity TEXT,             -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    confidence_contribution INTEGER,
    timestamp TEXT
);

CREATE TABLE correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT,
    entity_id TEXT,
    evidence_id INTEGER,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY(entity_id) REFERENCES entities(entity_id),
    FOREIGN KEY(evidence_id) REFERENCES evidence_items(id)
);

CREATE TABLE confidence_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    score INTEGER,
    severity TEXT,
    calculated_at TEXT
);

CREATE TABLE anti_forensics (
    alert_id TEXT PRIMARY KEY,
    finding_id TEXT,
    description TEXT,
    detected_at TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE attack_chains (
    chain_id TEXT PRIMARY KEY,
    finding_id TEXT,
    next_finding_id TEXT,
    relationship TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY(next_finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT,
    action TEXT,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
);
