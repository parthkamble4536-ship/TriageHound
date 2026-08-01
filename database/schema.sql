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
