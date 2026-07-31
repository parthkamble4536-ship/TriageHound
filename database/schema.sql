-- schema.sql

CREATE TABLE evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_type TEXT NOT NULL,      -- 'browser', 'usb', 'process', etc.
    source TEXT,                       -- e.g. 'Chrome', 'Registry'
    description TEXT,
    timestamp TEXT,                    -- ISO format, feeds the timeline
    raw_data TEXT,                     -- JSON blob of full details
    sha256_hash TEXT,                   -- hash of raw_data for integrity
    collected_at TEXT,                 -- when the tool collected it
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
