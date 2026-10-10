PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    created_at TEXT NOT NULL
);

-- Raw source evidence is stored as exact bytes in content-addressed files. This table
-- stores metadata only; normalized event fields live separately in event_records.
CREATE TABLE IF NOT EXISTS evidence_objects (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    original_filename TEXT NOT NULL CHECK (length(original_filename) BETWEEN 1 AND 255),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 127),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    storage_key TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    UNIQUE (id, case_id)
);
CREATE INDEX IF NOT EXISTS evidence_case_created_idx ON evidence_objects(case_id, ingested_at);
CREATE INDEX IF NOT EXISTS evidence_sha256_idx ON evidence_objects(sha256);

CREATE TABLE IF NOT EXISTS event_records (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    canonical_sha256 TEXT NOT NULL CHECK (length(canonical_sha256) = 64),
    FOREIGN KEY (evidence_id, case_id) REFERENCES evidence_objects(id, case_id) ON DELETE RESTRICT,
    UNIQUE (case_id, event_id)
);
CREATE INDEX IF NOT EXISTS events_case_time_idx ON event_records(case_id, occurred_at);
CREATE INDEX IF NOT EXISTS events_source_type_idx ON event_records(source_id, event_type);
