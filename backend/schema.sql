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

-- Organizations are explicit case-context labels, not inferred from evidence.
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(name) BETWEEN 1 AND 160),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_organizations (
    case_id TEXT PRIMARY KEY REFERENCES cases(id) ON DELETE RESTRICT,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    assigned_at TEXT NOT NULL
);

-- Correlations are reproducible outputs from deterministic, versioned rules.
CREATE TABLE IF NOT EXISTS correlations (
    id TEXT PRIMARY KEY CHECK (length(id) = 64),
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL CHECK (rule_version > 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds > 0),
    matched_entities_json TEXT NOT NULL,
    explanation TEXT NOT NULL,
    start_at TEXT NOT NULL,
    end_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (case_id, rule_id, id)
);
CREATE INDEX IF NOT EXISTS correlations_case_idx ON correlations(case_id, start_at, id);
CREATE TABLE IF NOT EXISTS correlation_events (
    correlation_id TEXT NOT NULL REFERENCES correlations(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal IN (0, 1)),
    event_record_id TEXT NOT NULL REFERENCES event_records(id) ON DELETE RESTRICT,
    PRIMARY KEY (correlation_id, ordinal),
    UNIQUE (correlation_id, event_record_id)
);

-- Analyst-authored investigation records reference existing evidence and
-- deterministic correlations. They do not assert causality or source truth.
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
    summary TEXT NOT NULL CHECK (length(summary) <= 4000),
    status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS investigations_case_updated_idx ON investigations(case_id, updated_at);
CREATE TABLE IF NOT EXISTS investigation_evidence (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL REFERENCES evidence_objects(id) ON DELETE RESTRICT,
    PRIMARY KEY (investigation_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS investigation_correlations (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE RESTRICT,
    correlation_id TEXT NOT NULL REFERENCES correlations(id) ON DELETE RESTRICT,
    PRIMARY KEY (investigation_id, correlation_id)
);

-- Rows are written only after the local-chain receipt and contract state have
-- passed independent JSON-RPC verification.
CREATE TABLE IF NOT EXISTS blockchain_anchors (
    batch_id TEXT PRIMARY KEY CHECK (length(batch_id) = 66),
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    merkle_root TEXT NOT NULL CHECK (length(merkle_root) = 66),
    leaf_count INTEGER NOT NULL CHECK (leaf_count > 0),
    tree_version TEXT NOT NULL,
    chain_id INTEGER NOT NULL CHECK (chain_id > 0),
    contract_address TEXT NOT NULL CHECK (length(contract_address) = 42),
    sender_address TEXT NOT NULL CHECK (length(sender_address) = 42),
    tx_hash TEXT NOT NULL UNIQUE CHECK (length(tx_hash) = 66),
    block_number INTEGER NOT NULL CHECK (block_number >= 0),
    block_hash TEXT NOT NULL CHECK (length(block_hash) = 66),
    anchored_at INTEGER NOT NULL CHECK (anchored_at >= 0),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS anchors_case_created_idx ON blockchain_anchors(case_id, created_at);

CREATE TABLE IF NOT EXISTS signing_keys (
    key_id TEXT PRIMARY KEY CHECK (length(key_id) = 64),
    public_key_der BLOB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    registered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS signature_checks (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    batch_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    tree_version TEXT NOT NULL,
    leaf_count INTEGER NOT NULL CHECK (leaf_count > 0),
    root_hash TEXT NOT NULL CHECK (length(root_hash) = 64),
    result TEXT NOT NULL,
    reason TEXT NOT NULL,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS signature_checks_case_idx ON signature_checks(case_id, checked_at);
CREATE TABLE IF NOT EXISTS proof_checks (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE RESTRICT,
    event_id TEXT NOT NULL,
    expected_root TEXT NOT NULL,
    valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
    reason TEXT NOT NULL,
    proof_json TEXT NOT NULL,
    checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS proof_checks_case_idx ON proof_checks(case_id, checked_at);
CREATE TABLE IF NOT EXISTS expected_event_manifests (
    case_id TEXT PRIMARY KEY REFERENCES cases(id) ON DELETE RESTRICT,
    expected_event_ids_json TEXT NOT NULL,
    manifest_id TEXT NOT NULL UNIQUE,
    updated_at TEXT NOT NULL
);
