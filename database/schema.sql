CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(512) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'ANALYST'
);

CREATE TABLE IF NOT EXISTS datasets (
    id INTEGER PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    mime_type VARCHAR(150) NOT NULL,
    uploader VARCHAR(255) NOT NULL,
    integrity_status VARCHAR(50) NOT NULL DEFAULT 'VERIFIED',
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS model_artifacts (
    id INTEGER PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    uploader VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'TRUSTED',
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS inference_records (
    id INTEGER PRIMARY KEY,
    input_sha256 VARCHAR(64) NOT NULL,
    model_sha256 VARCHAR(64) NOT NULL,
    config_sha256 VARCHAR(64) NOT NULL,
    output_sha256 VARCHAR(64) NOT NULL,
    provenance_sha256 VARCHAR(64) NOT NULL,
    signature VARCHAR(64) NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'VERIFIED',
    actor VARCHAR(255) NOT NULL DEFAULT 'web-user',
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    details TEXT NOT NULL,
    event_hash VARCHAR(64) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);
