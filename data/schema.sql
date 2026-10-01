-- CyberTrace AI — Reference DDL
-- Tables are created by seed_database.py; this file is for reference only.

CREATE TABLE IF NOT EXISTS auth_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      TEXT    NOT NULL,
    ip_address   TEXT    NOT NULL,
    timestamp    TEXT    NOT NULL,          -- ISO-8601 UTC
    status       TEXT    NOT NULL CHECK(status IN ('success', 'failed')),
    location     TEXT,
    device_id    TEXT
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           TEXT    NOT NULL,
    device_id         TEXT    NOT NULL,
    timestamp         TEXT    NOT NULL,    -- ISO-8601 UTC
    action_type       TEXT    NOT NULL,    -- FILE_READ | FILE_DOWNLOAD | FILE_UPLOAD
    file_name         TEXT,
    bytes_transferred INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS containment_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    action_type  TEXT NOT NULL,           -- BLOCK_IP | REVOKE_TOKEN
    target       TEXT NOT NULL,
    executed_by  TEXT DEFAULT 'analyst',
    status       TEXT DEFAULT 'executed'
);

CREATE TABLE IF NOT EXISTS suspended_users (
    user_id      TEXT PRIMARY KEY,
    suspended_at TEXT NOT NULL,
    reason       TEXT
);
