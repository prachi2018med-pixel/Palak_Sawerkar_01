"""
CyberTrace AI — SQLite connection helper.
"""
import sqlite3
from pathlib import Path
from backend.config import DB_PATH, DATA_DIR


def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with Row factory enabled."""
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Create all tables if they do not exist."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      TEXT    NOT NULL,
            ip_address   TEXT    NOT NULL,
            timestamp    TEXT    NOT NULL,
            status       TEXT    NOT NULL CHECK(status IN ('success', 'failed')),
            location     TEXT,
            device_id    TEXT
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id           TEXT    NOT NULL,
            device_id         TEXT    NOT NULL,
            timestamp         TEXT    NOT NULL,
            action_type       TEXT    NOT NULL,
            file_name         TEXT,
            bytes_transferred INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS containment_actions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            action_type  TEXT NOT NULL,
            target       TEXT NOT NULL,
            executed_by  TEXT DEFAULT 'analyst',
            status       TEXT DEFAULT 'executed'
        );

        CREATE TABLE IF NOT EXISTS suspended_users (
            user_id      TEXT PRIMARY KEY,
            suspended_at TEXT NOT NULL,
            reason       TEXT
        );
    """)
    conn.commit()
    conn.close()
