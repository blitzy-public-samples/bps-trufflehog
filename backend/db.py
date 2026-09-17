"""SQLite persistence for scans and findings."""

import json
import logging
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'git',
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    exit_code INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    detector TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    file TEXT,
    line INTEGER,
    repository TEXT,
    commit_hash TEXT,
    redacted TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
"""

SCAN_SELECT = (
    "SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) "
    "AS finding_count FROM scans s ORDER BY s.id DESC"
)

FINDING_INSERT = (
    "INSERT INTO findings (scan_id, detector, verified, file, line, repository, "
    "commit_hash, redacted, raw_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def utc_now() -> str:
    """Returns the current UTC time as ISO-8601 text with second precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_path() -> Path:
    """Returns the database file path: TRUFFLEHOG_DB_PATH if set, else trufflehog.db beside this module."""
    override = os.environ.get("TRUFFLEHOG_DB_PATH")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent / "trufflehog.db"


def connect() -> sqlite3.Connection:
    """Returns a new connection to db_path() in WAL mode with foreign keys on and row access by name."""
    conn = sqlite3.connect(db_path(), timeout=30)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
    except sqlite3.Error:
        conn.close()
        raise
    return conn


def recover_orphans(conn: sqlite3.Connection) -> int:
    """Marks scans left in 'running' as failed on the caller's connection; returns the row count."""
    cursor = conn.execute(
        "UPDATE scans SET status = 'failed', finished_at = ? WHERE status = 'running'",
        (utc_now(),),
    )
    swept = max(cursor.rowcount, 0)
    if swept:
        logger.info("marked %d orphaned scan(s) as failed", swept)
    return swept


def init_db() -> None:
    """Creates the schema if absent, sweeps orphaned running scans and commits."""
    with closing(connect()) as conn:
        conn.executescript(SCHEMA)
        recover_orphans(conn)
        conn.commit()


def create_scan(target: str, source: str) -> dict:
    """Inserts a running scan for an already-redacted target; returns the new scan object."""
    started_at = utc_now()
    with closing(connect()) as conn:
        cursor = conn.execute(
            "INSERT INTO scans (target, source, status, started_at) VALUES (?, ?, 'running', ?)",
            (target, source, started_at),
        )
        conn.commit()
        scan_id = cursor.lastrowid
    return {
        "id": scan_id,
        "target": target,
        "source": source,
        "status": "running",
        "exit_code": None,
        "started_at": started_at,
        "finished_at": None,
        "finding_count": 0,
    }


def finish_scan(scan_id: int, status: str, exit_code: int | None) -> None:
    """Sets a scan's terminal status, exit code (may be None) and finish timestamp."""
    with closing(connect()) as conn:
        conn.execute(
            "UPDATE scans SET status = ?, exit_code = ?, finished_at = ? WHERE id = ?",
            (status, exit_code, utc_now(), scan_id),
        )
        conn.commit()


def list_scans() -> list[dict]:
    """Returns every scan object, each with its finding_count, newest id first."""
    with closing(connect()) as conn:
        rows = conn.execute(SCAN_SELECT).fetchall()
    return [dict(row) for row in rows]


def scan_exists(scan_id: int) -> bool:
    """Returns whether a scan row with this id exists."""
    with closing(connect()) as conn:
        row = conn.execute("SELECT 1 FROM scans WHERE id = ? LIMIT 1", (scan_id,)).fetchone()
    return row is not None


def list_findings(scan_id: int | None = None) -> list[dict]:
    """Returns finding objects, newest id first, for one scan when scan_id is given or for all scans."""
    query = "SELECT * FROM findings"
    params: tuple = ()
    if scan_id is not None:
        query += " WHERE scan_id = ?"
        params = (scan_id,)
    query += " ORDER BY id DESC"
    with closing(connect()) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_finding(row) for row in rows]


def insert_finding(conn: sqlite3.Connection, scan_id: int, finding: dict) -> None:
    """Inserts one mapped finding on the caller's connection and commits it immediately."""
    conn.execute(
        FINDING_INSERT,
        (
            scan_id,
            finding["detector"],
            int(bool(finding["verified"])),
            finding.get("file"),
            finding.get("line"),
            finding.get("repository"),
            finding.get("commit_hash"),
            finding["redacted"],
            finding["raw_json"],
            utc_now(),
        ),
    )
    conn.commit()


def _row_to_finding(row: sqlite3.Row) -> dict:
    """Converts a findings row into a finding object with a bool verified and raw_json parsed as raw."""
    try:
        raw = json.loads(row["raw_json"])
    except (json.JSONDecodeError, TypeError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    return {
        "id": row["id"],
        "scan_id": row["scan_id"],
        "detector": row["detector"],
        "verified": bool(row["verified"]),
        "file": row["file"],
        "line": row["line"],
        "repository": row["repository"],
        "commit_hash": row["commit_hash"],
        "redacted": row["redacted"],
        "created_at": row["created_at"],
        "raw": raw,
    }
