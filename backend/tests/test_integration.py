"""End-to-end checks over the scan endpoints and the background scan worker."""

import json
import logging
import shutil
import sys
import time

import pytest

import db
import scanner
from conftest import PLANTED_TOKEN

TRUFFLEHOG_BINARY = shutil.which("trufflehog")

START_BUDGET_SECONDS = 0.5
POLL_INTERVAL_SECONDS = 1
POLL_ATTEMPTS = 180

BINARY_MISSING_DETAIL = "trufflehog binary not found on PATH; install it or set TRUFFLEHOG_BIN"

BANNER_LINE = (
    "\U0001f437\U0001f511\U0001f437  TruffleHog. Unearth your secrets. "
    "\U0001f437\U0001f511\U0001f437"
)
MALFORMED_LINE = '{"DetectorName": "Github", "Verified": '
STDERR_MARKER = "stderr-marker-line"

WORKER_SCRIPT_TEMPLATE = """\
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
print(%(banner)s)
print("")
print(%(malformed)s)
print(%(finding)s)
print(%(marker)s, file=sys.stderr)
%(tail)s
"""


def _finding_line() -> str:
    """Returns one stdout line shaped like TruffleHog's git JSON output, carrying a synthetic secret
    assembled at runtime."""
    secret = "ghp_" + "x" * 36
    return json.dumps(
        {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "commit": "1caf0105f0b6b8b0b8a6c6d1b6ad7c9e0f2a3b4c",
                        "file": "config.env",
                        "email": "tests@example.invalid",
                        "repository": "file:///tmp/planted_repo",
                        "timestamp": "2026-09-16 18:19:04 +0000",
                        "line": 1,
                        "repository_local_path": "/tmp/trufflehog-1-2",
                    }
                }
            },
            "SourceID": 1,
            "SourceType": 16,
            "SourceName": "trufflehog - git",
            "DetectorType": 8,
            "DetectorName": "Github",
            "DecoderName": "PLAIN",
            "Verified": False,
            "VerificationFromCache": False,
            "Raw": secret,
            "RawV2": "",
            "Redacted": "",
            "ExtraData": {"token_type": "Personal Access Token (classic)"},
            "StructuredData": None,
            "SecretParts": {"key": secret},
        }
    )


def _worker_script(exit_code: int) -> str:
    """Returns Python source that prints a banner, an empty line, a malformed line and one finding to
    stdout plus one marker line to stderr, then exits with exit_code."""
    return WORKER_SCRIPT_TEMPLATE % {
        "banner": ascii(BANNER_LINE),
        "malformed": ascii(MALFORMED_LINE),
        "finding": ascii(_finding_line()),
        "marker": ascii(STDERR_MARKER),
        "tail": "" if exit_code == 0 else "sys.exit(%d)" % exit_code,
    }


def _stored_scan(scan_id: int) -> dict:
    """Returns the stored scan object with this id, failing the calling test when no row has it."""
    for row in db.list_scans():
        if row["id"] == scan_id:
            return row
    pytest.fail(f"no scan row with id {scan_id}")


def _served_scan(client, scan_id: int) -> dict:
    """Returns the scan object with this id from GET /api/scans, failing the test when it is absent."""
    response = client.get("/api/scans")
    assert response.status_code == 200, response.text
    for row in response.json():
        if row["id"] == scan_id:
            return row
    pytest.fail(f"GET /api/scans returned no row with id {scan_id}")


def _messages(caplog, level: int) -> list[str]:
    """Returns the formatted messages of the captured records at exactly this level."""
    return [record.getMessage() for record in caplog.records if record.levelno == level]


@pytest.mark.skipif(
    TRUFFLEHOG_BINARY is None,
    reason="the trufflehog binary is not installed on PATH",
)
def test_scan_planted_repo(client, planted_repo):
    """Scans a repository holding a planted token through the API and checks the scan row and the
    single finding served by the scan, per-scan findings and all-findings routes."""
    started = time.perf_counter()
    response = client.post("/api/scans", json={"target": planted_repo})
    elapsed = time.perf_counter() - started

    assert response.status_code == 202, response.text
    scan = response.json()
    scan_id = scan["id"]
    assert isinstance(scan_id, int) and scan_id > 0
    assert scan["status"] == "running"
    assert elapsed < START_BUDGET_SECONDS, f"POST /api/scans took {elapsed:.3f}s"

    row = _served_scan(client, scan_id)
    for _ in range(POLL_ATTEMPTS):
        if row["status"] != "running":
            break
        time.sleep(POLL_INTERVAL_SECONDS)
        row = _served_scan(client, scan_id)

    assert row["status"] == "completed", row
    assert row["exit_code"] == 0
    assert row["finding_count"] == 1

    scan_findings = client.get(f"/api/scans/{scan_id}/findings")
    assert scan_findings.status_code == 200, scan_findings.text
    rows = scan_findings.json()
    assert len(rows) == 1, rows

    finding = rows[0]
    assert finding["scan_id"] == scan_id
    assert finding["detector"] == "Github"
    assert finding["verified"] is False
    assert finding["file"] == "config.env"
    assert finding["line"] == 1
    assert finding["repository"] == planted_repo
    assert finding["commit_hash"]
    assert finding["redacted"]
    assert finding["redacted"] != PLANTED_TOKEN
    assert PLANTED_TOKEN not in json.dumps(finding)
    for key in ("Raw", "RawV2", "SecretParts"):
        assert key not in finding["raw"]

    all_findings = client.get("/api/findings")
    assert all_findings.status_code == 200, all_findings.text
    assert any(item["id"] == finding["id"] for item in all_findings.json())


def test_run_scan_skips_unparseable_lines(db_path, caplog):
    """Runs the scan worker against a stand-in subprocess to check line skipping, the exit-code
    mapping and that neither malformed stdout text nor stderr text reaches a log record."""
    caplog.set_level(logging.DEBUG)
    db.init_db()

    scan_id = db.create_scan("fake", "git")["id"]
    scanner.run_scan(scan_id, [sys.executable, "-c", _worker_script(0)])

    assert len(db.list_findings(scan_id)) == 1
    completed = _stored_scan(scan_id)
    assert completed["status"] == "completed"
    assert completed["exit_code"] == 0

    skips = [m for m in _messages(caplog, logging.WARNING) if "skipped unparseable stdout line" in m]
    assert len(skips) == 2, f"expected one warning per non-empty unparseable line, got {skips}"
    assert all(f"scan_id={scan_id}" in m for m in skips)
    malformed_skips = [m for m in skips if f"length={len(MALFORMED_LINE.strip())}" in m]
    assert len(malformed_skips) == 1, f"malformed line reported by length exactly once, got {skips}"
    assert MALFORMED_LINE not in caplog.text
    assert any("skipped empty stdout line" in m for m in _messages(caplog, logging.DEBUG))
    assert STDERR_MARKER not in caplog.text

    caplog.clear()
    failing_id = db.create_scan("fake", "git")["id"]
    scanner.run_scan(failing_id, [sys.executable, "-c", _worker_script(3)])

    failed = _stored_scan(failing_id)
    assert failed["status"] == "failed"
    assert failed["exit_code"] == 3
    assert len(db.list_findings(failing_id)) == 1
    assert any("exited with code 3" in m for m in _messages(caplog, logging.WARNING))


def test_unknown_scan_404(client):
    """Requests the findings of an id no scan row carries and expects a 404 with its detail."""
    response = client.get("/api/scans/999999/findings")

    assert response.status_code == 404, response.text
    assert response.json()["detail"] == "scan not found"


def test_missing_binary_503(client, monkeypatch):
    """Starts a scan while TRUFFLEHOG_BIN names a missing executable and expects a 503 that leaves
    the scans table untouched."""
    monkeypatch.setenv("TRUFFLEHOG_BIN", "trufflehog-does-not-exist")
    before = len(client.get("/api/scans").json())

    response = client.post("/api/scans", json={"target": "file:///tmp/unused"})

    assert response.status_code == 503, response.text
    assert response.json()["detail"] == BINARY_MISSING_DETAIL
    assert len(client.get("/api/scans").json()) == before
