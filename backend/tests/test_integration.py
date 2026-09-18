"""End-to-end checks over the scan endpoints and the background scan worker."""

import json
import logging
import shutil
import sys
import threading
import time
from pathlib import Path

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

STREAM_FIRST_FILE = "first.env"
STREAM_SECOND_FILE = "second.env"
STREAM_TIMEOUT_SECONDS = 30
STREAM_POLL_SECONDS = 0.01
CHILD_WAIT_SECONDS = 60
CHILD_STUCK_EXIT_CODE = 97

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

STREAM_SCRIPT_TEMPLATE = """\
import os
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")
print(%(first)s, flush=True)
deadline = time.monotonic() + %(wait)s
while not os.path.exists(%(release)s):
    if time.monotonic() > deadline:
        sys.exit(%(stuck)s)
    time.sleep(%(poll)s)
print(%(second)s, flush=True)
"""


def _finding_line(file: str = "config.env") -> str:
    """Returns one stdout line shaped like TruffleHog's git JSON output for this file path, carrying a
    synthetic secret assembled at runtime."""
    secret = "ghp_" + "x" * 36
    return json.dumps(
        {
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "commit": "1caf0105f0b6b8b0b8a6c6d1b6ad7c9e0f2a3b4c",
                        "file": file,
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


def _stream_script(release_path: Path) -> str:
    """Returns Python source that prints and flushes one finding, waits for release_path to appear
    before printing and flushing a second finding, then exits 0."""
    return STREAM_SCRIPT_TEMPLATE % {
        "first": ascii(_finding_line(STREAM_FIRST_FILE)),
        "second": ascii(_finding_line(STREAM_SECOND_FILE)),
        "release": ascii(str(release_path)),
        "wait": CHILD_WAIT_SECONDS,
        "stuck": CHILD_STUCK_EXIT_CODE,
        "poll": STREAM_POLL_SECONDS,
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


def _await_findings(scan_id: int, count: int) -> list[dict]:
    """Returns this scan's stored findings once at least count of them are queryable, failing the
    calling test when they do not appear within the streaming budget."""
    deadline = time.monotonic() + STREAM_TIMEOUT_SECONDS
    rows = db.list_findings(scan_id)
    while len(rows) < count and time.monotonic() < deadline:
        time.sleep(STREAM_POLL_SECONDS)
        rows = db.list_findings(scan_id)
    if len(rows) < count:
        pytest.fail(
            f"scan {scan_id} exposed {len(rows)} finding(s) within {STREAM_TIMEOUT_SECONDS}s, "
            f"expected at least {count}"
        )
    return rows


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
    empty_skips = [m for m in _messages(caplog, logging.DEBUG) if "skipped empty stdout line" in m]
    assert len(empty_skips) == 1, f"expected exactly one empty-line debug record, got {empty_skips}"
    assert f"scan_id={scan_id}" in empty_skips[0]
    assert STDERR_MARKER not in caplog.text

    caplog.clear()
    failing_id = db.create_scan("fake", "git")["id"]
    scanner.run_scan(failing_id, [sys.executable, "-c", _worker_script(3)])

    failed = _stored_scan(failing_id)
    assert failed["status"] == "failed"
    assert failed["exit_code"] == 3
    assert len(db.list_findings(failing_id)) == 1
    assert any("exited with code 3" in m for m in _messages(caplog, logging.WARNING))


def test_run_scan_commits_findings_while_running(db_path, tmp_path):
    """Drives the scan worker on its own thread against a child that emits one finding, blocks, then
    emits a second, and checks each finding is stored before the scan reaches a terminal status."""
    db.init_db()
    release = tmp_path / "release-second-finding"
    scan_id = db.create_scan("fake", "git")["id"]

    worker = threading.Thread(
        target=scanner.run_scan,
        args=(scan_id, [sys.executable, "-c", _stream_script(release)]),
        name=f"test-scan-{scan_id}",
        daemon=True,
    )
    worker.start()
    try:
        streamed = _await_findings(scan_id, 1)
        assert [row["file"] for row in streamed] == [STREAM_FIRST_FILE]

        mid_scan = _stored_scan(scan_id)
        assert mid_scan["status"] == "running", mid_scan
        assert mid_scan["exit_code"] is None, mid_scan
        assert mid_scan["finished_at"] is None, mid_scan
        assert mid_scan["finding_count"] == 1, mid_scan
    finally:
        release.write_text("release", encoding="utf-8")

    worker.join(timeout=STREAM_TIMEOUT_SECONDS)
    assert not worker.is_alive(), f"the scan worker ran past {STREAM_TIMEOUT_SECONDS}s"

    rows = db.list_findings(scan_id)
    assert sorted(row["file"] for row in rows) == [STREAM_FIRST_FILE, STREAM_SECOND_FILE]

    finished = _stored_scan(scan_id)
    assert finished["status"] == "completed", finished
    assert finished["exit_code"] == 0
    assert finished["finding_count"] == 2


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


GRANDCHILD_LIFETIME_SECONDS = 2.0
TINY_JOIN_TIMEOUT_SECONDS = 0.05

LINGERING_WORKER_TEMPLATE = """\
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
print(%(finding)s)
print(%(marker)s, file=sys.stderr)
sys.stdout.flush()
sys.stderr.flush()
subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(%(sleep).1f)"],
    stdout=subprocess.DEVNULL,
)
"""


def _lingering_worker_script() -> str:
    """Returns Python source that prints one finding to stdout and one line to stderr, leaves a
    grandchild holding the inherited stderr pipe for GRANDCHILD_LIFETIME_SECONDS, then exits 0."""
    return LINGERING_WORKER_TEMPLATE % {
        "finding": ascii(_finding_line()),
        "marker": ascii(STDERR_MARKER),
        "sleep": GRANDCHILD_LIFETIME_SECONDS,
    }


def test_run_scan_finalizes_and_guards_the_terminal_update(db_path):
    """Checks the worker's single finalization path: a finding insert that fails still records a
    terminal status, and a terminal update that fails once is retried."""
    import sqlite3

    db.init_db()
    stuck_id = db.create_scan("fake", "git")["id"]

    def refuse_insert(conn, scan_id, finding):
        """Fails every insert the way a locked database does."""
        raise sqlite3.OperationalError("database is locked")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(db, "insert_finding", refuse_insert)
        with pytest.raises(sqlite3.OperationalError):
            scanner.run_scan(stuck_id, [sys.executable, "-c", _worker_script(0)])

    stuck = _stored_scan(stuck_id)
    assert stuck["status"] == "failed", "a failed insert must not leave the row running"
    assert stuck["exit_code"] is None
    assert db.list_findings(stuck_id) == []

    retried_id = db.create_scan("fake", "git")["id"]
    real_finish = db.finish_scan
    finish_calls = []

    def flaky_finish(scan_id, status, exit_code):
        """Fails the first terminal update and delegates every later one to db.finish_scan."""
        finish_calls.append((scan_id, status, exit_code))
        if len(finish_calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        real_finish(scan_id, status, exit_code)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(db, "finish_scan", flaky_finish)
        patch.setattr(scanner, "TERMINAL_RETRY_DELAY", 0)
        scanner.run_scan(retried_id, [sys.executable, "-c", _worker_script(0)])

    assert len(finish_calls) == 2, f"the terminal update is attempted twice, got {finish_calls}"
    retried = _stored_scan(retried_id)
    assert retried["status"] == "completed"
    assert retried["exit_code"] == 0


def test_start_scan_marks_the_scan_failed_when_the_worker_thread_cannot_start(client, monkeypatch):
    """Starts a scan whose worker thread refuses to start and expects a controlled 503 plus a scan
    row marked failed with no exit code rather than one stuck in 'running'."""
    import types

    import main

    constructed = []

    class RefusingThread:
        """Stands in for threading.Thread: records its construction and refuses to start."""

        def __init__(self, *args, **kwargs):
            """Records the keyword arguments start_scan constructed this thread with."""
            constructed.append(kwargs)

        def start(self):
            """Raises the error threading.Thread raises when the host cannot create a thread."""
            raise RuntimeError("can't start new thread")

    monkeypatch.setenv("TRUFFLEHOG_BIN", sys.executable)
    monkeypatch.setattr(scanner, "threading", types.SimpleNamespace(Thread=RefusingThread))
    before = {row["id"] for row in client.get("/api/scans").json()}

    response = client.post("/api/scans", json={"target": "file:///tmp/unused"})

    assert response.status_code == 503, response.text
    assert response.json()["detail"] == main.WORKER_START_UNAVAILABLE_DETAIL
    assert [kwargs["target"] for kwargs in constructed] == [scanner.run_scan]
    created = [row for row in client.get("/api/scans").json() if row["id"] not in before]
    assert len(created) == 1, created
    assert created[0]["status"] == "failed", "a worker-less row must not stay running"
    assert created[0]["exit_code"] is None


def test_completion_record_reports_an_unfinished_stderr_drain(db_path, caplog):
    """Runs a worker that leaves a grandchild holding the stderr pipe and checks that finalization
    is neither blocked nor stalled and that the completion record qualifies the drained count."""
    caplog.set_level(logging.INFO)
    db.init_db()
    scan_id = db.create_scan("fake", "git")["id"]

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(scanner, "STDERR_JOIN_TIMEOUT", TINY_JOIN_TIMEOUT_SECONDS)
        started = time.perf_counter()
        scanner.run_scan(scan_id, [sys.executable, "-c", _lingering_worker_script()])
        elapsed = time.perf_counter() - started

    completed = _stored_scan(scan_id)
    assert completed["status"] == "completed"
    assert completed["exit_code"] == 0
    assert elapsed < GRANDCHILD_LIFETIME_SECONDS / 2, f"the worker waited {elapsed:.3f}s on stderr"

    summaries = [m for m in _messages(caplog, logging.INFO) if "scan finished" in m]
    assert len(summaries) == 1, summaries
    drained = summaries[0].split("stderr_lines_drained=")[1].rstrip(")")
    assert drained.endswith("+"), f"an unfinished drain must not read as a final count: {drained}"
    assert STDERR_MARKER not in caplog.text


DRAIN_START_FAILURE = "refusing to start the stderr drain"


def test_run_scan_finalizes_when_the_stderr_drain_cannot_start(db_path, caplog):
    """Refuses to start the stderr drain and checks that the worker still records a terminal status
    and propagates the original failure rather than an error from joining an unstarted thread."""
    import threading
    import types

    caplog.set_level(logging.INFO)
    db.init_db()
    scan_id = db.create_scan("fake", "git")["id"]

    class UnstartableThread(threading.Thread):
        """Stands in for the drain thread: constructs normally and refuses to start."""

        def start(self):
            """Raises the error threading.Thread raises when the host cannot create a thread."""
            raise RuntimeError(DRAIN_START_FAILURE)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(scanner, "threading", types.SimpleNamespace(Thread=UnstartableThread))
        with pytest.raises(RuntimeError, match=DRAIN_START_FAILURE):
            scanner.run_scan(scan_id, [sys.executable, "-c", _worker_script(0)])

    row = _stored_scan(scan_id)
    assert row["status"] == "failed", "a drain that cannot start must not leave the row running"
    assert row["exit_code"] is None

    summaries = [m for m in _messages(caplog, logging.INFO) if "scan finished" in m]
    assert len(summaries) == 1, summaries
    assert "stderr_lines_drained=0" in summaries[0]
    assert STDERR_MARKER not in caplog.text
