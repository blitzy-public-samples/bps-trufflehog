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
import main
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
    """Returns one TruffleHog-shaped JSON line for file, with its synthetic secret split across
    source tokens."""
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


@pytest.mark.regression
def test_run_scan_commits_findings_while_running(db_path, tmp_path):
    """Runs a two-finding child and checks partial results are visible while the scan is running
    and both findings are stored at completion."""
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


@pytest.mark.regression
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


@pytest.mark.regression
def test_start_scan_marks_the_scan_failed_when_the_worker_thread_cannot_start(client, monkeypatch):
    """Starts a scan whose worker thread refuses to start and expects a controlled 503 plus a scan
    row marked failed with no exit code rather than one stuck in 'running'."""
    import types

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


@pytest.mark.regression
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


@pytest.mark.regression
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


# Split across source tokens like conftest's planted token, so no line here reads as a credential.
MALFORMED_TARGET_CREDENTIAL = "n0t-a-real" + "-target-token"
MALFORMED_CREDENTIAL_TARGETS = (
    (f"https://user:{MALFORMED_TARGET_CREDENTIAL}@[bad/repo.git", "https://***@[bad/repo.git"),
    (f"https:///user:{MALFORMED_TARGET_CREDENTIAL}@[bad/repo.git", "https:///***@[bad/repo.git"),
    (f"user:{MALFORMED_TARGET_CREDENTIAL}@host:org//repo.git", "***@host:org//repo.git"),
)


def _settled_scan(client, scan_id: int) -> dict:
    """Returns this scan's served row once its status is no longer 'running', failing the calling
    test when it stays running past the streaming budget."""
    deadline = time.monotonic() + STREAM_TIMEOUT_SECONDS
    row = _served_scan(client, scan_id)
    while row["status"] == "running" and time.monotonic() < deadline:
        time.sleep(STREAM_POLL_SECONDS)
        row = _served_scan(client, scan_id)
    if row["status"] == "running":
        pytest.fail(f"scan {scan_id} was still running after {STREAM_TIMEOUT_SECONDS}s")
    return row


@pytest.mark.regression
@pytest.mark.parametrize(("target", "redacted"), MALFORMED_CREDENTIAL_TARGETS)
def test_a_malformed_credential_target_is_redacted_in_every_sink(
    client, monkeypatch, caplog, target, redacted
):
    """Starts a scan of a credential-bearing target no authority can be parsed from and checks the
    userinfo reaches neither the 202 body, the served row, the stored row nor the log."""
    caplog.set_level(logging.INFO)
    monkeypatch.setenv("TRUFFLEHOG_BIN", sys.executable)

    response = client.post("/api/scans", json={"target": target})

    assert response.status_code == 202, response.text
    accepted = response.json()
    scan_id = accepted["id"]
    assert accepted["target"] == redacted, accepted
    assert _served_scan(client, scan_id)["target"] == redacted
    stored = _stored_scan(scan_id)
    assert stored["target"] == redacted, stored

    assert MALFORMED_TARGET_CREDENTIAL not in response.text, "the 202 body leaked the credential"
    assert MALFORMED_TARGET_CREDENTIAL not in client.get("/api/scans").text, "GET leaked it"
    assert MALFORMED_TARGET_CREDENTIAL not in json.dumps(stored), "the scans row leaked it"
    assert MALFORMED_TARGET_CREDENTIAL not in caplog.text, "a log record leaked it"

    starts = [
        m
        for m in _messages(caplog, logging.INFO)
        if "starting scan" in m and f"scan_id={scan_id}" in m
    ]
    assert len(starts) == 1, f"expected one start record for scan {scan_id}, got {starts}"
    assert redacted in starts[0], starts[0]

    settled = _settled_scan(client, scan_id)
    assert settled["status"] == "failed", settled
    assert settled["target"] == redacted, settled


FORGED_RECORD_TEXT = "ERROR forged record"
CONTROL_CHARACTER_TARGET = f"file:///tmp/x\n{FORGED_RECORD_TEXT}\r\x1b[31m\u2028\u2029tail"
RAW_CONTROL_CHARACTERS = ("\n", "\r", "\x1b", "\u2028", "\u2029")
ESCAPED_CONTROL_SEQUENCES = ("\\n", "\\r", "\\x1b", "\\u2028", "\\u2029")


@pytest.mark.regression
def test_the_start_record_escapes_control_characters_in_a_target(db_path, caplog):
    """Starts a worker on a target carrying newline, carriage-return, escape and Unicode separator
    characters and checks the INFO start record escapes them onto its own single line."""
    caplog.set_level(logging.INFO)
    db.init_db()
    scan_id = db.create_scan("fake", "git")["id"]

    worker = scanner.start_scan(scan_id, "git", CONTROL_CHARACTER_TARGET, sys.executable)
    worker.join(timeout=STREAM_TIMEOUT_SECONDS)
    assert not worker.is_alive(), f"the scan worker ran past {STREAM_TIMEOUT_SECONDS}s"

    starts = [m for m in _messages(caplog, logging.INFO) if "starting scan" in m]
    assert len(starts) == 1, f"expected exactly one start record, got {starts}"
    for character in RAW_CONTROL_CHARACTERS:
        assert character not in starts[0], f"{character!r} reached the start record unescaped"
    for sequence in ESCAPED_CONTROL_SEQUENCES:
        assert sequence in starts[0], f"{sequence} is missing from the start record"
    assert "'--'" in starts[0], f"the positional terminator is missing from {starts[0]}"

    messages = [record.getMessage() for record in caplog.records]
    forged = [m for m in messages if m.startswith(FORGED_RECORD_TEXT)]
    assert forged == [], f"the target forged a log record: {forged}"
    lines = caplog.text.splitlines()
    forged_lines = [line for line in lines if line.startswith(FORGED_RECORD_TEXT)]
    assert forged_lines == [], f"the target forged a log line: {forged_lines}"


VALIDATION_STATUS = 422
MISSING_BINARY_NAME = "trufflehog-does-not-exist"
INVALID_SCAN_BODIES = (
    ({"target": ""}, "target", "string_too_short"),
    ({"target": "file:///tmp/x", "source": "bogus"}, "source", "literal_error"),
)


def _scan_ids(client) -> set[int]:
    """Returns the id of every scan GET /api/scans serves."""
    response = client.get("/api/scans")
    assert response.status_code == 200, response.text
    return {row["id"] for row in response.json()}


def _validation_errors(response) -> list[dict]:
    """Returns the entries of a rejected request's detail list, failing the calling test when the
    response body carries no such list."""
    payload = response.json()
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if not isinstance(detail, list) or not detail:
        pytest.fail(f"expected a non-empty validation detail list, got {payload!r}")
    return detail


def _errors_for(response, field: str) -> list[dict]:
    """Returns the validation errors of this response whose loc ends in field."""
    return [error for error in _validation_errors(response) if error["loc"][-1] == field]


@pytest.mark.regression
@pytest.mark.parametrize(("body", "field", "error_type"), INVALID_SCAN_BODIES)
def test_an_invalid_scan_request_is_rejected(client, body, field, error_type):
    """Posts a body the request model must reject and checks the 422 names the offending field and
    its error type while the scans table stays untouched."""
    before = _scan_ids(client)

    response = client.post("/api/scans", json=body)

    assert response.status_code == VALIDATION_STATUS, response.text
    offending = _errors_for(response, field)
    assert len(offending) == 1, _validation_errors(response)
    assert offending[0]["type"] == error_type, offending[0]
    assert _scan_ids(client) == before, "a rejected request must not create a scan row"


@pytest.mark.regression
def test_request_validation_precedes_binary_resolution(client, monkeypatch):
    """Posts an empty target while TRUFFLEHOG_BIN names a missing executable and checks the request
    is rejected with 422 rather than the 503 of an unresolvable binary, creating no scan row."""
    monkeypatch.setenv("TRUFFLEHOG_BIN", MISSING_BINARY_NAME)
    before = _scan_ids(client)

    response = client.post("/api/scans", json={"target": ""})

    assert response.status_code == VALIDATION_STATUS, response.text
    assert len(_errors_for(response, "target")) == 1, _validation_errors(response)
    assert BINARY_MISSING_DETAIL not in response.text, response.text
    assert _scan_ids(client) == before, "a rejected request must not create a scan row"


JSON_HEADERS = {"content-type": "application/json"}
# json.dumps escapes each surrogate, so every request body below is plain ASCII on the wire; the
# server's parser rebuilds the character, which UTF-8 then cannot encode.
HIGH_SURROGATE = "\ud800"
LOW_SURROGATE = "\udfff"
HIGH_SURROGATE_ESCAPE = r"\ud800"
LOW_SURROGATE_ESCAPE = r"\udfff"
SURROGATE_BODIES = (
    (json.dumps({"target": f"file:///tmp/{HIGH_SURROGATE}bad"}), "target", HIGH_SURROGATE_ESCAPE),
    (
        json.dumps({"target": "file:///tmp/ok", "source": f"g{HIGH_SURROGATE}it"}),
        "source",
        HIGH_SURROGATE_ESCAPE,
    ),
    (json.dumps({"target": {"a": HIGH_SURROGATE}}), "target", HIGH_SURROGATE_ESCAPE),
    (json.dumps(HIGH_SURROGATE), "body", HIGH_SURROGATE_ESCAPE),
    (json.dumps({"target": f"file:///tmp/{LOW_SURROGATE}bad"}), "target", LOW_SURROGATE_ESCAPE),
)
# A surrogate the request model never reads: an unknown field, and a key rather than a value.
ACCEPTED_SURROGATE_BODIES = (
    json.dumps({"target": "file:///tmp/surrogate-extra", "note": HIGH_SURROGATE}),
    json.dumps({"target": "file:///tmp/surrogate-key", HIGH_SURROGATE: "x"}),
)


def _has_surrogate(text: str) -> bool:
    """Reports whether text carries a UTF-16 surrogate code point, which UTF-8 cannot encode."""
    return any("\ud800" <= character <= "\udfff" for character in text)


@pytest.mark.regression
@pytest.mark.parametrize(("body", "field", "escape"), SURROGATE_BODIES)
def test_a_lone_surrogate_in_the_body_is_rejected_without_a_server_error(
    client, body, field, escape
):
    """Posts a body carrying a lone UTF-16 surrogate and checks the request is rejected with the
    documented 422 JSON detail naming the offending field, its input escaped rather than passed
    through, and no scan row created."""
    before = _scan_ids(client)

    response = client.post("/api/scans", content=body.encode("ascii"), headers=JSON_HEADERS)

    assert response.status_code == VALIDATION_STATUS, response.text
    assert response.headers["content-type"].startswith("application/json"), response.headers
    offending = _errors_for(response, field)
    assert len(offending) == 1, _validation_errors(response)
    echoed = json.dumps(offending[0].get("input"))
    assert escape in echoed, echoed
    assert not _has_surrogate(response.text), "the rejection echoed an unencodable code point"
    assert _scan_ids(client) == before, "a rejected request must not create a scan row"


@pytest.mark.regression
@pytest.mark.parametrize("body", ACCEPTED_SURROGATE_BODIES)
def test_a_surrogate_outside_the_request_fields_still_starts_a_scan(client, monkeypatch, body):
    """Posts a valid target beside a surrogate the request model never reads and checks the scan is
    still accepted, so the rejection path cannot swallow a usable request."""
    monkeypatch.setenv("TRUFFLEHOG_BIN", sys.executable)

    response = client.post("/api/scans", content=body.encode("ascii"), headers=JSON_HEADERS)

    assert response.status_code == 202, response.text
    accepted = response.json()
    assert accepted["status"] == "running", accepted
    # Settled before the test ends so this scan's worker cannot outlive the database it writes to.
    assert _settled_scan(client, accepted["id"])["status"] == "failed"


@pytest.mark.regression
def test_json_safe_renders_the_shapes_a_rejection_detail_can_carry():
    """Checks the rejection body builder escapes unencodable text, stringifies keys, flattens the
    sequences pydantic reports and carries an arbitrary object as its text."""
    rendered = main.json_safe(
        {
            ("body", "target"): ValueError(f"bad {HIGH_SURROGATE}"),
            1: {"ints": (1, 2), "set": {3}, "flags": [True, None, 1.5]},
            "text": f"file:///tmp/{HIGH_SURROGATE}",
        }
    )

    assert rendered["text"] == f"file:///tmp/{HIGH_SURROGATE_ESCAPE}"
    assert HIGH_SURROGATE_ESCAPE in rendered["('body', 'target')"]
    assert rendered["1"] == {"ints": [1, 2], "set": [3], "flags": [True, None, 1.5]}
    assert not _has_surrogate(json.dumps(rendered))
    assert json.dumps(rendered).encode("utf-8"), "the rendered detail must encode as UTF-8"


UNSPAWNABLE_BINARY_PATH = "/nonexistent/binary/path"
SPAWN_FAILURE_MESSAGE = "could not start the scan subprocess"

NON_UTF8_STDOUT_BYTES = b"\xff\xfe not utf8\n"
NON_UTF8_STDOUT_TEXT = NON_UTF8_STDOUT_BYTES.decode("utf-8", errors="replace").strip()
NON_UTF8_ASCII_RUN = "not utf8"
REPLACEMENT_CHARACTER = "\ufffd"

GARBLED_WORKER_TEMPLATE = """\
import sys

sys.stdout.buffer.write(%(garbage)s)
sys.stdout.buffer.flush()
sys.stdout.buffer.write(%(finding)s.encode("utf-8") + b"\\n")
sys.stdout.buffer.flush()
"""

ORPHAN_SWEEP_MESSAGE = "marked 1 orphaned scan(s) as failed"
ORPHAN_SWEEP_SUBJECT = "orphaned scan"


def _garbled_worker_script() -> str:
    """Returns Python source that writes one raw undecodable line and then one valid finding line to
    stdout, then exits 0."""
    return GARBLED_WORKER_TEMPLATE % {
        "garbage": ascii(NON_UTF8_STDOUT_BYTES),
        "finding": ascii(_finding_line()),
    }


def _scans_by_id() -> dict[int, dict]:
    """Returns every stored scan object keyed by its id."""
    return {row["id"]: row for row in db.list_scans()}


@pytest.mark.regression
def test_run_scan_fails_the_scan_when_the_subprocess_cannot_be_spawned(db_path, caplog):
    """Runs the worker on a command whose binary does not exist and checks it returns without
    raising, leaves the row failed with no exit code and no findings, and reports the spawn failure
    once at ERROR."""
    caplog.set_level(logging.INFO)
    db.init_db()
    scan_id = db.create_scan("fake", "git")["id"]

    scanner.run_scan(scan_id, [UNSPAWNABLE_BINARY_PATH])

    row = _stored_scan(scan_id)
    assert row["status"] == "failed", row
    assert row["exit_code"] is None, row
    assert row["finished_at"], "an unspawnable scan must still record a finish time"
    assert db.list_findings(scan_id) == []

    errors = _messages(caplog, logging.ERROR)
    assert len(errors) == 1, f"expected exactly one error record, got {errors}"
    assert SPAWN_FAILURE_MESSAGE in errors[0], errors[0]
    assert f"scan_id={scan_id}" in errors[0], errors[0]


@pytest.mark.regression
def test_run_scan_survives_undecodable_stdout_bytes(db_path, caplog):
    """Runs a stand-in child that emits raw non-UTF-8 bytes before one valid finding and checks the
    read loop skips the undecodable line, stores the finding, completes the scan and logs neither
    the bytes nor their replacement text."""
    caplog.set_level(logging.DEBUG)
    db.init_db()
    scan_id = db.create_scan("fake", "git")["id"]

    scanner.run_scan(scan_id, [sys.executable, "-c", _garbled_worker_script()])

    assert len(db.list_findings(scan_id)) == 1
    completed = _stored_scan(scan_id)
    assert completed["status"] == "completed", completed
    assert completed["exit_code"] == 0, completed

    skips = [m for m in _messages(caplog, logging.WARNING) if "skipped unparseable stdout line" in m]
    assert len(skips) == 1, f"expected one warning for the undecodable line, got {skips}"
    assert f"scan_id={scan_id}" in skips[0], skips[0]
    assert f"length={len(NON_UTF8_STDOUT_TEXT)}" in skips[0], skips[0]
    assert NON_UTF8_ASCII_RUN not in caplog.text, "the undecodable line reached a log record"
    assert REPLACEMENT_CHARACTER not in caplog.text, "the replaced bytes reached a log record"


@pytest.mark.regression
def test_init_db_sweeps_scans_left_running(db_path, caplog):
    """Leaves one scan running beside one completed scan across a second init_db and checks the
    startup sweep fails only the running row, reports the count once, and changes nothing on a
    later startup with no running scan."""
    caplog.set_level(logging.INFO)
    db.init_db()
    orphan_id = db.create_scan("fake", "git")["id"]
    settled_id = db.create_scan("fake", "git")["id"]
    db.finish_scan(settled_id, "completed", 0)
    settled_before = _scans_by_id()[settled_id]

    db.init_db()

    swept = _scans_by_id()
    assert swept[orphan_id]["status"] == "failed", swept[orphan_id]
    assert swept[orphan_id]["exit_code"] is None, swept[orphan_id]
    assert swept[orphan_id]["finished_at"], "a swept scan must carry a finish time"
    assert swept[settled_id] == settled_before, "the sweep must not touch a terminal row"

    sweeps = [m for m in _messages(caplog, logging.INFO) if ORPHAN_SWEEP_MESSAGE in m]
    assert len(sweeps) == 1, f"expected one sweep record, got {_messages(caplog, logging.INFO)}"

    caplog.clear()
    db.init_db()

    assert _scans_by_id() == swept, "a startup with nothing running must change no row"
    assert ORPHAN_SWEEP_SUBJECT not in caplog.text, caplog.text


# Split across source tokens like conftest's planted token, so no line here reads as a credential.
LONG_TARGET_CREDENTIAL = "n0t-a-real" + "-long-target-token"
LONG_TARGET_PREFIX = "file:///tmp/qa-"
LONG_PATH_PREFIX = "/srv/"
LONG_PATH_SUFFIX = f"/user:{LONG_TARGET_CREDENTIAL}@host/repo"
LONG_PATH_REDACTED_SUFFIX = "/***@host/repo"
# Both shapes carry no authority for urlsplit to find, which is the redaction path that used to grow
# with the square of the target length, and both sit on the longest target the request model accepts.
LONG_TARGET_FILLER = "a" * (main.TARGET_MAX_LENGTH - len(LONG_TARGET_PREFIX))
LONG_PATH_FILLER = "a" * (main.TARGET_MAX_LENGTH - len(LONG_PATH_PREFIX) - len(LONG_PATH_SUFFIX))
LONG_TARGETS = (
    (f"{LONG_TARGET_PREFIX}{LONG_TARGET_FILLER}", f"{LONG_TARGET_PREFIX}{LONG_TARGET_FILLER}"),
    (
        f"{LONG_PATH_PREFIX}{LONG_PATH_FILLER}{LONG_PATH_SUFFIX}",
        f"{LONG_PATH_PREFIX}{LONG_PATH_FILLER}{LONG_PATH_REDACTED_SUFFIX}",
    ),
)

# The length the report's amplification payload used, beside the first length the model refuses.
AMPLIFYING_TARGET_LENGTH = 5_000_000
OVERSIZE_TARGET_LENGTHS = (main.TARGET_MAX_LENGTH + 1, AMPLIFYING_TARGET_LENGTH)
TOO_LONG_ERROR_TYPE = "string_too_long"
ERROR_TEXT_LIMIT = 200

SINGLE_REDACTION_TARGET = f"https://user:{MALFORMED_TARGET_CREDENTIAL}@host/org/repo.git"
SINGLE_REDACTION_EXPECTED = "https://***@host/org/repo.git"

NUL_BYTE_TARGET = "file:///tmp/a\x00b"
LONE_SURROGATE_ARGUMENT = "file:///tmp/a\ud800b"
UNENCODABLE_ARGUMENTS = (NUL_BYTE_TARGET, LONE_SURROGATE_ARGUMENT)

NOT_FOUND_DETAIL = "scan not found"
# Ids outside the range a SQLite INTEGER column holds, beside the boundaries that just fit it.
UNQUERYABLE_SCAN_IDS = (2**63, 2**64, -(2**63) - 1)
UNUSED_SCAN_IDS = (2**63 - 1, -(2**63), 0, -1, 999999)


@pytest.mark.regression
@pytest.mark.parametrize(("target", "redacted"), LONG_TARGETS)
def test_a_long_target_is_accepted_within_the_start_budget(client, monkeypatch, target, redacted):
    """Posts the longest accepted target in each authority-less shape and checks the scan id comes
    back inside the start budget with any credential already masked."""
    monkeypatch.setenv("TRUFFLEHOG_BIN", sys.executable)
    assert len(target) == main.TARGET_MAX_LENGTH, len(target)

    started = time.perf_counter()
    response = client.post("/api/scans", json={"target": target})
    elapsed = time.perf_counter() - started

    assert response.status_code == 202, response.text
    assert elapsed < START_BUDGET_SECONDS, (
        f"POST of a {len(target)}-character target took {elapsed:.3f}s, "
        f"budget {START_BUDGET_SECONDS}s"
    )
    accepted = response.json()
    assert accepted["target"] == redacted, accepted["target"][-60:]
    assert LONG_TARGET_CREDENTIAL not in accepted["target"], "a long target kept its credential"
    assert _served_scan(client, accepted["id"])["target"] == redacted
    # Settled before the test ends so this scan's worker cannot outlive the database it writes to.
    assert _settled_scan(client, accepted["id"])["target"] == redacted


@pytest.mark.regression
@pytest.mark.parametrize("length", OVERSIZE_TARGET_LENGTHS)
def test_an_oversize_target_is_rejected_and_never_stored(client, monkeypatch, length):
    """Posts a target longer than the request model accepts and checks it is rejected with a 422
    naming the bound, that no scan row is created, and that no served row carries a target past the
    bound, so one request cannot inflate every later scans response."""
    monkeypatch.setenv("TRUFFLEHOG_BIN", sys.executable)
    before = _scan_ids(client)

    response = client.post("/api/scans", json={"target": "g" * length})

    assert response.status_code == VALIDATION_STATUS, response.text[:ERROR_TEXT_LIMIT]
    offending = _errors_for(response, "target")
    assert len(offending) == 1, len(_validation_errors(response))
    assert offending[0]["type"] == TOO_LONG_ERROR_TYPE, offending[0]["type"]
    assert offending[0]["ctx"]["max_length"] == main.TARGET_MAX_LENGTH, offending[0]["ctx"]
    assert _scan_ids(client) == before, "a rejected request must not create a scan row"

    served = client.get("/api/scans")
    assert served.status_code == 200, served.text[:ERROR_TEXT_LIMIT]
    longest = max((len(row["target"]) for row in served.json()), default=0)
    assert longest <= main.TARGET_MAX_LENGTH, f"a stored target reached {longest} characters"


@pytest.mark.regression
def test_the_request_path_redacts_the_target_once(client, monkeypatch):
    """Posts a credential-bearing target and checks the request redacts it exactly once, so the work
    is not paid for twice on the way to the row and the log."""
    monkeypatch.setenv("TRUFFLEHOG_BIN", sys.executable)
    real_redact = scanner.redact_target
    redactions = []

    def counting_redact(target: str) -> str:
        """Records the target it was given and returns scanner.redact_target's result for it."""
        redactions.append(target)
        return real_redact(target)

    monkeypatch.setattr(scanner, "redact_target", counting_redact)

    response = client.post("/api/scans", json={"target": SINGLE_REDACTION_TARGET})

    assert response.status_code == 202, response.text
    accepted = response.json()
    assert redactions == [SINGLE_REDACTION_TARGET], (
        f"the target must be redacted once per request, got {len(redactions)} redaction(s)"
    )
    assert accepted["target"] == SINGLE_REDACTION_EXPECTED
    # Settled before the test ends so this scan's worker cannot outlive the database it writes to.
    assert _settled_scan(client, accepted["id"])["target"] == SINGLE_REDACTION_EXPECTED


@pytest.mark.regression
def test_a_nul_byte_target_fails_the_scan_without_an_unhandled_thread_exception(
    client, monkeypatch, caplog
):
    """Starts a scan whose target carries a NUL byte and checks the worker reports the spawn failure
    at ERROR and finalizes the row failed with no exit code, leaving the thread hook untouched."""
    caplog.set_level(logging.INFO)
    monkeypatch.setenv("TRUFFLEHOG_BIN", sys.executable)
    unhandled = []

    def record_unhandled(args) -> None:
        """Stands in for threading.excepthook, recording whatever reaches it."""
        unhandled.append(args)

    monkeypatch.setattr(threading, "excepthook", record_unhandled)

    response = client.post("/api/scans", json={"target": NUL_BYTE_TARGET})

    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    settled = _settled_scan(client, scan_id)
    assert settled["status"] == "failed", settled
    assert settled["exit_code"] is None, settled
    assert settled["finished_at"], "a scan that never spawned must still record a finish time"
    assert unhandled == [], f"the worker thread died with an unhandled exception: {unhandled}"

    errors = [m for m in _messages(caplog, logging.ERROR) if f"scan_id={scan_id}" in m]
    assert len(errors) == 1, f"expected one spawn-failure record, got {errors}"
    assert SPAWN_FAILURE_MESSAGE in errors[0], errors[0]


@pytest.mark.regression
@pytest.mark.parametrize("argument", UNENCODABLE_ARGUMENTS)
def test_run_scan_fails_the_scan_when_an_argument_cannot_be_encoded(db_path, caplog, argument):
    """Runs the worker with an argument the exec layer refuses — an embedded NUL, a lone surrogate —
    and checks it returns without raising and records one ERROR against a failed row."""
    caplog.set_level(logging.INFO)
    db.init_db()
    scan_id = db.create_scan("fake", "git")["id"]

    scanner.run_scan(scan_id, [sys.executable, "-c", "pass", argument])

    row = _stored_scan(scan_id)
    assert row["status"] == "failed", row
    assert row["exit_code"] is None, row
    assert row["finished_at"], "a scan that never spawned must still record a finish time"
    assert db.list_findings(scan_id) == []

    errors = _messages(caplog, logging.ERROR)
    assert len(errors) == 1, f"expected exactly one error record, got {errors}"
    assert SPAWN_FAILURE_MESSAGE in errors[0], errors[0]
    assert f"scan_id={scan_id}" in errors[0], errors[0]


@pytest.mark.regression
@pytest.mark.parametrize("scan_id", UNQUERYABLE_SCAN_IDS + UNUSED_SCAN_IDS)
def test_a_scan_id_no_row_carries_is_not_found(client, scan_id):
    """Requests the findings of ids outside and inside the range a scan id column holds and checks
    each answers the documented 404 JSON rather than a server error."""
    response = client.get(f"/api/scans/{scan_id}/findings")

    assert response.status_code == 404, f"id {scan_id} answered {response.status_code}"
    assert response.headers["content-type"].startswith("application/json"), response.headers
    assert response.json() == {"detail": NOT_FOUND_DETAIL}, response.text


@pytest.mark.regression
def test_a_stored_scan_id_still_serves_its_findings(client):
    """Requests the findings of a scan row that exists and checks the id guard leaves the 200 path
    alone."""
    scan_id = db.create_scan("fake", "git")["id"]

    response = client.get(f"/api/scans/{scan_id}/findings")

    assert response.status_code == 200, response.text
    assert response.json() == []

