"""TruffleHog process boundary: binary resolution, output parsing and the background scan worker."""

import contextlib
import json
import logging
import os
import shutil
import subprocess
import threading
import time
import urllib.parse

import db

logger = logging.getLogger(__name__)

BINARY_ENV_VAR = "TRUFFLEHOG_BIN"
DEFAULT_BINARY = "trufflehog"
BINARY_MISSING_MESSAGE = "trufflehog binary not found on PATH; install it or set TRUFFLEHOG_BIN"
SECRET_KEYS = frozenset({"Raw", "RawV2", "SecretParts"})
MASK_THRESHOLD = 12
STDERR_JOIN_TIMEOUT = 5
TERMINAL_RETRY_DELAY = 0.5


class TrufflehogNotFoundError(RuntimeError):
    """Raised when no trufflehog executable can be resolved."""


def resolve_binary() -> str:
    """Returns the path of the trufflehog executable named by TRUFFLEHOG_BIN or found on PATH, and
    raises TrufflehogNotFoundError when none resolves."""
    name = os.environ.get(BINARY_ENV_VAR, DEFAULT_BINARY)
    path = shutil.which(name)
    if not path:
        logger.error("trufflehog binary not found (looked for %r on PATH)", name)
        raise TrufflehogNotFoundError(BINARY_MISSING_MESSAGE)
    return path


def build_command(binary: str, source: str, target: str) -> list[str]:
    """Returns the argument list scanning target in JSON mode, where source is the subcommand
    ("git" or "filesystem") and target its positional argument."""
    return [binary, source, target, "--json", "--no-update"]


def parse_line(line: str) -> dict | None:
    """Returns the finding object decoded from one stdout line, or None when the line is blank,
    malformed or valid JSON that is not an object."""
    text = line.strip()
    if not text:
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def redact_target(target: str) -> str:
    """Returns target with any URL userinfo replaced by '***@'; input without userinfo, or input that
    is not a URL, is returned unchanged."""
    try:
        parts = urllib.parse.urlsplit(target)
    except ValueError:
        return target
    if "@" not in parts.netloc:
        return target
    host = parts.netloc.rsplit("@", 1)[1]
    return urllib.parse.urlunsplit(parts._replace(netloc="***@" + host))


def mask_secret(raw: str) -> str:
    """Returns a display-safe form of raw: its first and last four characters around an ellipsis, or
    one asterisk per character when it is short. An empty value yields an empty string."""
    if not raw:
        return ""
    if len(raw) > MASK_THRESHOLD:
        return raw[:4] + "\u2026" + raw[-4:]
    return "*" * len(raw)


def finding_from_json(obj: dict) -> dict:
    """Maps one parsed finding object onto the findings columns, leaving obj unchanged. Returns
    detector, verified, file, line, repository, commit_hash, redacted and raw_json — the object
    without its Raw, RawV2 and SecretParts values."""
    metadata = obj.get("SourceMetadata")
    data = metadata.get("Data") if isinstance(metadata, dict) else None
    member = next(iter(data.values()), None) if isinstance(data, dict) else None
    if not isinstance(member, dict):
        member = {}
    try:
        line = int(member.get("line"))
    except (TypeError, ValueError):
        line = None
    # Absent and empty values drop out, so a missing key reads back as None; every other value is
    # carried as text because each one reaches a TEXT column, directly or through mask_secret.
    text = {
        name: value if isinstance(value, str) else str(value)
        for name, value in (
            ("file", member.get("file")),
            ("repository", member.get("repository")),
            ("commit", member.get("commit")),
            ("redacted", obj.get("Redacted")),
            ("raw", obj.get("Raw")),
        )
        if not (value is None or value == "")
    }
    return {
        "detector": obj.get("DetectorName") or "unknown",
        "verified": 1 if obj.get("Verified") else 0,
        "file": text.get("file"),
        "line": line,
        "repository": text.get("repository"),
        "commit_hash": text.get("commit"),
        "redacted": text.get("redacted") or mask_secret(text.get("raw") or ""),
        "raw_json": json.dumps({k: v for k, v in obj.items() if k not in SECRET_KEYS}),
    }


def _drain_stderr(pipe, counter: list[int]) -> None:
    """Reads the subprocess error pipe to EOF so the child never blocks on it, counting the lines in
    counter[0] and discarding their text."""
    with pipe:
        for _ in pipe:
            counter[0] += 1


def run_scan(scan_id: int, cmd: list[str]) -> None:
    """Runs cmd, inserting every finding it prints as the scan progresses, and records the terminal
    status of scan_id from a single finalization: 'completed' on exit code 0, 'failed' on any other
    code and on a code that never arrived (exit_code stays NULL for that case)."""
    stderr_lines = [0]
    inserted = 0
    skipped = 0
    exit_code = None
    proc = None
    drain = None
    conn = None
    try:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                errors="replace",
            )
        except OSError as exc:
            logger.error("could not start the scan subprocess (scan_id=%s): %s", scan_id, exc)
            return
        stderr_drain = threading.Thread(
            target=_drain_stderr,
            args=(proc.stderr, stderr_lines),
            name=f"scan-{scan_id}-stderr",
            daemon=True,
        )
        stderr_drain.start()
        # Bound only once the thread is running, so the finalization below can tell a drain it must
        # join from one that never started, whose pipe it owns and whose join would raise.
        drain = stderr_drain
        conn = db.connect()
        for line in proc.stdout:
            obj = parse_line(line)
            if obj is None:
                skipped += 1
                stripped = line.strip()
                if stripped:
                    logger.warning(
                        "skipped unparseable stdout line (scan_id=%s, length=%d)",
                        scan_id,
                        len(stripped),
                    )
                else:
                    logger.debug("skipped empty stdout line (scan_id=%s)", scan_id)
                continue
            db.insert_finding(conn, scan_id, finding_from_json(obj))
            inserted += 1
        exit_code = proc.wait()
    finally:
        # Every cleanup step is guarded on its own: no rollback, kill, close or join failure may
        # stop this block from reaching the terminal update below.
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.rollback()
            with contextlib.suppress(Exception):
                conn.close()
        if proc is not None and exit_code is None:
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait()
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.stdout.close()
            if drain is None:
                with contextlib.suppress(Exception):
                    proc.stderr.close()
        drained = str(stderr_lines[0])
        if drain is not None:
            with contextlib.suppress(Exception):
                drain.join(timeout=STDERR_JOIN_TIMEOUT)
            # A grandchild that inherited the write end keeps the pipe open after the child exits,
            # so the join stays bounded and the count is reported as a lower bound ("12+") when the
            # drain is still running rather than as a final figure.
            drained = f"{stderr_lines[0]}+" if drain.is_alive() else str(stderr_lines[0])
        status = "completed" if exit_code == 0 else "failed"
        if exit_code is not None and exit_code != 0:
            logger.warning(
                "trufflehog exited with code %d (scan_id=%s, findings=%d)",
                exit_code,
                scan_id,
                inserted,
            )
        try:
            db.finish_scan(scan_id, status, exit_code)
        except Exception:
            time.sleep(TERMINAL_RETRY_DELAY)
            db.finish_scan(scan_id, status, exit_code)
        if proc is not None:
            logger.info(
                "scan finished (scan_id=%s, exit_code=%s, findings=%d, stdout_lines_skipped=%d, "
                "stderr_lines_drained=%s)",
                scan_id,
                exit_code,
                inserted,
                skipped,
                drained,
            )


def start_scan(scan_id: int, source: str, target: str, binary: str) -> threading.Thread:
    """Starts run_scan for scan_id on a daemon thread and returns that thread without joining it,
    where binary is the resolved executable, source the subcommand and target its argument. Marks
    the already-created scan failed with no exit code and re-raises when the thread cannot start."""
    cmd = build_command(binary, source, target)
    logger.info(
        "starting scan (scan_id=%s, source=%s): %s",
        scan_id,
        source,
        " ".join(build_command(binary, source, redact_target(target))),
    )
    try:
        thread = threading.Thread(
            target=run_scan,
            args=(scan_id, cmd),
            name=f"scan-{scan_id}",
            daemon=True,
        )
        thread.start()
    except Exception:
        # The scan row is already committed as running and no worker will ever finalize it, so
        # compensate here; a compensation that cannot be written is swept on the next startup.
        with contextlib.suppress(Exception):
            db.finish_scan(scan_id, "failed", None)
        raise
    return thread
