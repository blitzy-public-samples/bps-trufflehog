"""TruffleHog process boundary: binary resolution, output parsing and the background scan worker."""

import json
import logging
import os
import shutil
import subprocess
import threading
import urllib.parse

import db

logger = logging.getLogger(__name__)

BINARY_ENV_VAR = "TRUFFLEHOG_BIN"
DEFAULT_BINARY = "trufflehog"
BINARY_MISSING_MESSAGE = "trufflehog binary not found on PATH; install it or set TRUFFLEHOG_BIN"
SECRET_KEYS = frozenset({"Raw", "RawV2", "SecretParts"})
MASK_THRESHOLD = 12
STDERR_JOIN_TIMEOUT = 5


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


def _text(value) -> str | None:
    """Returns value as text, or None when it is absent or empty."""
    if value is None or value == "":
        return None
    return value if isinstance(value, str) else str(value)


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
    return {
        "detector": obj.get("DetectorName") or "unknown",
        "verified": 1 if obj.get("Verified") else 0,
        "file": _text(member.get("file")),
        "line": line,
        "repository": _text(member.get("repository")),
        "commit_hash": _text(member.get("commit")),
        "redacted": _text(obj.get("Redacted")) or mask_secret(_text(obj.get("Raw")) or ""),
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
    status of scan_id: 'completed' on exit code 0, 'failed' on any other code."""
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
        db.finish_scan(scan_id, "failed", None)
        return

    stderr_lines = [0]
    drain = threading.Thread(
        target=_drain_stderr,
        args=(proc.stderr, stderr_lines),
        name=f"scan-{scan_id}-stderr",
        daemon=True,
    )
    drain.start()

    inserted = 0
    skipped = 0
    conn = None
    try:
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
    except Exception:
        logger.exception("scan worker stopped before the scan finished (scan_id=%s)", scan_id)
        proc.kill()
        proc.wait()
        db.finish_scan(scan_id, "failed", None)
        return
    finally:
        if conn is not None:
            conn.close()
        proc.stdout.close()

    drain.join(timeout=STDERR_JOIN_TIMEOUT)
    status = "completed" if exit_code == 0 else "failed"
    if exit_code != 0:
        logger.warning(
            "trufflehog exited with code %d (scan_id=%s, findings=%d)",
            exit_code,
            scan_id,
            inserted,
        )
    db.finish_scan(scan_id, status, exit_code)
    logger.info(
        "scan finished (scan_id=%s, exit_code=%s, findings=%d, stdout_lines_skipped=%d, "
        "stderr_lines_drained=%d)",
        scan_id,
        exit_code,
        inserted,
        skipped,
        stderr_lines[0],
    )


def start_scan(scan_id: int, source: str, target: str, binary: str) -> threading.Thread:
    """Starts run_scan for scan_id on a daemon thread and returns that thread without joining it,
    where binary is the resolved executable, source the subcommand and target its argument."""
    cmd = build_command(binary, source, target)
    logger.info(
        "starting scan (scan_id=%s, source=%s): %s",
        scan_id,
        source,
        " ".join(build_command(binary, source, redact_target(target))),
    )
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, cmd),
        name=f"scan-{scan_id}",
        daemon=True,
    )
    thread.start()
    return thread
