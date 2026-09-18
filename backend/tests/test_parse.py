"""Unit tests for scanner parsing, mapping, command, masking, and redaction helpers."""

import json
import logging
import urllib.parse

import pytest

import scanner

# Split across source tokens so this file's text matches no GitHub token pattern.
RAW = "ghp_" + "x" * 36

# Expected masks are defined independently, so mask_secret is never its own oracle.
MASKED_RAW = "ghp_\u2026xxxx"
SHORT_RAW = "a" * 12
MASKED_SHORT_RAW = "*" * 12

COMMIT = "1caf0105" + "9f3c" * 8
REPOSITORY = "file:///tmp/fixture"

TARGET_SECRET = "n0t-a-real-token"

CREDENTIAL_TARGETS = (
    (f"https://user:{TARGET_SECRET}@host/org/repo.git", "https://***@host/org/repo.git"),
    (f"ssh://user:{TARGET_SECRET}@[::1]:22/org/repo.git", "ssh://***@[::1]:22/org/repo.git"),
)

UNPARSEABLE_CREDENTIAL_TARGETS = (
    (f"https://user:{TARGET_SECRET}@[bad/repo.git", "https://***@[bad/repo.git"),
    (f"https://user:{TARGET_SECRET}@[::1/repo.git", "https://***@[::1/repo.git"),
    (f"https://user%3A{TARGET_SECRET}@[bad/repo.git", "https://***@[bad/repo.git"),
    (f"https://user:{TARGET_SECRET}@x@[bad/repo.git", "https://***@[bad/repo.git"),
)

AUTHORITYLESS_CREDENTIAL_TARGETS = (
    (f"user:{TARGET_SECRET}@host:org/repo.git", "***@host:org/repo.git"),
    (f"user:{TARGET_SECRET}@host:org//repo.git", "***@host:org//repo.git"),
    (f"https:///user:{TARGET_SECRET}@[bad/repo.git", "https:///***@[bad/repo.git"),
    (f"https:/user:{TARGET_SECRET}@[bad/repo.git", "https:/***@[bad/repo.git"),
    (f"https:user:{TARGET_SECRET}@host/repo.git", "***@host/repo.git"),
)

HOSTILE_CREDENTIAL_SPELLINGS = (
    f"https://user:{TARGET_SECRET}@host/org/repo.git",
    f"ssh://user:{TARGET_SECRET}@[::1]:22/repo.git",
    f"git+ssh://user:{TARGET_SECRET}@host/repo.git",
    f"//user:{TARGET_SECRET}@host/repo.git",
    f"////user:{TARGET_SECRET}@host/repo.git",
    f"HTTPS://user:{TARGET_SECRET}@[bad/repo.git",
    f"  https://user:{TARGET_SECRET}@[bad/repo.git",
    f"user:{TARGET_SECRET}@[bad",
    f"file:///tmp/x\nuser:{TARGET_SECRET}@host",
)

CREDENTIAL_FREE_TARGETS = (
    "https://host/org/repo.git",
    "file:///tmp/r",
    "/srv/code",
    "/srv/code@main/repo",
    "git@github.com:org/repo.git",
)

FLAG_SHAPED_TARGETS = (
    "--profile",
    "--config=/tmp/injected.yaml",
    "--no-verification",
    "--fail",
    "--json-legacy",
    "@/tmp/injected-args",
)

LOG_HOSTILE_TARGET = "file:///tmp/r\nWARNING forged record\rreturn\x1b[31m\u2028\u2029\u0085"

GIT_METADATA = {
    "Data": {
        "Git": {
            "commit": COMMIT,
            "file": "token.py",
            "email": "developer <developer@example.invalid>",
            "repository": REPOSITORY,
            "timestamp": "2026-09-17 15:21:56 +0000",
            "line": 1,
            "repository_local_path": "/tmp/trufflehog-752-fixture",
        }
    }
}

FILESYSTEM_METADATA = {
    "Data": {
        "Filesystem": {
            "file": "app/settings.py",
            "link": "",
            "email": "",
            "line": 12,
        }
    }
}

BANNER_LINES = (
    "\U0001f437\U0001f511\U0001f437  TruffleHog. Unearth your secrets. \U0001f437\U0001f511\U0001f437",
    "Found unverified result \U0001f437\U0001f511\u2753",
)


def finding_object(redacted: str = "", metadata: dict | None = None) -> dict:
    """Returns one finding object in the field order of TruffleHog's JSON printer; redacted sets
    Redacted and metadata replaces SourceMetadata."""
    return {
        "SourceMetadata": GIT_METADATA if metadata is None else metadata,
        "SourceID": 1,
        "SourceType": 16,
        "SourceName": "trufflehog - git",
        "DetectorType": 8,
        "DetectorName": "Github",
        "DetectorDescription": "GitHub personal access token",
        "DecoderName": "PLAIN",
        "Verified": False,
        "VerificationFromCache": False,
        "Raw": RAW,
        "RawV2": "",
        "Redacted": redacted,
        "ExtraData": {
            "rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
            "token_type": "Personal Access Token (classic)",
            "version": "2",
        },
        "StructuredData": None,
        "SecretParts": {"key": RAW},
    }


def finding_line(**overrides) -> str:
    """Returns finding_object(**overrides) serialised as a single JSON line."""
    return json.dumps(finding_object(**overrides)) + "\n"


def test_valid_finding_line():
    """A printer-shaped line maps every stored finding field while keeping the plaintext secret out
    of the display value and raw_json."""
    obj = scanner.parse_line(finding_line())
    assert isinstance(obj, dict)

    mapped = scanner.finding_from_json(obj)
    assert mapped["detector"] == "Github"
    assert mapped["verified"] == 0
    assert mapped["file"] == "token.py"
    assert mapped["line"] == 1
    assert mapped["repository"] == REPOSITORY
    assert mapped["commit_hash"] == COMMIT
    assert mapped["redacted"] == MASKED_RAW, f"expected {MASKED_RAW!r}, got {mapped['redacted']!r}"
    assert mapped["redacted"] != RAW, "plaintext secret stored as the display value"
    assert RAW not in mapped["redacted"], "display value carries the plaintext secret"

    assert scanner.mask_secret(RAW) == MASKED_RAW, f"mask of a long secret is {MASKED_RAW!r}"
    assert scanner.mask_secret(SHORT_RAW) == MASKED_SHORT_RAW, (
        f"mask of the {len(SHORT_RAW)}-character {SHORT_RAW!r} is {MASKED_SHORT_RAW!r}"
    )
    assert scanner.mask_secret(SHORT_RAW) != SHORT_RAW, "short secret returned in plaintext"
    assert SHORT_RAW not in scanner.mask_secret(SHORT_RAW), "short secret survived masking"
    assert scanner.mask_secret("") == "", "an absent secret masks to an empty display value"

    stored = json.loads(mapped["raw_json"])
    for key in ("Raw", "RawV2", "SecretParts"):
        assert key not in stored, f"{key} must never be stored"
    assert RAW not in mapped["raw_json"], "plaintext secret survived in raw_json text"
    assert stored["ExtraData"]["token_type"] == "Personal Access Token (classic)"
    assert stored["DecoderName"] == "PLAIN"


def test_malformed_line(caplog):
    """Truncated JSON yields None, and parse_line itself emits no log record."""
    caplog.set_level(logging.DEBUG)

    assert scanner.parse_line('{"DetectorName": "Github", "Verified": ') is None
    assert caplog.records == [], "parse_line must leave skip logging to the scan worker"


def test_empty_line():
    """Blank and whitespace-only stdout lines yield None."""
    for line in ("", "\n", "   \n"):
        assert scanner.parse_line(line) is None, f"{line!r} must be skipped"


def test_banner_line():
    """The human banner and result lines TruffleHog prints without a machine format yield None."""
    for line in BANNER_LINES:
        assert scanner.parse_line(line) is None, f"{line!r} must be skipped"


def test_non_object_json():
    """Valid JSON that is not a finding object yields None."""
    for line in ("42", "[1, 2]"):
        assert scanner.parse_line(line) is None, f"{line!r} must be skipped"


def test_filesystem_metadata():
    """A Filesystem finding maps file and line while repository and commit_hash stay unset."""
    mapped = scanner.finding_from_json(
        scanner.parse_line(finding_line(metadata=FILESYSTEM_METADATA))
    )

    assert mapped["file"] == "app/settings.py"
    assert mapped["line"] == 12
    assert mapped["repository"] is None
    assert mapped["commit_hash"] is None


def test_redacted_preferred_over_mask():
    """A non-empty Redacted value is stored verbatim rather than a mask derived from Raw."""
    redacted = "ghp_****xxxx"

    mapped = scanner.finding_from_json(scanner.parse_line(finding_line(redacted=redacted)))

    assert mapped["redacted"] == redacted
    assert mapped["redacted"] != MASKED_RAW, "the mask of Raw replaced the reported Redacted value"


def test_build_command():
    """The scan command is the binary and subcommand, then --json and --no-update, then the --
    terminator with the target last."""
    cmd = scanner.build_command("/usr/bin/trufflehog", "git", "file:///r")

    assert cmd == ["/usr/bin/trufflehog", "git", "--json", "--no-update", "--", "file:///r"]
    assert "--fail" not in cmd, "--fail would return exit code 183 and break the status mapping"
    assert "--no-verification" not in cmd, "verification drives the Verified badge and stays on"


def test_build_command_keeps_flag_shaped_targets_positional():
    """A target shaped like an option or an @argument file stays the last argument behind the --
    terminator, so the scanner's parser cannot read it as CLI syntax."""
    for target in FLAG_SHAPED_TARGETS:
        cmd = scanner.build_command("/usr/bin/trufflehog", "filesystem", target)

        assert cmd[:4] == ["/usr/bin/trufflehog", "filesystem", "--json", "--no-update"], cmd
        assert cmd[-2:] == ["--", target], f"{target!r} must follow the -- terminator, got {cmd}"
        assert len(cmd) == 6, f"{target!r} must add exactly one argument, got {cmd}"


def test_redact_target():
    """URL userinfo is replaced by '***@'; targets carrying no credentials pass through unchanged."""
    for target, expected in CREDENTIAL_TARGETS:
        assert scanner.redact_target(target) == expected, f"{target!r} must redact to {expected!r}"

    for target in CREDENTIAL_FREE_TARGETS:
        assert scanner.redact_target(target) == target, f"{target!r} must pass through unchanged"


def test_redact_target_on_an_unparseable_authority():
    """A credential-bearing URL urlsplit rejects is redacted instead of returned intact."""
    for target, expected in UNPARSEABLE_CREDENTIAL_TARGETS:
        with pytest.raises(ValueError):
            urllib.parse.urlsplit(target)

        redacted = scanner.redact_target(target)
        assert redacted == expected, f"{target!r} must redact to {expected!r}, got {redacted!r}"
        assert TARGET_SECRET not in redacted, "an unparseable URL carried its credential through"


def test_redact_target_without_a_parsed_authority():
    """A target urlsplit parses without a netloc — scp-style, or a URL whose separators are
    malformed — is redacted on the credential run itself rather than on a located authority."""
    for target, expected in AUTHORITYLESS_CREDENTIAL_TARGETS:
        assert urllib.parse.urlsplit(target).netloc == "", f"{target!r} needs an empty netloc"

        redacted = scanner.redact_target(target)
        assert redacted == expected, f"{target!r} must redact to {expected!r}, got {redacted!r}"
        assert TARGET_SECRET not in redacted, f"{target!r} carried its credential through"


def test_redact_target_never_returns_a_credential():
    """No spelling of a credential-bearing target keeps its password: every hostile form loses the
    secret and gains the mask, whichever branch of redact_target handles it."""
    spellings = (
        HOSTILE_CREDENTIAL_SPELLINGS
        + tuple(target for target, _ in CREDENTIAL_TARGETS)
        + tuple(target for target, _ in UNPARSEABLE_CREDENTIAL_TARGETS)
        + tuple(target for target, _ in AUTHORITYLESS_CREDENTIAL_TARGETS)
    )

    for target in spellings:
        redacted = scanner.redact_target(target)
        assert TARGET_SECRET not in redacted, f"{target!r} leaked its credential as {redacted!r}"
        assert "***@" in redacted, f"{target!r} was not masked: {redacted!r}"


def test_command_log_line_escapes_control_characters():
    """A target carrying newline, carriage-return, escape or Unicode separator characters reaches the
    logged command line escaped, so it cannot forge or reshape a record."""
    line = scanner.command_log_line(
        scanner.build_command("/usr/bin/trufflehog", "git", LOG_HOSTILE_TARGET)
    )

    for character in ("\n", "\r", "\x1b", "\u2028", "\u2029", "\u0085"):
        assert character not in line, f"{character!r} must not survive into a log line"

    for escaped in ("\\n", "\\r", "\\x1b", "\\u2028", "\\u2029", "\\x85"):
        assert escaped in line, f"{escaped} must stand in for the raw character: {line}"

    assert "'--'" in line, "the logged command line keeps the -- terminator visible"
