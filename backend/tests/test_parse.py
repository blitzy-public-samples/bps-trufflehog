"""Unit tests for the pure output-parsing helpers in scanner."""

import json
import logging

import pytest

import scanner

# Joined at runtime so this file's own text matches no GitHub token pattern.
RAW = "ghp_" + "x" * 36

COMMIT = "1caf0105" + "9f3c" * 8
REPOSITORY = "file:///tmp/fixture"

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
    """A printer-shaped line parses into an object whose mapping fills every findings column and
    keeps the plaintext secret out of the stored JSON."""
    obj = scanner.parse_line(finding_line())
    assert isinstance(obj, dict)

    mapped = scanner.finding_from_json(obj)
    assert mapped["detector"] == "Github"
    assert mapped["verified"] == 0
    assert mapped["file"] == "token.py"
    assert mapped["line"] == 1
    assert mapped["repository"] == REPOSITORY
    assert mapped["commit_hash"] == COMMIT
    assert mapped["redacted"] == scanner.mask_secret(RAW)

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


@pytest.mark.parametrize("line", ["", "\n", "   \n"])
def test_empty_line(line):
    """Blank and whitespace-only stdout lines yield None."""
    assert scanner.parse_line(line) is None


@pytest.mark.parametrize("line", BANNER_LINES)
def test_banner_line(line):
    """The human banner and result lines TruffleHog prints without a machine format yield None."""
    assert scanner.parse_line(line) is None


@pytest.mark.parametrize("line", ["42", "[1, 2]"])
def test_non_object_json(line):
    """Valid JSON that is not a finding object yields None."""
    assert scanner.parse_line(line) is None


def test_filesystem_metadata():
    """A Filesystem finding maps file and line while repository and commit stay unset."""
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
    assert mapped["redacted"] != scanner.mask_secret(RAW)


def test_build_command():
    """The scan command is the binary, subcommand and target followed by --json and --no-update."""
    cmd = scanner.build_command("/usr/bin/trufflehog", "git", "file:///r")

    assert cmd == ["/usr/bin/trufflehog", "git", "file:///r", "--json", "--no-update"]
    assert "--fail" not in cmd, "--fail would return exit code 183 and break the status mapping"
    assert "--no-verification" not in cmd, "verification drives the Verified badge and stays on"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://user:tok@host/org/repo.git", "https://***@host/org/repo.git"),
        ("https://host/org/repo.git", "https://host/org/repo.git"),
        ("file:///tmp/r", "file:///tmp/r"),
        ("/srv/code", "/srv/code"),
    ],
)
def test_redact_target(target, expected):
    """URL userinfo is replaced by '***@'; targets carrying no credentials pass through unchanged."""
    assert scanner.redact_target(target) == expected
