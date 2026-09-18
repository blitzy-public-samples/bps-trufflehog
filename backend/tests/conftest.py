"""Fixtures for the results-pipeline test suite."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Keep the two halves separate: joined into one literal, this file itself would match the detector.
PLANTED_TOKEN = "ghp_Ih6X3x7CMamOw5bQFsYO" + "PSzn1nitshTLhhFT"

GIT_LOCAL_CONFIG = (
    ("user.name", "Results Pipeline Test"),
    ("user.email", "tests@example.invalid"),
    ("commit.gpgsign", "false"),
)


def pytest_configure(config):
    """Registers the regression marker, which labels a test that pins an earlier fix rather than one
    of the suite's own named cases; config is the pytest config being initialised."""
    config.addinivalue_line(
        "markers",
        "regression: pins an earlier fix; deselect with -m 'not regression'",
    )


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    """Runs one git command inside repo with output captured; raises CalledProcessError on a non-zero
    exit and returns the completed process."""
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    """Points TRUFFLEHOG_DB_PATH at a per-test SQLite file under tmp_path; returns that path."""
    path = tmp_path / "test.db"
    monkeypatch.setenv("TRUFFLEHOG_DB_PATH", str(path))
    return path


@pytest.fixture
def client(db_path):
    """Yields a TestClient whose lifespan creates the schema in the temp database from db_path."""
    import main
    from fastapi.testclient import TestClient

    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def planted_repo(tmp_path):
    """Builds a single-commit git repository under tmp_path whose config.env holds PLANTED_TOKEN;
    yields its file:// URI, or skips the test when git is unavailable."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    repo = tmp_path / "planted_repo"
    repo.mkdir()
    _git(repo, "init")
    for key, value in GIT_LOCAL_CONFIG:
        _git(repo, "config", key, value)
    (repo / "config.env").write_text(f"GITHUB_TOKEN={PLANTED_TOKEN}\n", encoding="utf-8")
    _git(repo, "add", "config.env")
    _git(repo, "commit", "-q", "-m", "Add service configuration")
    yield "file://" + str(repo)
