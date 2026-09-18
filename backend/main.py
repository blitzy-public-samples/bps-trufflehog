"""FastAPI application exposing the stored TruffleHog scan results."""

import logging
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import db
import scanner

logging.basicConfig(level=logging.INFO)

WORKER_START_UNAVAILABLE_DETAIL = "the scan worker could not be started; try again shortly"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Creates the schema and sweeps orphaned scans before requests are served; yields nothing and
    has no shutdown work."""
    db.init_db()
    yield


app = FastAPI(title="TruffleHog Results Pipeline", lifespan=lifespan)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1)
    source: Literal["git", "filesystem"] = "git"


@app.post("/api/scans", status_code=202)
def create_scan(req: ScanRequest):
    """Starts a background scan of the requested target and returns the new running scan object.
    Fails with 503 when no trufflehog executable resolves, before any scan row is written, and when
    the worker cannot start, in which case start_scan has attempted to mark that row failed."""
    try:
        binary = scanner.resolve_binary()
    except scanner.TrufflehogNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    scan = db.create_scan(scanner.redact_target(req.target), req.source)
    try:
        scanner.start_scan(scan["id"], req.source, req.target, binary)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=WORKER_START_UNAVAILABLE_DETAIL) from exc
    return scan


@app.get("/api/scans")
def list_scans():
    """Returns every scan object, each with its finding_count, newest scan first."""
    return db.list_scans()


@app.get("/api/scans/{scan_id}/findings")
def list_scan_findings(scan_id: int):
    """Returns the findings of one scan, newest first, and 404s when no scan has that id."""
    if not db.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    return db.list_findings(scan_id)


@app.get("/api/findings")
def list_findings():
    """Returns every finding across all scans, newest first."""
    return db.list_findings()
