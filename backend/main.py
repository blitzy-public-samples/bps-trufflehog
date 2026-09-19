"""FastAPI application exposing the stored TruffleHog scan results."""

import logging
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import db
import scanner

logging.basicConfig(level=logging.INFO)

WORKER_START_UNAVAILABLE_DETAIL = "the scan worker could not be started; try again shortly"
GZIP_MINIMUM_SIZE = 1024
GZIP_LEVEL = 6
VALIDATION_STATUS = 422
# Bounds the stored target, so no single request can inflate every later scans response.
TARGET_MAX_LENGTH = 2048


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Creates the schema and sweeps orphaned scans before requests are served; yields nothing and
    has no shutdown work."""
    db.init_db()
    yield


# Slash redirection off: a trailing-slash variant of a route is answered 404 rather than with a
# redirect whose target is rebuilt from the request, which would carry the client's own Host header
# into the Location of a reply this app never needs to send.
app = FastAPI(title="TruffleHog Results Pipeline", lifespan=lifespan, redirect_slashes=False)
app.add_middleware(GZipMiddleware, minimum_size=GZIP_MINIMUM_SIZE, compresslevel=GZIP_LEVEL)


def json_safe(value: Any) -> Any:
    """Rebuilds value from the types JSON renders, escaping every character UTF-8 cannot encode and
    carrying anything else as its text; takes any object and returns a renderable equivalent."""
    if isinstance(value, str):
        return value.encode("utf-8", "backslashreplace").decode("utf-8")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):
        return {json_safe(str(key)): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_safe(item) for item in value]
    return json_safe(str(value))


@app.exception_handler(RequestValidationError)
async def handle_invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Answers a rejected request with the 422 detail list of exc, rendered so that an input UTF-8
    cannot encode fails the request rather than the response; request is the rejected request."""
    return JSONResponse(status_code=VALIDATION_STATUS, content={"detail": json_safe(exc.errors())})


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=TARGET_MAX_LENGTH)
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
    redacted = scanner.redact_target(req.target)
    scan = db.create_scan(redacted, req.source)
    try:
        scanner.start_scan(scan["id"], req.source, req.target, binary, redacted=redacted)
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
