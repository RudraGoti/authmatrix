"""FastAPI application for the local AuthMatrix web backend."""

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from authmatrix import __version__
from authmatrix.web.errors import register_error_handlers
from authmatrix.web.schemas import (
    ErrorResponse,
    HealthResponse,
    ScanRequest,
    ScanResponse,
    StatusResponse,
)
from authmatrix.web.services import run_policy_scan

CAPABILITIES = [
    "policy_validation",
    "authorization_scanning",
    "sanitized_scan_results",
]


def create_app(*, policy_dir: Path | None = None) -> FastAPI:
    """Create the AuthMatrix API with an injectable policy directory."""
    configured_dir = (
        policy_dir
        if policy_dir is not None
        else Path(os.environ.get("AUTHMATRIX_POLICY_DIR", "examples"))
    )

    app = FastAPI(
        title="AuthMatrix API",
        description="Local API for policy-driven authorization testing.",
        version=__version__,
        docs_url="/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )

    app.state.policy_dir = configured_dir.expanduser().resolve()

    register_error_handlers(app)

    @app.get(
        "/api/health",
        response_model=HealthResponse,
        tags=["system"],
    )
    async def health() -> HealthResponse:
        return HealthResponse(version=__version__)

    @app.get(
        "/api/status",
        response_model=StatusResponse,
        tags=["system"],
    )
    async def status() -> StatusResponse:
        return StatusResponse(
            version=__version__,
            capabilities=CAPABILITIES,
        )

    @app.post(
        "/api/scans",
        response_model=ScanResponse,
        responses={403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
        tags=["scans"],
    )
    async def create_scan(payload: ScanRequest) -> ScanResponse:
        results = run_policy_scan(
            payload.policy_path,
            app.state.policy_dir,
        )
        return results

    @app.get("/api", include_in_schema=False)
    async def api_root() -> JSONResponse:
        return JSONResponse(
            {
                "name": "AuthMatrix API",
                "version": __version__,
                "docs": "/docs",
                "openapi": "/api/openapi.json",
            }
        )

    return app


app = create_app()
