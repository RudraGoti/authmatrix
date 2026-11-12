"""Sanitized exception handling for the AuthMatrix web API."""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from authmatrix.errors import (
    AuthMatrixError,
    ConfigurationError,
    ScanError,
    ScopeError,
)

logger = logging.getLogger(__name__)


class AssetAPIError(Exception):
    """A sanitized inventory or scope API error."""

    def __init__(self, status_code: int, error: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.error = error
        self.detail = detail


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    ),
}


def register_error_handlers(app: FastAPI) -> None:
    """Register handlers that never expose raw exception details."""

    @app.exception_handler(AssetAPIError)
    async def asset_api_error_handler(
        request: Request,
        exc: AssetAPIError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.error, "detail": exc.detail},
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        logger.error("Unexpected AuthMatrix server error (%s).", type(exc).__name__)
        headers = dict(SECURITY_HEADERS)
        if request.url.path == "/api" or request.url.path.startswith("/api/"):
            headers["Cache-Control"] = "no-store"
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "detail": "An unexpected server error occurred.",
            },
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "detail": "The request contains invalid or unexpected fields.",
            },
        )

    @app.exception_handler(ConfigurationError)
    async def configuration_error_handler(
        request: Request,
        exc: ConfigurationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "configuration_error",
                "detail": "The policy configuration is invalid or unavailable.",
            },
        )

    @app.exception_handler(ScopeError)
    async def scope_error_handler(
        request: Request,
        exc: ScopeError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={
                "error": "scope_error",
                "detail": "The requested operation is outside the authorized scope.",
            },
        )

    @app.exception_handler(ScanError)
    async def scan_error_handler(
        request: Request,
        exc: ScanError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "scan_error",
                "detail": exc.public_detail
                or "The scan could not be completed safely.",
            },
        )

    @app.exception_handler(AuthMatrixError)
    async def authmatrix_error_handler(
        request: Request,
        exc: AuthMatrixError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "error": "authmatrix_error",
                "detail": "The requested AuthMatrix operation could not be completed.",
            },
        )
