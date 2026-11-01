"""Sanitized exception handling for the AuthMatrix web API."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from authmatrix.errors import (
    AuthMatrixError,
    ConfigurationError,
    ScanError,
    ScopeError,
)


def register_error_handlers(app: FastAPI) -> None:
    """Register handlers that never expose raw exception details."""

    @app.exception_handler(Exception)
    async def unexpected_error_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": "internal_server_error",
                "detail": "An unexpected server error occurred.",
            },
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
                "detail": "The scan could not be completed safely.",
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
