"""Errors surfaced by AuthMatrix."""


class AuthMatrixError(Exception):
    """Base class for expected, user-actionable errors."""


class ConfigurationError(AuthMatrixError):
    """Invalid or incomplete policy configuration."""


class ScopeError(AuthMatrixError):
    """A target or request falls outside the explicitly authorized scope."""


class ScanError(AuthMatrixError):
    """A scan could not be completed safely."""

    def __init__(self, message: str, *, public_detail: str | None = None) -> None:
        super().__init__(message)
        self.public_detail = public_detail


class OpenAPIError(AuthMatrixError):
    """Invalid or unsupported OpenAPI specification."""
