"""Errors surfaced by AuthMatrix."""


class AuthMatrixError(Exception):
    """Base class for expected, user-actionable errors."""


class ConfigurationError(AuthMatrixError):
    """Invalid or incomplete policy configuration."""


class ScopeError(AuthMatrixError):
    """A target or request falls outside the explicitly authorized scope."""


class ScanError(AuthMatrixError):
    """A scan could not be completed safely."""


class OpenAPIError(AuthMatrixError):
    """An OpenAPI document could not be parsed."""
