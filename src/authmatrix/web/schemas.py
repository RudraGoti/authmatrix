"""Strict request and response schemas for the AuthMatrix web API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base model that rejects unexpected input fields."""

    model_config = ConfigDict(extra="forbid")


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str


class StatusResponse(BaseModel):
    status: Literal["ready"] = "ready"
    version: str
    capabilities: list[str]


class ScanRequest(StrictModel):
    """A scan can only reference a server-side policy file."""

    policy_path: str = Field(
        min_length=1,
        max_length=255,
        description="Policy file path relative to the configured policy directory.",
        examples=["policy.yaml"],
    )
    authorization_confirmed: bool = False
    openapi_spec: str | None = Field(default=None, min_length=1, max_length=255)
    values_mapping: str | None = Field(default=None, min_length=1, max_length=255)


class BaselineComparisonRequest(StrictModel):
    baseline_scan_id: str = Field(min_length=1, max_length=64)
    current_scan_id: str = Field(min_length=1, max_length=64)


class ScanSummary(BaseModel):
    requests: int
    passed: int
    failed: int
    inconclusive: int
    findings: int
    skipped: int = 0


class ScanResponse(BaseModel):
    status: Literal["completed"] = "completed"
    schema_version: int
    scan_id: str | None = None
    generated_at: str
    target: str
    policy: str | None = None
    identities: list[dict[str, str]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    summary: ScanSummary
    findings: list[dict[str, object]]
    checks: list[dict[str, object]]
    skipped_operations: list[dict[str, str]] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    error: str
    detail: str
