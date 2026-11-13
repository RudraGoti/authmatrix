"""Strict request and response schemas for the AuthMatrix web API."""

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from authmatrix.web.asset_inventory import canonicalize_asset_value


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


class InventoryScanRequest(ScanRequest):
    """Selects a stored asset; it cannot provide execution or authorization policy."""

    asset_id: str = Field(min_length=1, max_length=64)


class BaselineComparisonRequest(StrictModel):
    baseline_scan_id: str = Field(min_length=1, max_length=64)
    current_scan_id: str = Field(min_length=1, max_length=64)


class AssetFields(StrictModel):
    name: str = Field(min_length=1, max_length=120, strict=True)
    asset_type: Literal[
        "domain", "subdomain", "hostname", "ipv4", "ipv6", "ipv4_cidr", "ipv6_cidr"
    ]
    value: str = Field(min_length=1, max_length=253, strict=True)
    description: str = Field(default="", max_length=2000, strict=True)
    tags: list[str] = Field(default_factory=list, max_length=20)
    organization: str = Field(default="Local workspace", min_length=1, max_length=120)

    @model_validator(mode="after")
    def validate_asset_fields(self):
        if not self.name.strip() or not self.organization.strip():
            raise ValueError("Name and organization must not be blank.")
        if any(not tag.strip() or len(tag) > 40 for tag in self.tags):
            raise ValueError("Tags must contain 1 to 40 characters.")
        canonicalize_asset_value(self.asset_type, self.value)
        return self


class AssetCreate(AssetFields):
    authorization_confirmed: StrictBool = False
    authorization_reference: str | None = Field(default=None, max_length=255)
    authorization_starts_at: date | None = None
    authorization_expires_at: date | None = None

    @model_validator(mode="after")
    def validate_authorization(self):
        _validate_authorization_dates(
            self.authorization_starts_at,
            self.authorization_expires_at,
        )
        if self.authorization_confirmed and not (
            self.authorization_reference and self.authorization_reference.strip()
        ):
            raise ValueError("Authorization confirmation requires a reference.")
        if self.authorization_reference is not None and (
            not self.authorization_reference.strip()
            or self.authorization_reference != self.authorization_reference.strip()
        ):
            raise ValueError("Authorization reference must not be blank or padded.")
        return self


class AssetUpdate(AssetFields):
    pass


class AuthorizationUpdate(StrictModel):
    status: Literal["pending", "authorized", "unverified"]
    authorization_confirmed: StrictBool = False
    authorization_reference: str | None = Field(default=None, max_length=255)
    authorization_starts_at: date | None = None
    authorization_expires_at: date | None = None

    @model_validator(mode="after")
    def validate_authorization(self):
        _validate_authorization_dates(
            self.authorization_starts_at,
            self.authorization_expires_at,
        )
        if self.status == "authorized" and not self.authorization_confirmed:
            raise ValueError("Authorization requires explicit confirmation.")
        if self.status == "authorized" and not (
            self.authorization_reference and self.authorization_reference.strip()
        ):
            raise ValueError("Authorization requires a reference.")
        if self.authorization_reference is not None and (
            not self.authorization_reference.strip()
            or self.authorization_reference != self.authorization_reference.strip()
        ):
            raise ValueError("Authorization reference must not be blank or padded.")
        if self.status != "authorized" and self.authorization_confirmed:
            raise ValueError("Only authorized status can be confirmed.")
        return self


class AssetActiveUpdate(StrictModel):
    active: StrictBool


class ScopeEntryCreate(StrictModel):
    asset_id: str = Field(min_length=1, max_length=64)
    direction: Literal["include", "exclude"]


class ScopeTarget(StrictModel):
    asset_type: Literal[
        "domain", "subdomain", "hostname", "ipv4", "ipv6", "ipv4_cidr", "ipv6_cidr"
    ]
    value: str = Field(min_length=1, max_length=253, strict=True)

    @model_validator(mode="after")
    def validate_target(self):
        canonicalize_asset_value(self.asset_type, self.value)
        return self


def _validate_authorization_dates(
    starts_at: date | None,
    expires_at: date | None,
) -> None:
    if starts_at and expires_at and expires_at < starts_at:
        raise ValueError("Authorization expiry must not precede its start date.")


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
