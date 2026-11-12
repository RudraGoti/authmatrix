"""FastAPI application for the local AuthMatrix web backend."""

import logging
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from authmatrix import __version__
from authmatrix.comparison import compare_result_documents
from authmatrix.config import load_config
from authmatrix.reporting import render_html, sanitize_results
from authmatrix.web.asset_inventory import (
    AssetValidationError,
    authorization_eligibility,
    authorization_state,
    canonicalize_asset_value,
    effective_scope,
    evaluate_target,
)
from authmatrix.web.errors import (
    SECURITY_HEADERS,
    AssetAPIError,
    register_error_handlers,
)
from authmatrix.web.schemas import (
    AssetActiveUpdate,
    AssetCreate,
    AssetUpdate,
    AuthorizationUpdate,
    BaselineComparisonRequest,
    ErrorResponse,
    HealthResponse,
    ScanRequest,
    ScanResponse,
    ScopeEntryCreate,
    ScopeTarget,
    StatusResponse,
)
from authmatrix.web.services import (
    configured_openapi_max_bytes,
    list_openapi_files,
    list_openapi_mapping_files,
    list_policy_files,
    load_openapi_inventory,
    resolve_policy_path,
    run_policy_scan,
)
from authmatrix.web.storage import ScanStore

CAPABILITIES = [
    "policy_validation",
    "authorization_scanning",
    "sanitized_scan_results",
    "asset_inventory",
    "authorization_scope_management",
]

DEFAULT_TRUSTED_ORIGINS = (
    "http://127.0.0.1:8001",
    "http://localhost:8001",
)
MAX_ACTIVE_SCAN_DETAIL = "Another scan is already running."
logger = logging.getLogger(__name__)


def _scan_overview(history: list[dict]) -> dict[str, int]:
    return {
        "total": len(history),
        "completed": sum(scan["status"] == "completed" for scan in history),
        "failed": sum(scan["status"] == "failed" for scan in history),
        "findings": sum(scan["findings"] for scan in history),
    }


def _asset_response(asset: dict) -> dict:
    asset["authorization_status"] = authorization_state(asset)
    asset["effective_scope_eligible"], asset["eligibility_reason"] = (
        authorization_eligibility(asset)
    )
    return asset


def _date_value(value):
    return value.isoformat() if value is not None else None


def _origin_tuple(value: str) -> tuple[str, str, int] | None:
    if value != value.strip() or any(
        ord(character) <= 32 or ord(character) == 127 for character in value
    ):
        return None

    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.netloc.endswith(":")
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            return None

        scheme = parsed.scheme.lower()
        port = parsed.port
    except ValueError:
        return None

    return (
        scheme,
        parsed.hostname.lower(),
        port if port is not None else (443 if scheme == "https" else 80),
    )


def _configured_trusted_origins() -> frozenset[tuple[str, str, int]]:
    configured = os.environ.get("AUTHMATRIX_TRUSTED_ORIGINS")
    if configured is not None and not configured.strip():
        raise ValueError(
            "AUTHMATRIX_TRUSTED_ORIGINS must include at least one valid origin."
        )

    values = (
        configured.split(",")
        if configured is not None
        else DEFAULT_TRUSTED_ORIGINS
    )

    origins = []
    for value in values:
        normalized = _origin_tuple(value.strip())
        if normalized is None:
            raise ValueError(
                "AUTHMATRIX_TRUSTED_ORIGINS must contain only valid HTTP(S) "
                "origins without paths."
            )
        origins.append(normalized)

    if not origins:
        raise ValueError("AUTHMATRIX_TRUSTED_ORIGINS must not be empty.")

    return frozenset(origins)


def create_app(
    *,
    policy_dir: Path | None = None,
    data_dir: Path | None = None,
    openapi_dir: Path | None = None,
    openapi_max_bytes: int | None = None,
) -> FastAPI:
    """Create the AuthMatrix API with an injectable policy directory."""
    configured_dir = (
        policy_dir
        if policy_dir is not None
        else Path(os.environ.get("AUTHMATRIX_POLICY_DIR", "examples"))
    )
    configured_data_dir = (
        data_dir.expanduser()
        if data_dir is not None
        else Path(
            os.environ.get(
                "AUTHMATRIX_DATA_DIR",
                str(Path.home() / ".authmatrix"),
            )
        ).expanduser()
    )
    configured_openapi_dir = (
        openapi_dir
        if openapi_dir is not None
        else Path(os.environ.get("AUTHMATRIX_OPENAPI_DIR", "examples"))
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
    app.state.openapi_dir = configured_openapi_dir.expanduser().resolve()
    app.state.openapi_values_dir = Path(
        os.environ.get(
            "AUTHMATRIX_OPENAPI_VALUES_DIR",
            str(configured_openapi_dir),
        )
    ).expanduser().resolve()
    app.state.openapi_max_bytes = configured_openapi_max_bytes(openapi_max_bytes)
    app.state.scan_store = ScanStore(
        configured_data_dir / "authmatrix-scans.sqlite3"
    )
    app.state.scan_lock = Lock()
    app.state.active_scan_id = None
    app.state.trusted_origins = _configured_trusted_origins()

    @app.middleware("http")
    async def enforce_web_security(request: Request, call_next):
        if (
            request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and request.url.path.startswith("/api/")
        ):
            origins = request.headers.getlist("origin")
            fetch_sites = request.headers.getlist("sec-fetch-site")
            request_origin = (
                _origin_tuple(origins[0]) if len(origins) == 1 else None
            )
            fetch_site = (
                fetch_sites[0].strip().lower() if len(fetch_sites) == 1 else ""
            )

            if (
                (origins and request_origin not in app.state.trusted_origins)
                or (fetch_sites and len(fetch_sites) != 1)
                or (
                    fetch_sites
                    and fetch_site not in {"same-origin", "none"}
                )
            ):
                response = JSONResponse(
                    status_code=403,
                    content={
                        "error": "csrf_error",
                        "detail": "Cross-origin requests are not allowed.",
                    },
                )
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)

        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        if request.url.path == "/api" or request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    register_error_handlers(app)

    static_dir = Path(__file__).parent / "static"

    @app.get("/", include_in_schema=False)
    async def dashboard() -> FileResponse:
        return FileResponse(static_dir / "index.html")

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
            capabilities=[
                *CAPABILITIES,
                "persistent_scan_history",
                "baseline_comparison",
                "openapi_inventory",
                "openapi_operation_scanning",
            ],
        )

    @app.get("/api/assets", tags=["assets"])
    async def get_assets(
        search: str | None = Query(default=None, max_length=120),
        asset_type: str | None = Query(
            default=None,
            pattern="^(domain|subdomain|hostname|ipv4|ipv6|ipv4_cidr|ipv6_cidr)$",
        ),
        authorization_status: str | None = Query(
            default=None,
            pattern="^(pending|authorized|expired|revoked|unverified)$",
        ),
        active: bool | None = None,
        sort_by: str = Query(
            default="name",
            pattern="^(name|value|created_at|updated_at)$",
        ),
        sort_order: str = Query(default="asc", pattern="^(asc|desc)$"),
        limit: int = Query(default=100, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=5000),
    ) -> dict:
        assets = app.state.scan_store.list_assets()
        if search:
            needle = search.casefold()
            assets = [
                asset
                for asset in assets
                if needle in asset["name"].casefold()
                or needle in asset["canonical_value"].casefold()
                or needle in asset["description"].casefold()
                or any(needle in tag.casefold() for tag in asset["tags"])
            ]
        if asset_type:
            assets = [asset for asset in assets if asset["asset_type"] == asset_type]
        if authorization_status:
            assets = [
                asset for asset in assets
                if authorization_state(asset) == authorization_status
            ]
        if active is not None:
            assets = [asset for asset in assets if asset["active"] is active]
        assets.sort(
            key=lambda asset: asset[
                "canonical_value" if sort_by == "value" else sort_by
            ].casefold(),
            reverse=sort_order == "desc",
        )
        matching_total = len(assets)
        assets = assets[offset : offset + limit]
        inventory = app.state.scan_store.list_assets()
        summary = {
            "total": len(inventory),
            "authorized": sum(
                authorization_eligibility(asset)[0] for asset in inventory
            ),
            "pending": sum(
                authorization_state(asset) == "pending" for asset in inventory
            ),
            "expired": sum(
                authorization_state(asset) == "expired" for asset in inventory
            ),
            "revoked": sum(
                authorization_state(asset) == "revoked" for asset in inventory
            ),
            "inactive": sum(not asset["active"] for asset in inventory),
        }
        return {
            "summary": summary,
            "matching_total": matching_total,
            "limit": limit,
            "offset": offset,
            "assets": [_asset_response(asset) for asset in assets],
        }

    @app.post("/api/assets", status_code=201, tags=["assets"])
    async def create_asset(payload: AssetCreate) -> dict:
        now = datetime.now(UTC).isoformat()
        record = {
            "asset_id": uuid4().hex,
            "name": payload.name.strip(),
            "asset_type": payload.asset_type,
            "canonical_value": canonicalize_asset_value(
                payload.asset_type, payload.value
            ),
            "description": payload.description,
            "tags": payload.tags,
            "organization": payload.organization.strip(),
            "authorization_status": (
                "authorized" if payload.authorization_confirmed else "pending"
            ),
            "authorization_confirmed": payload.authorization_confirmed,
            "authorization_reference": payload.authorization_reference,
            "authorization_starts_at": _date_value(payload.authorization_starts_at),
            "authorization_expires_at": _date_value(payload.authorization_expires_at),
            "created_at": now,
            "updated_at": now,
        }
        try:
            app.state.scan_store.create_asset(record)
        except sqlite3.IntegrityError as exc:
            raise AssetAPIError(
                409,
                "asset_conflict",
                "An asset with this canonical value already exists.",
            ) from exc
        except ValueError as exc:
            raise AssetAPIError(409, "asset_conflict", str(exc)) from exc
        return _asset_response(app.state.scan_store.get_asset(record["asset_id"]))

    @app.get("/api/assets/{asset_id}", tags=["assets"])
    async def get_asset(asset_id: str) -> dict:
        asset = app.state.scan_store.get_asset(asset_id)
        if asset is None:
            raise AssetAPIError(404, "asset_not_found", "Asset not found.")
        scope_entry = next(
            (
                entry
                for entry in app.state.scan_store.list_scope_entries()
                if entry["asset_id"] == asset_id
            ),
            None,
        )
        return {**_asset_response(asset), "scope": scope_entry}

    @app.put("/api/assets/{asset_id}", tags=["assets"])
    async def update_asset(asset_id: str, payload: AssetUpdate) -> dict:
        now = datetime.now(UTC).isoformat()
        record = {
            "name": payload.name.strip(),
            "asset_type": payload.asset_type,
            "canonical_value": canonicalize_asset_value(
                payload.asset_type, payload.value
            ),
            "description": payload.description,
            "tags": payload.tags,
            "organization": payload.organization.strip(),
            "updated_at": now,
        }
        try:
            updated = app.state.scan_store.update_asset(asset_id, record)
        except sqlite3.IntegrityError as exc:
            raise AssetAPIError(
                409,
                "asset_conflict",
                "An asset with this canonical value already exists.",
            ) from exc
        if not updated:
            raise AssetAPIError(404, "asset_not_found", "Asset not found.")
        return _asset_response(app.state.scan_store.get_asset(asset_id))

    @app.delete("/api/assets/{asset_id}", status_code=204, tags=["assets"])
    async def delete_asset(asset_id: str) -> None:
        if not app.state.scan_store.delete_asset(asset_id):
            raise AssetAPIError(404, "asset_not_found", "Asset not found.")

    @app.patch("/api/assets/{asset_id}/active", tags=["assets"])
    async def set_asset_active(asset_id: str, payload: AssetActiveUpdate) -> dict:
        updated = app.state.scan_store.set_asset_active(
            asset_id,
            payload.active,
            datetime.now(UTC).isoformat(),
        )
        if not updated:
            raise AssetAPIError(404, "asset_not_found", "Asset not found.")
        return _asset_response(app.state.scan_store.get_asset(asset_id))

    @app.put("/api/assets/{asset_id}/authorization", tags=["assets"])
    async def update_asset_authorization(
        asset_id: str,
        payload: AuthorizationUpdate,
    ) -> dict:
        if app.state.scan_store.get_asset(asset_id) is None:
            raise AssetAPIError(404, "asset_not_found", "Asset not found.")
        authorization = {
            "authorization_status": payload.status,
            "authorization_confirmed": payload.authorization_confirmed,
            "authorization_reference": payload.authorization_reference,
            "authorization_starts_at": _date_value(payload.authorization_starts_at),
            "authorization_expires_at": _date_value(payload.authorization_expires_at),
            "updated_at": datetime.now(UTC).isoformat(),
        }
        if not app.state.scan_store.update_authorization(asset_id, authorization):
            raise AssetAPIError(404, "asset_not_found", "Asset not found.")
        return _asset_response(app.state.scan_store.get_asset(asset_id))

    @app.post("/api/assets/{asset_id}/revoke", tags=["assets"])
    async def revoke_asset_authorization(asset_id: str) -> dict:
        current = app.state.scan_store.get_asset(asset_id)
        if current is None:
            raise AssetAPIError(404, "asset_not_found", "Asset not found.")
        authorization = {
            "authorization_status": "revoked",
            "authorization_confirmed": current["authorization_confirmed"],
            "authorization_reference": current["authorization_reference"],
            "authorization_starts_at": current["authorization_starts_at"],
            "authorization_expires_at": current["authorization_expires_at"],
            "updated_at": datetime.now(UTC).isoformat(),
        }
        app.state.scan_store.update_authorization(asset_id, authorization)
        return _asset_response(app.state.scan_store.get_asset(asset_id))

    @app.get("/api/scope", tags=["scope"])
    async def get_scope() -> dict:
        assets = app.state.scan_store.list_assets()
        entries = app.state.scan_store.list_scope_entries()
        scope = effective_scope(assets, entries)
        return {
            **scope,
            "eligible_count": sum(entry["eligible"] for entry in scope["included"]),
            "ineligible_count": sum(
                not entry["eligible"] for entry in scope["included"]
            ),
            "message": (
                "No DNS resolution is performed. Domain entries never authorize "
                "the IP address returned by DNS."
            ),
        }

    @app.post("/api/scope", status_code=201, tags=["scope"])
    async def set_scope_entry(payload: ScopeEntryCreate) -> dict:
        if not app.state.scan_store.set_scope_entry(
            payload.asset_id,
            payload.direction,
            datetime.now(UTC).isoformat(),
        ):
            raise AssetAPIError(404, "asset_not_found", "Asset not found.")
        return await get_scope()

    @app.delete("/api/scope/{asset_id}", status_code=204, tags=["scope"])
    async def remove_scope_entry(asset_id: str) -> None:
        if not app.state.scan_store.remove_scope_entry(asset_id):
            raise AssetAPIError(404, "scope_entry_not_found", "Scope entry not found.")

    @app.post("/api/scope/validate", tags=["scope"])
    async def validate_scope_target(payload: ScopeTarget) -> dict:
        try:
            return evaluate_target(
                app.state.scan_store.list_assets(),
                app.state.scan_store.list_scope_entries(),
                payload.asset_type,
                payload.value,
            )
        except AssetValidationError as exc:
            raise AssetAPIError(422, "asset_validation_error", str(exc)) from exc

    @app.get("/api/policies", tags=["policies"])
    async def get_policies() -> dict[str, list[str]]:
        return {"policies": list_policy_files(app.state.policy_dir)}

    @app.get("/api/openapi/specs", tags=["openapi"])
    async def get_openapi_specs() -> dict[str, list[str]]:
        return {
            "specifications": list_openapi_files(
                app.state.openapi_dir,
                app.state.openapi_max_bytes,
            )
        }

    @app.get("/api/openapi/mappings", tags=["openapi"])
    async def get_openapi_mappings() -> dict[str, list[str]]:
        return {
            "mappings": list_openapi_mapping_files(app.state.openapi_values_dir)
        }

    @app.get("/api/openapi/specs/{spec_path}", tags=["openapi"])
    async def get_openapi_spec(spec_path: str) -> dict:
        return load_openapi_inventory(
            spec_path,
            app.state.openapi_dir,
            app.state.openapi_max_bytes,
        )

    @app.get("/api/policies/{policy_path}", tags=["policies"])
    async def get_policy(policy_path: str) -> dict[str, object]:
        config = load_config(
            resolve_policy_path(policy_path, app.state.policy_dir),
            check_auth_env=False,
        )
        return {
            "name": Path(policy_path).name,
            "target": config.base_url,
            "authorized": config.authorized,
            "allowed_hosts": list(config.allowed_hosts),
            "timeout_seconds": config.timeout_seconds,
            "max_requests": config.max_requests,
            "max_response_bytes": config.max_response_bytes,
            "allow_destructive": config.allow_destructive,
            "identities": [
                {"name": identity.name, "role": identity.role}
                for identity in config.identities.values()
            ],
            "resources": [
                {"name": resource.name, "count": len(resource.ids)}
                for resource in config.resources.values()
            ],
            "operations": [
                {
                    "id": operation.operation_id,
                    "category": operation.category,
                    "method": operation.method,
                    "path": operation.path,
                }
                for operation in config.operations
            ],
        }

    @app.get("/api/scans", tags=["scans"])
    async def get_scans() -> dict[str, object]:
        scans = app.state.scan_store.list_scans()
        return {"summary": _scan_overview(scans), "scans": scans}

    @app.get("/api/findings", tags=["findings"])
    async def get_findings() -> dict[str, list[dict]]:
        return {"findings": app.state.scan_store.list_findings()}

    @app.post(
        "/api/comparisons",
        response_model=None,
        tags=["comparisons"],
    )
    async def compare_scans(payload: BaselineComparisonRequest) -> dict:
        baseline = app.state.scan_store.get_result(payload.baseline_scan_id)
        current = app.state.scan_store.get_result(payload.current_scan_id)
        if baseline is None or current is None:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "scan_not_found",
                    "detail": "Both completed scans must be available.",
                },
            )
        return compare_result_documents(baseline, current)

    @app.post(
        "/api/scans",
        response_model=ScanResponse,
        responses={
            403: {"model": ErrorResponse},
            409: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
        },
        tags=["scans"],
    )
    async def create_scan(payload: ScanRequest) -> ScanResponse | JSONResponse:
        if (payload.openapi_spec is None) != (payload.values_mapping is None):
            return JSONResponse(
                status_code=422,
                content={
                    "error": "validation_error",
                    "detail": (
                        "OpenAPI document and values mapping must be provided "
                        "together."
                    ),
                },
            )
        if payload.authorization_confirmed is not True:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "authorization_required",
                    "detail": "Confirm authorization before starting a scan.",
                },
            )
        if not app.state.scan_lock.acquire(blocking=False):
            return JSONResponse(
                status_code=409,
                content={
                    "error": "scan_in_progress",
                    "detail": MAX_ACTIVE_SCAN_DETAIL,
                },
            )

        scan_id = uuid4().hex
        started_at = datetime.now(UTC).isoformat()
        try:
            app.state.scan_store.start(
                scan_id,
                started_at,
                Path(payload.policy_path).name,
            )
            logger.info(
                "scan_started scan_id=%s policy=%s",
                scan_id,
                Path(payload.policy_path).name,
            )
            app.state.active_scan_id = scan_id
            result = await run_in_threadpool(
                run_policy_scan,
                payload.policy_path,
                app.state.policy_dir,
                payload.openapi_spec,
                payload.values_mapping,
                app.state.openapi_dir,
                app.state.openapi_values_dir,
                app.state.openapi_max_bytes,
            )
            result["scan_id"] = scan_id
            result["policy"] = Path(payload.policy_path).name
            result["status"] = "completed"
            result["summary"].setdefault("skipped", 0)
            result.setdefault("skipped_operations", [])
            result = sanitize_results(result)
            app.state.scan_store.complete(scan_id, result)
            logger.info(
                "scan_completed scan_id=%s requests=%s findings=%s failed=%s",
                scan_id,
                result["summary"]["requests"],
                result["summary"]["findings"],
                result["summary"]["failed"],
            )
            return result
        except Exception as exc:
            app.state.scan_store.fail(scan_id)
            logger.error(
                "scan_failed scan_id=%s error_type=%s",
                scan_id,
                type(exc).__name__,
            )
            raise
        finally:
            app.state.active_scan_id = None
            app.state.scan_lock.release()

    @app.get("/api/scans/{scan_id}", response_model=None, tags=["scans"])
    async def get_scan(scan_id: str) -> dict | JSONResponse:
        result = app.state.scan_store.get_result(scan_id)
        if result is not None:
            return result
        record = app.state.scan_store.get_scan(scan_id)
        if record is None:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "scan_not_found",
                    "detail": "The requested scan is not available.",
                },
            )
        return record

    @app.get(
        "/api/scans/{scan_id}/report.json",
        response_model=None,
        tags=["reports"],
    )
    async def get_json_report(scan_id: str) -> dict | JSONResponse:
        result = app.state.scan_store.get_result(scan_id)
        if result is None:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "report_not_found",
                    "detail": "The requested report is not available.",
                },
            )
        return sanitize_results(result)

    @app.get(
        "/api/scans/{scan_id}/report.html",
        response_model=None,
        tags=["reports"],
    )
    async def get_html_report(scan_id: str) -> HTMLResponse | JSONResponse:
        result = app.state.scan_store.get_result(scan_id)
        if result is None:
            return JSONResponse(
                status_code=404,
                content={
                    "error": "report_not_found",
                    "detail": "The requested report is not available.",
                },
            )
        return HTMLResponse(render_html(result))

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

    app.mount(
        "/static",
        StaticFiles(directory=static_dir),
        name="static",
    )

    return app


app = create_app()
