"""Service functions connecting the web API to the AuthMatrix engine."""

import os
import stat
from dataclasses import replace
from pathlib import Path

from authmatrix.config import load_config
from authmatrix.errors import ConfigurationError, OpenAPIError, ScopeError
from authmatrix.execution_scope import (
    DnspythonResolver,
    InventoryExecutionPolicy,
    Resolver,
)
from authmatrix.openapi import (
    DEFAULT_MAX_OPENAPI_BYTES,
    parse_openapi,
    sanitize_openapi_inventory,
)
from authmatrix.openapi_scan import compile_openapi_operations
from authmatrix.scanner import (
    run_authorization_tests,
    run_inventory_authorization_tests,
)
from authmatrix.transport import InventoryScopedTransport
from authmatrix.web.asset_inventory import authorization_eligibility
from authmatrix.web.storage import ScanStore

MAX_OPENAPI_BYTES_LIMIT = 16 * 1024 * 1024


def configured_openapi_max_bytes(value: int | None = None) -> int:
    """Return a validated, bounded size limit for local OpenAPI documents."""
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int)
    ):
        raise ValueError("The OpenAPI size limit must be an integer.")
    raw_value = os.environ.get("AUTHMATRIX_OPENAPI_MAX_BYTES")
    if value is None and raw_value is None:
        return DEFAULT_MAX_OPENAPI_BYTES
    try:
        max_bytes = value if value is not None else int(raw_value)
    except ValueError as exc:
        raise ValueError("AUTHMATRIX_OPENAPI_MAX_BYTES must be an integer.") from exc
    if not 1 <= max_bytes <= MAX_OPENAPI_BYTES_LIMIT:
        raise ValueError(
            "AUTHMATRIX_OPENAPI_MAX_BYTES must be between 1 and "
            f"{MAX_OPENAPI_BYTES_LIMIT}."
        )
    return max_bytes


def resolve_policy_path(policy_path: str, policy_dir: Path) -> Path:
    """Resolve a policy file while preventing traversal and symlink escapes."""
    root = policy_dir.expanduser().resolve()

    if not policy_path or "\x00" in policy_path:
        raise ConfigurationError("Invalid policy path.")

    supplied = Path(policy_path)

    if supplied.is_absolute():
        raise ConfigurationError("Policy path must be relative.")

    if supplied.suffix.lower() not in {".yaml", ".yml"}:
        raise ConfigurationError("Only YAML policy files are supported.")

    try:
        candidate = root / supplied
        resolved_parent = candidate.parent.resolve(strict=True)
        resolved_parent.relative_to(root)
        resolved = resolved_parent / candidate.name
        if not stat.S_ISREG(resolved.lstat().st_mode):
            raise ConfigurationError("Policy path must reference a regular file.")
    except (OSError, ValueError, RuntimeError) as exc:
        raise ConfigurationError("Policy file is unavailable.") from exc

    return resolved


def run_policy_scan(
    policy_path: str,
    policy_dir: Path,
    openapi_path: str | None = None,
    values_path: str | None = None,
    openapi_dir: Path | None = None,
    values_dir: Path | None = None,
    max_openapi_bytes: int = DEFAULT_MAX_OPENAPI_BYTES,
) -> dict:
    """Load an approved policy and run the existing authorization scanner."""
    resolved_path = resolve_policy_path(policy_path, policy_dir)
    config = load_config(resolved_path)
    if (openapi_path is None) != (values_path is None):
        raise ConfigurationError(
            "An OpenAPI document and its explicit values mapping must be "
            "selected together."
        )
    skipped_operations = []
    if openapi_path is not None and values_path is not None:
        specification_dir = openapi_dir or policy_dir
        mapping_dir = values_dir or specification_dir
        resolved_spec = resolve_openapi_path(openapi_path, specification_dir)
        resolved_mapping = resolve_openapi_mapping_path(values_path, mapping_dir)
        config, skipped_operations = compile_openapi_operations(
            config,
            resolved_spec,
            resolved_mapping,
            max_openapi_bytes=max_openapi_bytes,
        )
    results = run_authorization_tests(config)
    if openapi_path is not None:
        results["skipped_operations"] = skipped_operations
        results["summary"]["skipped"] = len(skipped_operations)
        results["limitations"].append(
            "OpenAPI values were supplied explicitly; unmapped or unsupported "
            "policy operations are listed as skipped."
        )
    return results


def run_inventory_policy_scan(
    policy_path: str,
    policy_dir: Path,
    store: ScanStore,
    asset_id: str,
    execution_policy: InventoryExecutionPolicy,
    openapi_path: str | None = None,
    values_path: str | None = None,
    openapi_dir: Path | None = None,
    values_dir: Path | None = None,
    max_openapi_bytes: int = DEFAULT_MAX_OPENAPI_BYTES,
    resolver: Resolver | None = None,
) -> dict:
    """Run explicit policy operations against one currently authorized asset."""
    if not execution_policy.enabled:
        raise ScopeError("Inventory-scoped execution is disabled by server policy.")
    assets, _entries = store.authorization_snapshot()
    asset = next((item for item in assets if item["asset_id"] == asset_id), None)
    if asset is None:
        raise ScopeError("Selected inventory asset is unavailable.")
    if asset["asset_type"] not in {
        "domain",
        "subdomain",
        "hostname",
        "ipv4",
        "ipv6",
    }:
        raise ScopeError("Selected inventory asset is not an executable target.")
    if not authorization_eligibility(asset)[0]:
        raise ScopeError("Selected inventory asset is not currently authorized.")

    host = asset["canonical_value"]
    authority = f"[{host}]" if ":" in host else host
    origin = f"{execution_policy.scheme}://{authority}:{execution_policy.port}"
    config = load_config(resolve_policy_path(policy_path, policy_dir))
    if (openapi_path is None) != (values_path is None):
        raise ConfigurationError(
            "An OpenAPI document and its explicit values mapping must be selected "
            "together."
        )
    skipped_operations = []
    if openapi_path is not None and values_path is not None:
        specification_dir = openapi_dir or policy_dir
        mapping_dir = values_dir or specification_dir
        resolved_spec = resolve_openapi_path(openapi_path, specification_dir)
        resolved_mapping = resolve_openapi_mapping_path(values_path, mapping_dir)
        config, skipped_operations = compile_openapi_operations(
            config,
            resolved_spec,
            resolved_mapping,
            max_openapi_bytes=max_openapi_bytes,
        )

    transport = InventoryScopedTransport(
        store,
        resolver
        or DnspythonResolver(
            nameservers=execution_policy.dns_nameservers,
            timeout_seconds=execution_policy.dns_timeout_seconds,
            max_cname_depth=execution_policy.dns_max_cname_depth,
            max_answers=execution_policy.dns_max_answers,
        ),
        execution_policy,
        asset_id=asset_id,
        asset_type=asset["asset_type"],
        canonical_value=asset["canonical_value"],
    )
    results = run_inventory_authorization_tests(
        replace(config, base_url=origin),
        transport,
    )
    if openapi_path is not None:
        results["skipped_operations"] = skipped_operations
        results["summary"]["skipped"] = len(skipped_operations)
        results["limitations"].append(
            "Inventory-scoped execution used only explicitly configured policy "
            "operations; redirects, retries, and connection reuse are disabled."
        )
    results["limitations"].append(
        "DNS addresses were pinned and checked against current address policy "
        "for each request. Revocation can be delayed while SQLite authorization "
        "is reserved through response headers."
    )
    return results


def list_policy_files(policy_dir: Path) -> list[str]:
    """List valid AuthMatrix YAML policies without checking credentials."""
    root = policy_dir.expanduser().resolve()

    if not root.is_dir():
        return []

    policies = []

    for candidate in root.iterdir():
        if candidate.suffix.lower() not in {".yaml", ".yml"}:
            continue

        try:
            resolved = resolve_policy_path(candidate.name, root)
            if resolved.parent != root:
                continue

            load_config(resolved, check_auth_env=False)
        except (OSError, ValueError, RuntimeError, ConfigurationError):
            continue

        policies.append(candidate.name)

    return sorted(policies, key=str.casefold)


def resolve_openapi_path(spec_path: str, openapi_dir: Path) -> Path:
    """Resolve a local OpenAPI document without allowing path escapes."""
    root = openapi_dir.expanduser().resolve()
    supplied = Path(spec_path)
    if (
        not spec_path
        or "\x00" in spec_path
        or supplied.is_absolute()
        or supplied.name != spec_path
        or supplied.suffix.lower() not in {".json", ".yaml", ".yml"}
    ):
        raise OpenAPIError("OpenAPI path must be a local document filename.")

    try:
        resolved = (root / supplied).resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError, RuntimeError) as exc:
        raise OpenAPIError("OpenAPI document is unavailable.") from exc

    if not resolved.is_file():
        raise OpenAPIError("OpenAPI path must reference a local file.")
    return resolved


def resolve_openapi_mapping_path(mapping_path: str, mapping_dir: Path) -> Path:
    """Resolve a local YAML values mapping without allowing path escapes."""
    root = mapping_dir.expanduser().resolve()
    supplied = Path(mapping_path)
    if (
        not mapping_path
        or "\x00" in mapping_path
        or supplied.is_absolute()
        or supplied.name != mapping_path
        or supplied.suffix.lower() not in {".yaml", ".yml"}
    ):
        raise ConfigurationError(
            "OpenAPI values path must be a local YAML mapping filename."
        )
    try:
        resolved = (root / supplied).resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError, RuntimeError) as exc:
        raise ConfigurationError("OpenAPI values mapping is unavailable.") from exc
    if not resolved.is_file():
        raise ConfigurationError("OpenAPI values path must reference a local file.")
    return resolved


def list_openapi_mapping_files(mapping_dir: Path) -> list[str]:
    """List local value mappings conventionally named *.mapping.yaml."""
    root = mapping_dir.expanduser().resolve()
    if not root.is_dir():
        return []
    mappings = []
    for candidate in root.iterdir():
        if not candidate.name.endswith((".mapping.yaml", ".mapping.yml")):
            continue
        try:
            resolved = resolve_openapi_mapping_path(candidate.name, root)
            resolved.stat()
        except (OSError, ConfigurationError):
            continue
        mappings.append(candidate.name)
    return sorted(mappings, key=str.casefold)


def list_openapi_files(
    openapi_dir: Path,
    max_bytes: int = DEFAULT_MAX_OPENAPI_BYTES,
) -> list[str]:
    """List parseable local OpenAPI documents inside a configured directory."""
    root = openapi_dir.expanduser().resolve()
    if not root.is_dir():
        return []

    documents = []
    for candidate in root.iterdir():
        if candidate.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        try:
            resolved = resolve_openapi_path(candidate.name, root)
            parse_openapi(resolved, max_bytes=max_bytes)
        except (OSError, ValueError, RuntimeError, OpenAPIError):
            continue
        documents.append(candidate.name)
    return sorted(documents, key=str.casefold)


def load_openapi_inventory(
    spec_path: str,
    openapi_dir: Path,
    max_bytes: int = DEFAULT_MAX_OPENAPI_BYTES,
) -> dict:
    """Parse an allowlisted local document into an operation inventory."""
    inventory = parse_openapi(
        resolve_openapi_path(spec_path, openapi_dir),
        max_bytes=max_bytes,
    )
    return sanitize_openapi_inventory(inventory)
