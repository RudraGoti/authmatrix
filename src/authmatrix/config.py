"""Load and validate scan policies."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from authmatrix.errors import ConfigurationError, ScopeError

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DESTRUCTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ALL_METHODS = SAFE_METHODS | DESTRUCTIVE_METHODS
RESPONSE_ID_PATH = re.compile(
    r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+|\[[0-9]+\])*$"
)


@dataclass(frozen=True)
class AuthConfig:
    kind: str
    token_env: str | None = None
    username_env: str | None = None
    password_env: str | None = None


@dataclass(frozen=True)
class Identity:
    name: str
    role: str
    auth: AuthConfig


@dataclass(frozen=True)
class Resource:
    name: str
    ids: tuple[str, ...]
    owner_by_id: dict[str, str]


@dataclass(frozen=True)
class Operation:
    operation_id: str
    category: str
    method: str
    path: str
    resource: str | None
    expected: dict[str, Any]
    response_id_path: str = "id"


@dataclass(frozen=True)
class ScanConfig:
    authorized: bool
    base_url: str
    allowed_hosts: tuple[str, ...]
    timeout_seconds: float
    max_requests: int
    max_response_bytes: int
    allow_destructive: bool
    identities: dict[str, Identity]
    resources: dict[str, Resource]
    operations: tuple[Operation, ...]
    source: Path


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label} must be a mapping.")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{label} must be a non-empty string.")
    return value.strip()


def _positive_number(
    value: Any, label: str, *, integer: bool = False
) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigurationError(f"{label} must be a positive number.")
    if integer and not isinstance(value, int):
        raise ConfigurationError(f"{label} must be a positive integer.")
    return value


def validate_scope(base_url: str, allowed_hosts: tuple[str, ...]) -> None:
    """Ensure the target is an explicitly authorized loopback IP address."""
    parsed = urlsplit(base_url)

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ScopeError(
            "scope.base_url must be an http(s) URL with a loopback IP address, "
            "no credentials, and no path, query, or fragment."
        )

    try:
        _ = parsed.port
    except ValueError as exc:
        raise ScopeError("scope.base_url must contain a valid port.") from exc

    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ScopeError("Only literal loopback IP addresses are in scope.") from exc

    if not address.is_loopback:
        raise ScopeError("Only loopback IP addresses are in scope.")

    if parsed.hostname not in allowed_hosts:
        raise ScopeError(
            f"Target host {parsed.hostname!r} is not listed in scope.allowed_hosts."
        )

    for host in allowed_hosts:
        try:
            allowlisted_address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ScopeError(
                "scope.allowed_hosts entries must be literal loopback IPs."
            ) from exc

        if not allowlisted_address.is_loopback:
            raise ScopeError("scope.allowed_hosts entries must be loopback IPs.")


def load_config(path: str | Path, *, check_auth_env: bool = False) -> ScanConfig:
    source = Path(path).expanduser().resolve()

    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"Cannot read configuration file: {source}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"Invalid YAML in configuration file: {source}"
        ) from exc

    root = _mapping(raw, "Configuration")

    if root.get("version") != 1:
        raise ConfigurationError("Configuration version must be 1.")

    scope = _mapping(root.get("scope"), "scope")

    authorized = scope.get("authorized") is True
    if not authorized:
        raise ScopeError(
            "Set scope.authorized: true to explicitly authorize this target."
        )

    base_url = _string(scope.get("base_url"), "scope.base_url").rstrip("/")

    hosts_value = scope.get("allowed_hosts")
    if not isinstance(hosts_value, list) or not hosts_value:
        raise ConfigurationError("scope.allowed_hosts must be a non-empty list.")

    allowed_hosts = tuple(
        _string(host, "scope.allowed_hosts entry") for host in hosts_value
    )

    if len(set(allowed_hosts)) != len(allowed_hosts):
        raise ConfigurationError("scope.allowed_hosts entries must be unique.")

    validate_scope(base_url, allowed_hosts)

    timeout = _positive_number(
        scope.get("timeout_seconds", 3), "scope.timeout_seconds"
    )
    request_limit = _positive_number(
        scope.get("max_requests", 25),
        "scope.max_requests",
        integer=True,
    )
    response_limit = _positive_number(
        scope.get("max_response_bytes", 65536),
        "scope.max_response_bytes",
        integer=True,
    )

    allow_destructive = scope.get("allow_destructive", False)
    if not isinstance(allow_destructive, bool):
        raise ConfigurationError("scope.allow_destructive must be a boolean.")

    raw_identities = _mapping(root.get("identities"), "identities")
    if not raw_identities:
        raise ConfigurationError("At least one identity must be configured.")

    identities: dict[str, Identity] = {}

    for name, value in raw_identities.items():
        identity_name = _string(name, "identity name")
        entry = _mapping(value, f"identities.{identity_name}")

        role = _string(entry.get("role"), f"identities.{identity_name}.role")
        auth_raw = _mapping(
            entry.get("auth"), f"identities.{identity_name}.auth"
        )
        kind = _string(
            auth_raw.get("type"),
            f"identities.{identity_name}.auth.type",
        )

        if kind == "bearer":
            auth = AuthConfig(
                kind=kind,
                token_env=_string(
                    auth_raw.get("token_env"),
                    f"identities.{identity_name}.auth.token_env",
                ),
            )
        elif kind == "basic":
            auth = AuthConfig(
                kind=kind,
                username_env=_string(
                    auth_raw.get("username_env"),
                    f"identities.{identity_name}.auth.username_env",
                ),
                password_env=_string(
                    auth_raw.get("password_env"),
                    f"identities.{identity_name}.auth.password_env",
                ),
            )
        else:
            raise ConfigurationError(
                f"identities.{identity_name}.auth.type must be bearer or basic."
            )

        if check_auth_env:
            env_names = (
                [auth.token_env]
                if auth.kind == "bearer"
                else [auth.username_env, auth.password_env]
            )

            missing = [
                env_name for env_name in env_names if not os.environ.get(env_name)
            ]

            if missing:
                raise ConfigurationError(
                    "Missing authentication environment variable(s): "
                    f"{', '.join(missing)}."
                )

        identities[identity_name] = Identity(identity_name, role, auth)

    raw_resources = root.get("resources", [])
    if not isinstance(raw_resources, list):
        raise ConfigurationError("resources must be a list.")

    resources: dict[str, Resource] = {}

    for index, value in enumerate(raw_resources):
        entry = _mapping(value, f"resources[{index}]")
        name = _string(entry.get("name"), f"resources[{index}].name")

        if name in resources:
            raise ConfigurationError(f"Duplicate resource name: {name}.")

        ids_raw = entry.get("ids")
        if not isinstance(ids_raw, list) or not ids_raw:
            raise ConfigurationError(
                f"resources.{name}.ids must be a non-empty list."
            )

        ids = tuple(
            _string(item, f"resources.{name}.ids entry") for item in ids_raw
        )

        if len(set(ids)) != len(ids):
            raise ConfigurationError(f"resources.{name}.ids must be unique.")

        owners_raw = entry.get("owner_by_id", {})
        owners = _mapping(owners_raw, f"resources.{name}.owner_by_id")

        for resource_id, owner in owners.items():
            if str(resource_id) not in ids:
                raise ConfigurationError(
                    f"Owner mapping references unknown {name} resource "
                    f"{resource_id!r}."
                )

            if not isinstance(owner, str) or owner not in identities:
                raise ConfigurationError(f"Unknown owner identity {owner!r}.")

        resources[name] = Resource(
            name,
            ids,
            {str(key): str(value) for key, value in owners.items()},
        )

    raw_operations = root.get("operations")
    if not isinstance(raw_operations, list) or not raw_operations:
        raise ConfigurationError("operations must be a non-empty list.")

    operations: list[Operation] = []
    seen_operations: set[str] = set()

    for index, value in enumerate(raw_operations):
        entry = _mapping(value, f"operations[{index}]")
        operation_id = _string(entry.get("id"), f"operations[{index}].id")

        if operation_id in seen_operations:
            raise ConfigurationError(f"Duplicate operation id: {operation_id}.")

        seen_operations.add(operation_id)

        category = _string(
            entry.get("category"),
            f"operations.{operation_id}.category",
        )

        if category not in {"BOLA", "BFLA"}:
            raise ConfigurationError(
                f"Operation {operation_id} category must be BOLA or BFLA."
            )

        method = _string(
            entry.get("method"),
            f"operations.{operation_id}.method",
        ).upper()

        if method not in ALL_METHODS:
            raise ConfigurationError(
                f"Operation {operation_id} method must be one of "
                f"{', '.join(sorted(ALL_METHODS))}."
            )

        if method in DESTRUCTIVE_METHODS and not allow_destructive:
            raise ScopeError(
                f"Operation {operation_id} uses destructive method {method}; "
                "set scope.allow_destructive: true only for an authorized local lab."
            )

        route = _string(
            entry.get("path"),
            f"operations.{operation_id}.path",
        )

        if (
            not route.startswith("/")
            or "://" in route
            or "?" in route
            or "#" in route
        ):
            raise ConfigurationError(
                f"Operation {operation_id} path must be a relative absolute-path route."
            )

        if ".." in route.split("/"):
            raise ConfigurationError(
                f"Operation {operation_id} path cannot contain '..'."
            )

        resource_value = entry.get("resource")
        resource = (
            _string(resource_value, f"operations.{operation_id}.resource")
            if resource_value is not None
            else None
        )

        if category == "BOLA" and (resource is None or resource not in resources):
            raise ConfigurationError(
                f"BOLA operation {operation_id} must reference a configured resource."
            )

        if category == "BFLA" and resource is not None:
            raise ConfigurationError(
                f"BFLA operation {operation_id} cannot reference a resource."
            )

        response_id_path = entry.get("response_id_path", "id")

        if category == "BFLA":
            if "response_id_path" in entry:
                raise ConfigurationError(
                    f"BFLA operation {operation_id} cannot define response_id_path."
                )
        else:
            if (
                not isinstance(response_id_path, str)
                or not RESPONSE_ID_PATH.fullmatch(response_id_path)
            ):
                raise ConfigurationError(
                    f"Operation {operation_id} has an invalid response_id_path."
                )

        expected = _mapping(
            entry.get("expected"),
            f"operations.{operation_id}.expected",
        )

        if set(expected) != set(identities):
            raise ConfigurationError(
                f"Operation {operation_id} expected decisions must cover "
                "every identity."
            )

        for identity_name, decisions in expected.items():
            if resource is None:
                if (
                    not isinstance(decisions, str)
                    or decisions not in {"allow", "deny"}
                ):
                    raise ConfigurationError(
                        f"Expected decision for {operation_id}/{identity_name} "
                        "must be allow or deny."
                    )
            else:
                decisions_map = _mapping(
                    decisions,
                    f"operations.{operation_id}.expected.{identity_name}",
                )

                if set(decisions_map) != set(resources[resource].ids):
                    raise ConfigurationError(
                        f"Expected decisions for {operation_id}/{identity_name} "
                        f"must cover all {resource} ids."
                    )

                if any(
                    not isinstance(decision, str)
                    or decision not in {"allow", "deny"}
                    for decision in decisions_map.values()
                ):
                    raise ConfigurationError(
                        f"Expected decisions for {operation_id}/{identity_name} "
                        "must be allow or deny."
                    )

        placeholder_names = {
            part[1:-1]
            for part in route.split("/")
            if part.startswith("{") and part.endswith("}")
        }

        if resource is None and placeholder_names:
            raise ConfigurationError(
                f"BFLA operation {operation_id} cannot contain resource "
                "path placeholders."
            )

        placeholder_parts = [
            part
            for part in route.split("/")
            if part.startswith("{") and part.endswith("}")
        ]

        if any(part == "{}" for part in placeholder_parts):
            raise ConfigurationError(
                f"BOLA operation {operation_id} must use a non-empty "
                "resource path placeholder."
            )

        if resource is not None and len(placeholder_parts) != 1:
            raise ConfigurationError(
                f"BOLA operation {operation_id} must contain a resource "
                "path placeholder."
            )

        operations.append(
            Operation(
                operation_id,
                category,
                method,
                route,
                resource,
                expected,
                response_id_path,
            )
        )

    return ScanConfig(
        authorized=True,
        base_url=base_url,
        allowed_hosts=allowed_hosts,
        timeout_seconds=float(timeout),
        max_requests=int(request_limit),
        max_response_bytes=int(response_limit),
        allow_destructive=allow_destructive,
        identities=identities,
        resources=resources,
        operations=tuple(operations),
        source=source,
    )
