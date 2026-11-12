"""Compile explicit OpenAPI value mappings into existing scan operations."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from authmatrix.config import DESTRUCTIVE_METHODS, Operation, ScanConfig
from authmatrix.errors import ConfigurationError, OpenAPIError
from authmatrix.openapi import DEFAULT_MAX_OPENAPI_BYTES, parse_openapi

MAX_MAPPING_BYTES = 1024 * 1024
RESOURCE_ID_MARKER = "$authmatrix_resource_id"
IDENTITY_VALUES_MARKER = "$authmatrix_by_identity"
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
FORBIDDEN_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "expect",
    "host",
    "keep-alive",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class _SkipOperation(Exception):
    """An operation is safe to omit but cannot be executed from supplied values."""


def _read_mapping(path: Path) -> dict[str, Any]:
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ConfigurationError("OpenAPI value mapping is unavailable.") from exc

    try:
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ConfigurationError(
                    "OpenAPI value mapping must be a regular local file."
                )
            content = source.read(MAX_MAPPING_BYTES + 1)
            if len(content) > MAX_MAPPING_BYTES:
                raise ConfigurationError(
                    "OpenAPI value mapping exceeds the 1 MiB size limit."
                )
        document = yaml.safe_load(content.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigurationError(
            "OpenAPI value mapping must be valid UTF-8 YAML."
        ) from exc
    except (OSError, yaml.YAMLError, RecursionError) as exc:
        raise ConfigurationError("OpenAPI value mapping is not valid YAML.") from exc
    if not isinstance(document, dict) or set(document) != {"operations"}:
        raise ConfigurationError(
            "OpenAPI value mapping must contain only an operations mapping."
        )
    if not isinstance(document["operations"], dict):
        raise ConfigurationError("OpenAPI value mapping operations must be a mapping.")
    return document["operations"]


def _validate_json_value(value: Any, label: str) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ConfigurationError(
                f"{label} contains invalid Unicode text."
            ) from exc
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{label} must contain only JSON values.") from exc


def _validate_value_mapping(
    value: Any,
    identities: set[str],
    label: str,
    active: set[int] | None = None,
    depth: int = 0,
) -> None:
    if not isinstance(value, (dict, list)):
        _validate_json_value(value, label)
        return
    active = active if active is not None else set()
    identity = id(value)
    if identity in active:
        raise ConfigurationError(f"{label} contains a cyclic YAML alias.")
    if depth > 100:
        raise ConfigurationError(f"{label} nesting exceeds 100 levels.")
    active.add(identity)
    try:
        if isinstance(value, dict):
            if RESOURCE_ID_MARKER in value:
                if value != {RESOURCE_ID_MARKER: True}:
                    raise ConfigurationError(
                        f"{label} uses an invalid {RESOURCE_ID_MARKER} marker."
                    )
                return
            if IDENTITY_VALUES_MARKER in value:
                values = value[IDENTITY_VALUES_MARKER]
                if not isinstance(values, dict) or set(values) != identities:
                    raise ConfigurationError(
                        f"{label} {IDENTITY_VALUES_MARKER} must provide a value "
                        "for every configured identity."
                    )
                for identity_name, item in values.items():
                    _validate_value_mapping(
                        item,
                        identities,
                        f"{label}/{identity_name}",
                        active,
                        depth + 1,
                    )
                return
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ConfigurationError(f"{label} object keys must be strings.")
                _validate_json_value(key, label)
                _validate_value_mapping(item, identities, label, active, depth + 1)
            return
        for item in value:
            _validate_value_mapping(item, identities, label, active, depth + 1)
    finally:
        active.remove(identity)


def _parameter_value_matches(value: Any, schema: dict[str, Any]) -> bool:
    if isinstance(value, dict) and value == {RESOURCE_ID_MARKER: True}:
        value = "resource-id"
    if isinstance(value, dict) and IDENTITY_VALUES_MARKER in value:
        return all(
            _parameter_value_matches(item, schema)
            for item in value[IDENTITY_VALUES_MARKER].values()
        )
    expected_type = schema.get("type")
    if expected_type is None:
        return (
            isinstance(value, (str, int, float, bool, list, dict))
            and value is not None
        )
    valid = {
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float))
        and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "array": lambda item: isinstance(item, list),
        "object": lambda item: isinstance(item, dict),
    }.get(expected_type)
    if valid is None or value is None or not valid(value):
        return False
    if expected_type == "array" and isinstance(schema.get("items"), dict):
        return all(_parameter_value_matches(item, schema["items"]) for item in value)
    return True


def _mapping_resolves_to_scalar(value: Any) -> bool:
    if isinstance(value, dict) and value == {RESOURCE_ID_MARKER: True}:
        return True
    if isinstance(value, dict) and IDENTITY_VALUES_MARKER in value:
        return all(
            _mapping_resolves_to_scalar(item)
            for item in value[IDENTITY_VALUES_MARKER].values()
        )
    return isinstance(value, (str, int, float, bool)) and value is not None


def _parameter_values_serializable(value: Any) -> bool:
    if isinstance(value, dict):
        if value == {RESOURCE_ID_MARKER: True}:
            return True
        if IDENTITY_VALUES_MARKER in value:
            return all(
                _parameter_values_serializable(item)
                for item in value[IDENTITY_VALUES_MARKER].values()
            )
        return all(
            isinstance(key, str) and _mapping_resolves_to_scalar(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return all(_mapping_resolves_to_scalar(item) for item in value)
    return isinstance(value, (str, int, float, bool)) and value is not None


def _header_scalar_supported(value: Any) -> bool:
    if isinstance(value, dict) and IDENTITY_VALUES_MARKER in value:
        return all(
            _header_scalar_supported(item)
            for item in value[IDENTITY_VALUES_MARKER].values()
        )
    if isinstance(value, bool):
        serialized = "true" if value else "false"
    elif isinstance(value, (str, int, float)) and value is not None:
        serialized = str(value)
    else:
        return False
    return all(
        32 <= ord(character) <= 255 and ord(character) != 127
        for character in serialized
    )


def _header_value_supported(value: Any) -> bool:
    if isinstance(value, dict) and IDENTITY_VALUES_MARKER in value:
        return all(
            _header_value_supported(item)
            for item in value[IDENTITY_VALUES_MARKER].values()
        )
    if isinstance(value, dict):
        return all(
            isinstance(key, str)
            and all(
                32 <= ord(character) <= 255 and ord(character) != 127
                for character in key
            )
            and _header_scalar_supported(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return all(_header_scalar_supported(item) for item in value)
    return _header_scalar_supported(value)


def _operation_mapping(
    mapping: Any,
    operation: Operation,
    spec_operations: dict[str, dict[str, Any]],
    identities: set[str],
    allow_destructive: bool,
) -> Operation:
    if not isinstance(mapping, dict):
        raise ConfigurationError(
            f"OpenAPI mapping for policy operation {operation.operation_id} "
            "must be an object."
        )
    unknown = set(mapping) - {"operation_id", "parameters", "body", "content_type"}
    if unknown:
        raise ConfigurationError(
            f"OpenAPI mapping for {operation.operation_id} has unknown field(s): "
            f"{', '.join(sorted(map(str, unknown)))}."
        )

    requested_id = mapping.get("operation_id", operation.operation_id)
    if not isinstance(requested_id, str) or not requested_id:
        raise ConfigurationError(
            f"OpenAPI operation_id for {operation.operation_id} must be a string."
        )
    spec_operation = spec_operations.get(requested_id)
    if spec_operation is None:
        raise _SkipOperation(
            f"OpenAPI operationId {requested_id!r} is not present in the document."
        )
    if spec_operation["method"] in DESTRUCTIVE_METHODS and not allow_destructive:
        raise _SkipOperation(
            f"{spec_operation['method']} is destructive and "
            "scope.allow_destructive is not enabled."
        )

    route = spec_operation["path"]
    if (
        not route.startswith("/")
        or route.startswith("//")
        or "://" in route
        or "?" in route
        or "#" in route
        or "\\" in route
        or any(ord(character) <= 32 or ord(character) == 127 for character in route)
        or any(part in {".", ".."} for part in route.split("/"))
    ):
        raise OpenAPIError(
            f"OpenAPI operation {requested_id!r} has an unsafe request path."
        )
    path_placeholders = re.findall(r"\{([^{}]+)\}", route)
    if len(path_placeholders) != len(set(path_placeholders)):
        raise _SkipOperation(
            "repeated OpenAPI path parameter names are not supported."
        )

    parameters = mapping.get("parameters", {})
    if not isinstance(parameters, dict):
        raise ConfigurationError(
            f"OpenAPI parameters for {operation.operation_id} must be a mapping."
        )
    parameter_definitions = {
        parameter["name"]: parameter for parameter in spec_operation["parameters"]
    }
    unused = set(parameters) - set(parameter_definitions)
    if unused:
        raise ConfigurationError(
            f"OpenAPI mapping for {operation.operation_id} names unknown "
            f"parameter(s): {', '.join(sorted(map(str, unused)))}."
        )

    request_parameters: dict[str, dict[str, dict[str, Any]]] = {
        "path": {},
        "query": {},
        "header": {},
    }
    resource_path_bindings = 0
    for parameter in spec_operation["parameters"]:
        name = parameter["name"]
        if name not in parameters:
            if parameter["required"]:
                raise _SkipOperation(
                    f"required {parameter['in']} parameter {name!r} has no "
                    "explicit test value."
                )
            continue
        value = parameters[name]
        _validate_value_mapping(value, identities, f"{operation.operation_id}.{name}")
        if parameter.get("allow_reserved") or parameter.get("allow_empty_value"):
            raise _SkipOperation(
                f"parameter {name!r} uses allowReserved or allowEmptyValue, "
                "which is not supported."
            )
        if not _parameter_value_matches(value, parameter["schema"]):
            raise _SkipOperation(
                f"explicit value for parameter {name!r} does not match its "
                "declared JSON schema type."
            )
        if not _parameter_values_serializable(value):
            raise _SkipOperation(
                f"explicit value for parameter {name!r} has a nested shape "
                "unsupported by its OpenAPI serialization style."
            )
        schema_type = parameter["schema"].get("type")
        if (
            parameter["in"] == "query"
            and parameter["style"] in {"spaceDelimited", "pipeDelimited"}
            and (schema_type != "array" or parameter["explode"])
        ):
            raise _SkipOperation(
                f"query parameter {name!r} uses {parameter['style']} with an "
                "unsupported schema or explode setting."
            )
        if (
            parameter["in"] == "query"
            and parameter["style"] == "deepObject"
            and schema_type != "object"
        ):
            raise _SkipOperation(
                f"query parameter {name!r} uses deepObject without an object schema."
            )
        if (
            parameter["in"] == "header"
            and (
                not HEADER_NAME.fullmatch(name)
                or name.lower() in FORBIDDEN_HEADERS
                or name.lower().startswith("proxy-")
                or not _header_value_supported(value)
            )
        ):
            raise _SkipOperation(
                f"header parameter {name!r} cannot safely be supplied."
            )
        if parameter["in"] == "path" and value == {RESOURCE_ID_MARKER: True}:
            resource_path_bindings += 1
            if operation.resource is None:
                raise _SkipOperation(
                    f"path parameter {name!r} uses a resource ID but the policy "
                    "operation has no configured resource."
                )
        request_parameters[parameter["in"]][name] = {
            "value": value,
            "style": parameter["style"],
            "explode": parameter["explode"],
            "allow_reserved": parameter.get("allow_reserved", False),
            "schema": parameter["schema"],
        }

    if operation.resource is not None and resource_path_bindings != 1:
        raise _SkipOperation(
            "a BOLA operation must bind exactly one path parameter to the "
            "policy's configured resource IDs."
        )
    if operation.resource is None and resource_path_bindings:
        raise _SkipOperation("a BFLA operation cannot bind a resource ID.")

    request_body = spec_operation["request_body"]
    body_supplied = "body" in mapping
    body = mapping.get("body")
    content_type = None
    if body_supplied:
        _validate_value_mapping(
            body,
            identities,
            f"{operation.operation_id}.body",
        )
        requested_content_type = mapping.get("content_type")
        supported_types = [
            media_type
            for media_type in request_body["content"]
            if media_type == "application/json"
            or (
                media_type.startswith("application/")
                and media_type.endswith("+json")
            )
        ]
        if requested_content_type is not None:
            if (
                not isinstance(requested_content_type, str)
                or requested_content_type.lower() not in supported_types
            ):
                raise _SkipOperation(
                    "the requested body content type is not a supported JSON "
                    "type declared by OpenAPI."
                )
            content_type = requested_content_type.lower()
        elif supported_types:
            content_type = supported_types[0]
        else:
            raise _SkipOperation(
                "the operation does not declare a supported JSON request body."
            )
    elif request_body["required"]:
        raise _SkipOperation(
            "the OpenAPI request body is required but has no explicit test value."
        )
    elif mapping.get("content_type") is not None:
        raise ConfigurationError(
            f"content_type for {operation.operation_id} requires an explicit body."
        )

    return replace(
        operation,
        method=spec_operation["method"],
        path=route,
        request_parameters=request_parameters,
        request_body=body if body_supplied else None,
        request_content_type=content_type,
    )


def compile_openapi_operations(
    config: ScanConfig,
    specification: str | Path,
    value_mapping: str | Path,
    *,
    max_openapi_bytes: int = DEFAULT_MAX_OPENAPI_BYTES,
) -> tuple[ScanConfig, list[dict[str, str]]]:
    """Apply explicit OpenAPI values to policy operations, reporting omissions."""
    inventory = parse_openapi(specification, max_bytes=max_openapi_bytes)
    mapping_path = Path(value_mapping)
    raw_mappings = _read_mapping(mapping_path)
    policy_operation_ids = {item.operation_id for item in config.operations}
    unknown_mappings = set(raw_mappings) - policy_operation_ids
    if unknown_mappings:
        raise ConfigurationError(
            "OpenAPI mapping references unknown policy operation(s): "
            f"{', '.join(sorted(map(str, unknown_mappings)))}."
        )

    by_operation_id = {
        item["operation_id"]: item
        for item in inventory["operations"]
        if item["operation_id"] is not None
    }
    compiled = []
    skipped = []
    for operation in config.operations:
        if operation.operation_id not in raw_mappings:
            skipped.append(
                {
                    "operation_id": operation.operation_id,
                    "method": operation.method,
                    "path": operation.path,
                    "reason": "No explicit OpenAPI value mapping was supplied.",
                }
            )
            continue
        try:
            compiled.append(
                _operation_mapping(
                    raw_mappings[operation.operation_id],
                    operation,
                    by_operation_id,
                    set(config.identities),
                    config.allow_destructive,
                )
            )
        except _SkipOperation as exc:
            skipped.append(
                {
                    "operation_id": operation.operation_id,
                    "method": operation.method,
                    "path": operation.path,
                    "reason": str(exc),
                }
            )

    if not compiled and not skipped:
        raise ConfigurationError("No policy operations are available to scan.")
    return replace(config, operations=tuple(compiled)), skipped
