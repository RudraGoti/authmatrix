"""Local OpenAPI document parsing and operation extraction."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

import yaml

from authmatrix.errors import OpenAPIError
from authmatrix.reporting import sanitize_results

HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete"}
PARAMETER_LOCATIONS = {"path", "query", "header"}
PATH_PARAMETER_PATTERN = re.compile(r"\{([^{}]+)\}")
OPENAPI_VERSION_PATTERN = re.compile(r"3\.\d+\.\d+")
DEFAULT_MAX_OPENAPI_BYTES = 2 * 1024 * 1024
OPENAPI_SAMPLE_VALUE_KEYS = {"const", "default", "enum", "example", "examples"}


def _validate_document_tree(document: dict[str, Any]) -> None:
    """Bound YAML/JSON nesting and reject cyclic YAML aliases."""
    active: set[int] = set()
    visited: set[int] = set()
    stack: list[tuple[Any, int, bool]] = [(document, 0, False)]
    nodes = 0
    while stack:
        value, depth, exiting = stack.pop()
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise OpenAPIError(
                    "OpenAPI document contains invalid Unicode text."
                ) from exc
            continue
        if not isinstance(value, (dict, list)):
            continue
        identity = id(value)
        if exiting:
            active.remove(identity)
            visited.add(identity)
            continue
        if identity in active:
            raise OpenAPIError("OpenAPI document contains a cyclic YAML alias.")
        if identity in visited:
            continue
        if depth > 100:
            raise OpenAPIError("OpenAPI document nesting exceeds 100 levels.")
        nodes += 1
        if nodes > 100_000:
            raise OpenAPIError("OpenAPI document contains too many structured values.")
        active.add(identity)
        stack.append((value, depth, True))
        children = (
            (
                item
                for key, child in value.items()
                for item in (key, child)
            )
            if isinstance(value, dict)
            else value
        )
        stack.extend((child, depth + 1, False) for child in children)


def _reject_schema_references(value: Any, label: str) -> None:
    if isinstance(value, dict):
        if "$ref" in value:
            raise OpenAPIError(
                f"Referenced schemas are not supported in {label}; "
                "define the schema locally."
            )
        for item in value.values():
            _reject_schema_references(item, label)
    elif isinstance(value, list):
        for item in value:
            _reject_schema_references(item, label)


def _remove_openapi_sample_values(value: Any) -> Any:
    if isinstance(value, dict):
            return {
                key: _remove_openapi_sample_values(item)
                for key, item in value.items()
                if not isinstance(key, str)
                or key.lower() not in OPENAPI_SAMPLE_VALUE_KEYS
            }
    if isinstance(value, list):
            return [_remove_openapi_sample_values(item) for item in value]
    return value


def sanitize_openapi_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Remove schema samples and recognizable secrets from inventory output."""
    sanitized = sanitize_results(_remove_openapi_sample_values(inventory))
    return sanitized


def _validate_parameter(parameter: Any, route: str, method: str) -> dict[str, Any]:
    """Validate and normalize a supported OpenAPI parameter."""
    label = f"{method.upper()} {route}"

    if not isinstance(parameter, dict):
        raise OpenAPIError(f"Parameter in {label} must be an object.")

    if "$ref" in parameter:
        raise OpenAPIError(
            f"Referenced parameters are not supported in {label}; "
            "define the parameter locally."
        )

    name = parameter.get("name")
    location = parameter.get("in")

    if not isinstance(name, str) or not name.strip() or name != name.strip():
        raise OpenAPIError(f"Parameter in {label} must have a non-empty name.")

    if not isinstance(location, str) or location not in PARAMETER_LOCATIONS:
        raise OpenAPIError(
            f"Parameter '{name}' in {label} has an unsupported location."
        )

    required = parameter.get("required", False)
    if not isinstance(required, bool):
        raise OpenAPIError(
            f"Parameter '{name}' in {label} must use a boolean required value."
        )

    if location == "path" and required is not True:
        raise OpenAPIError(f"Path parameter '{name}' in {label} must be required.")

    if "content" in parameter:
        raise OpenAPIError(
            f"Content-based parameter '{name}' in {label} is not supported."
        )

    schema = parameter.get("schema")
    if not isinstance(schema, dict):
        raise OpenAPIError(
            f"Parameter '{name}' in {label} must define schema as an object."
        )
    _reject_schema_references(schema, f"parameter '{name}' in {label}")

    default_styles = {"path": "simple", "query": "form", "header": "simple"}
    style = parameter.get("style", default_styles[location])
    supported_styles = {
        "path": {"simple", "label", "matrix"},
        "query": {"form", "spaceDelimited", "pipeDelimited", "deepObject"},
        "header": {"simple"},
    }
    if not isinstance(style, str) or style not in supported_styles[location]:
        raise OpenAPIError(f"Parameter '{name}' in {label} uses an unsupported style.")

    explode = parameter.get("explode", style == "form")
    if not isinstance(explode, bool):
        raise OpenAPIError(
            f"Parameter '{name}' in {label} must use a boolean explode value."
        )
    allow_reserved = parameter.get("allowReserved", False)
    if not isinstance(allow_reserved, bool):
        raise OpenAPIError(
            f"Parameter '{name}' in {label} must use a boolean allowReserved value."
        )
    allow_empty = parameter.get("allowEmptyValue", False)
    if not isinstance(allow_empty, bool):
        raise OpenAPIError(
            f"Parameter '{name}' in {label} must use a boolean allowEmptyValue value."
        )

    normalized = {
        "name": name,
        "in": location,
        "required": required,
        "schema": schema,
        "style": style,
        "explode": explode,
    }
    if allow_reserved:
        normalized["allow_reserved"] = True
    if allow_empty:
        normalized["allow_empty_value"] = True
    return normalized


def _extract_parameters(
    path_item: dict[str, Any], operation: dict[str, Any], route: str, method: str
) -> list[dict[str, Any]]:
    """Merge path-level and operation-level parameter definitions."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}

    for source_name, definitions in (
        ("path", path_item.get("parameters", [])),
        ("operation", operation.get("parameters", [])),
    ):
        if not isinstance(definitions, list):
            raise OpenAPIError(
                f"{source_name.capitalize()} parameters for "
                f"{method.upper()} {route} must be a list."
            )

        seen: set[tuple[str, str]] = set()
        for definition in definitions:
            parameter = _validate_parameter(definition, route, method)
            key = (parameter["name"], parameter["in"])

            if key in seen:
                raise OpenAPIError(
                    f"Duplicate parameter '{key[0]}' in '{key[1]}' "
                    f"for {method.upper()} {route}."
                )
            seen.add(key)
            merged[key] = parameter

    placeholders = set(PATH_PARAMETER_PATTERN.findall(route))
    if "{" in PATH_PARAMETER_PATTERN.sub(
        "", route
    ) or "}" in PATH_PARAMETER_PATTERN.sub("", route):
        raise OpenAPIError(
            f"Path {route} contains a malformed path parameter placeholder."
        )
    path_parameters = {name for name, location in merged if location == "path"}

    missing = placeholders - path_parameters
    extra = path_parameters - placeholders

    if missing:
        names = ", ".join(sorted(missing))
        raise OpenAPIError(
            f"Path {route} has no required path parameter definition for: {names}."
        )
    if extra:
        names = ", ".join(sorted(extra))
        raise OpenAPIError(
            f"Path parameter definitions for {method.upper()} {route} "
            f"do not match path placeholders: {names}."
        )

    return sorted(
        merged.values(),
        key=lambda item: (item["in"], item["name"]),
    )


def _extract_request_body(operation: dict[str, Any], route: str, method: str) -> dict:
    """Validate a local request-body description without resolving references."""
    request_body = operation.get("requestBody")
    if request_body is None:
        return {"required": False, "content": {}}
    if not isinstance(request_body, dict):
        raise OpenAPIError(
            f"Request body for {method.upper()} {route} must be an object."
        )
    if "$ref" in request_body:
        raise OpenAPIError(
            f"Referenced request bodies are not supported for "
            f"{method.upper()} {route}; define the body locally."
        )

    required = request_body.get("required", False)
    content = request_body.get("content")
    if not isinstance(required, bool) or not isinstance(content, dict) or not content:
        raise OpenAPIError(
            f"Request body for {method.upper()} {route} must define a boolean "
            "required value and non-empty content mapping."
        )

    normalized_content = {}
    for media_type, definition in content.items():
        if (
            not isinstance(media_type, str)
            or not media_type.strip()
            or not isinstance(definition, dict)
        ):
            raise OpenAPIError(
                f"Request body content for {method.upper()} {route} is invalid."
            )
        schema = definition.get("schema")
        if schema is not None and not isinstance(schema, dict):
            raise OpenAPIError(
                f"Request body schema for {method.upper()} {route} "
                "must be an object."
            )
        if schema is not None:
            _reject_schema_references(
                schema,
                f"request body for {method.upper()} {route}",
            )
        normalized_content[media_type.lower()] = {"schema": schema}
    return {"required": required, "content": normalized_content}


def parse_openapi(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_OPENAPI_BYTES,
) -> dict[str, Any]:
    source = Path(path)
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes < 1
    ):
        raise ValueError("The OpenAPI size limit must be a positive integer.")

    try:
        if source.stat().st_size > max_bytes:
            raise OpenAPIError(
                f"OpenAPI document exceeds the {max_bytes}-byte size limit."
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise OpenAPIError(f"Cannot read OpenAPI document: {source}") from exc

    try:
        with os.fdopen(descriptor, "rb") as source_file:
            info = os.fstat(source_file.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise OpenAPIError("OpenAPI document must be a regular local file.")
            if info.st_size > max_bytes:
                raise OpenAPIError(
                    f"OpenAPI document exceeds the {max_bytes}-byte size limit."
                )
            content = source_file.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise OpenAPIError(
                    f"OpenAPI document exceeds the {max_bytes}-byte size limit."
                )
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OpenAPIError(
            f"OpenAPI document is not valid UTF-8: {source}"
        ) from exc
    except OSError as exc:
        raise OpenAPIError(f"Cannot read OpenAPI document: {source}") from exc

    try:
        document = (
            json.loads(text)
            if source.suffix.lower() == ".json"
            else yaml.safe_load(text)
        )
    except (json.JSONDecodeError, yaml.YAMLError, RecursionError) as exc:
        raise OpenAPIError(
            f"OpenAPI document is not valid JSON or YAML: {source}"
        ) from exc

    if not isinstance(document, dict):
        raise OpenAPIError("OpenAPI document root must be a mapping.")
    _validate_document_tree(document)

    if not isinstance(
        document.get("openapi"), str
    ) or not OPENAPI_VERSION_PATTERN.fullmatch(document["openapi"]):
        raise OpenAPIError("Only OpenAPI 3.x documents are supported.")

    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise OpenAPIError("OpenAPI document must define at least one path.")

    operations = []
    operation_ids: set[str] = set()
    for route, path_item in paths.items():
        if (
            not isinstance(route, str)
            or not route.startswith("/")
            or not isinstance(path_item, dict)
        ):
            raise OpenAPIError(
                "Every OpenAPI path must start with '/' and map to an object."
            )

        if "$ref" in path_item:
            raise OpenAPIError(
                f"Referenced path items are not supported for {route}; "
                "define operations locally."
            )

        for method, operation in path_item.items():
            if not isinstance(method, str) or method.lower() not in HTTP_METHODS:
                continue

            if not isinstance(operation, dict):
                raise OpenAPIError(
                    f"Operation {method.upper()} {route} must be an object."
                )
            if "$ref" in operation:
                raise OpenAPIError(
                    f"Referenced operations are not supported for "
                    f"{method.upper()} {route}; define the operation locally."
                )

            for metadata_field in ("operationId", "summary"):
                metadata_value = operation.get(metadata_field)
                if metadata_value is not None and not isinstance(metadata_value, str):
                    raise OpenAPIError(
                        f"{metadata_field} for {method.upper()} {route} "
                        "must be a string."
                    )

            parameters = _extract_parameters(path_item, operation, route, method)
            operation_id = operation.get("operationId")
            if operation_id is not None:
                if not operation_id.strip():
                    raise OpenAPIError(
                        f"operationId for {method.upper()} {route} "
                        "must not be empty."
                    )
                if operation_id in operation_ids:
                    raise OpenAPIError(
                        f"Duplicate OpenAPI operationId: {operation_id}."
                    )
                operation_ids.add(operation_id)
            operations.append(
                {
                    "method": method.upper(),
                    "path": route,
                    "operation_id": operation_id,
                    "summary": operation.get("summary"),
                    "parameters": parameters,
                    "request_body": _extract_request_body(
                        operation, route, method
                    ),
                }
            )

    if not operations:
        raise OpenAPIError(
            "OpenAPI document does not contain any supported HTTP operations."
        )

    return {
        "openapi_version": document["openapi"],
        "title": document.get("info", {}).get("title", "Untitled API")
        if isinstance(document.get("info", {}), dict)
        else "Untitled API",
        "operations": operations,
    }


def write_operation_inventory(path: str | Path, output: str | Path) -> int:
    inventory = sanitize_openapi_inventory(parse_openapi(path))
    destination = Path(output)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(inventory, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise OpenAPIError(f"Cannot write operation inventory: {destination}") from exc

    return len(inventory["operations"])
