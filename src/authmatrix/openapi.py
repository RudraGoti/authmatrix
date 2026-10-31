"""Local OpenAPI document parsing and operation extraction."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from authmatrix.errors import OpenAPIError

HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete"}
PARAMETER_LOCATIONS = {"path", "query", "header"}
PATH_PARAMETER_PATTERN = re.compile(r"\{([^{}]+)\}")
OPENAPI_VERSION_PATTERN = re.compile(r"3\.\d+\.\d+")


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

    style = parameter.get("style")
    supported_styles = {
        "path": {"simple", "label", "matrix"},
        "query": {"form", "spaceDelimited", "pipeDelimited", "deepObject"},
        "header": {"simple"},
    }
    if style is not None and (
        not isinstance(style, str) or style not in supported_styles[location]
    ):
        raise OpenAPIError(f"Parameter '{name}' in {label} uses an unsupported style.")

    return {
        "name": name,
        "in": location,
        "required": required,
        "schema": schema,
    }


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


def parse_openapi(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise OpenAPIError(f"Cannot read OpenAPI document: {source}") from exc

    try:
        document = (
            json.loads(text)
            if source.suffix.lower() == ".json"
            else yaml.safe_load(text)
        )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise OpenAPIError(
            f"OpenAPI document is not valid JSON or YAML: {source}"
        ) from exc

    if not isinstance(document, dict):
        raise OpenAPIError("OpenAPI document root must be a mapping.")

    if not isinstance(
        document.get("openapi"), str
    ) or not OPENAPI_VERSION_PATTERN.fullmatch(document["openapi"]):
        raise OpenAPIError("Only OpenAPI 3.x documents are supported.")

    paths = document.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise OpenAPIError("OpenAPI document must define at least one path.")

    operations = []
    for route, path_item in paths.items():
        if (
            not isinstance(route, str)
            or not route.startswith("/")
            or not isinstance(path_item, dict)
        ):
            raise OpenAPIError(
                "Every OpenAPI path must start with '/' and map to an object."
            )

        for method, operation in path_item.items():
            if not isinstance(method, str) or method.lower() not in HTTP_METHODS:
                continue

            if not isinstance(operation, dict):
                raise OpenAPIError(
                    f"Operation {method.upper()} {route} must be an object."
                )

            parameters = _extract_parameters(path_item, operation, route, method)
            operations.append(
                {
                    "method": method.upper(),
                    "path": route,
                    "operation_id": operation.get("operationId"),
                    "summary": operation.get("summary"),
                    "parameters": parameters,
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
    inventory = parse_openapi(path)
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
