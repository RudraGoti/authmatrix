"""Local OpenAPI document parsing and operation extraction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from authmatrix.errors import OpenAPIError

HTTP_METHODS = {"get", "head", "options", "post", "put", "patch", "delete"}


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
    if not isinstance(document.get("openapi"), str) or not document[
        "openapi"
    ].startswith("3."):
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
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise OpenAPIError(
                    f"Operation {method.upper()} {route} must be an object."
                )
            operations.append(
                {
                    "method": method.upper(),
                    "path": route,
                    "operation_id": operation.get("operationId"),
                    "summary": operation.get("summary"),
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
