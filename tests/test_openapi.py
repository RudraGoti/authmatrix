from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from authmatrix.errors import OpenAPIError
from authmatrix.openapi import parse_openapi, write_operation_inventory

ROOT = Path(__file__).resolve().parents[1]


def _write_spec(tmp_path: Path, paths: dict) -> Path:
    path = tmp_path / "spec.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "openapi": "3.0.3",
                "info": {"title": "Parameter Test API", "version": "1.0"},
                "paths": paths,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_imports_local_openapi_operations(tmp_path: Path) -> None:
    inventory = parse_openapi(ROOT / "examples" / "openapi.yaml")
    assert inventory["title"] == "AuthMatrix Local Demo API"
    assert {item["method"] for item in inventory["operations"]} == {"GET"}

    item_operation = next(
        item for item in inventory["operations"] if item["path"] == "/items/{item_id}"
    )
    assert item_operation["parameters"] == [
        {
            "name": "item_id",
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
        }
    ]

    output = tmp_path / "inventory.json"
    assert write_operation_inventory(ROOT / "examples" / "openapi.yaml", output) == 2
    assert json.loads(output.read_text(encoding="utf-8"))["openapi_version"] == "3.0.3"


def test_rejects_invalid_openapi(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("openapi: 2.0\npaths: {}", encoding="utf-8")
    with pytest.raises(OpenAPIError, match="OpenAPI 3.x"):
        parse_openapi(path)


def test_imports_query_and_header_parameters(tmp_path: Path) -> None:
    path = _write_spec(
        tmp_path,
        {
            "/items": {
                "get": {
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "integer", "minimum": 1},
                        },
                        {
                            "name": "X-Request-ID",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string"},
                        },
                    ]
                }
            }
        },
    )

    parameters = parse_openapi(path)["operations"][0]["parameters"]
    assert parameters == [
        {
            "name": "X-Request-ID",
            "in": "header",
            "required": True,
            "schema": {"type": "string"},
        },
        {
            "name": "limit",
            "in": "query",
            "required": False,
            "schema": {"type": "integer", "minimum": 1},
        },
    ]


def test_merges_path_and_operation_parameters(tmp_path: Path) -> None:
    path = _write_spec(
        tmp_path,
        {
            "/items/{item_id}": {
                "parameters": [
                    {
                        "name": "item_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "version",
                        "in": "query",
                        "schema": {"type": "string"},
                    },
                ],
                "get": {
                    "parameters": [
                        {
                            "name": "version",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ]
                },
            }
        },
    )

    parameters = parse_openapi(path)["operations"][0]["parameters"]
    version = next(item for item in parameters if item["name"] == "version")
    assert version["required"] is True
    assert version["schema"] == {"type": "integer"}
    assert len(parameters) == 2


@pytest.mark.parametrize(
    ("parameter", "message"),
    [
        (
            {"name": "id", "in": "path", "schema": {"type": "string"}},
            "must be required",
        ),
        (
            {"name": "id", "in": "cookie", "schema": {"type": "string"}},
            "unsupported location",
        ),
        (
            {"name": "id", "in": "query", "required": "yes"},
            "boolean required",
        ),
        (
            {"name": "id", "in": "query", "schema": "string"},
            "schema as an object",
        ),
        (
            {"$ref": "#/components/parameters/ItemId"},
            "Referenced parameters are not supported",
        ),
        (
            {
                "name": "id",
                "in": "query",
                "content": {"application/json": {"schema": {"type": "string"}}},
            },
            "Content-based parameter",
        ),
    ],
)
def test_rejects_unsupported_or_invalid_parameters(
    tmp_path: Path, parameter: dict, message: str
) -> None:
    path = _write_spec(
        tmp_path,
        {"/items": {"get": {"parameters": [parameter]}}},
    )

    with pytest.raises(OpenAPIError, match=message):
        parse_openapi(path)


def test_rejects_missing_path_parameter_definition(tmp_path: Path) -> None:
    path = _write_spec(
        tmp_path,
        {"/items/{item_id}": {"get": {}}},
    )

    with pytest.raises(OpenAPIError, match="no required path parameter"):
        parse_openapi(path)


def test_rejects_duplicate_parameters_in_same_scope(tmp_path: Path) -> None:
    parameter = {
        "name": "limit",
        "in": "query",
        "schema": {"type": "integer"},
    }
    path = _write_spec(
        tmp_path,
        {"/items": {"get": {"parameters": [parameter, parameter]}}},
    )

    with pytest.raises(OpenAPIError, match="Duplicate parameter"):
        parse_openapi(path)


def test_rejects_path_parameter_not_matching_placeholder(tmp_path: Path) -> None:
    path = _write_spec(
        tmp_path,
        {
            "/items/{item_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "other_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ]
                }
            }
        },
    )

    with pytest.raises(OpenAPIError, match="no required path parameter"):
        parse_openapi(path)


@pytest.mark.parametrize("version", ["3.invalid", "3.0", "4.0.0"])
def test_rejects_invalid_openapi_version(tmp_path: Path, version: str) -> None:
    path = _write_spec(tmp_path, {"/items": {"get": {}}})
    content = path.read_text(encoding="utf-8").replace("3.0.3", version)
    path.write_text(content, encoding="utf-8")

    with pytest.raises(OpenAPIError, match="OpenAPI 3.x"):
        parse_openapi(path)


def test_rejects_malformed_path_placeholder(tmp_path: Path) -> None:
    path = _write_spec(tmp_path, {"/items/{item_id": {"get": {}}})

    with pytest.raises(OpenAPIError, match="malformed path parameter"):
        parse_openapi(path)


def test_rejects_parameter_name_with_surrounding_whitespace(tmp_path: Path) -> None:
    path = _write_spec(
        tmp_path,
        {
            "/items": {
                "get": {
                    "parameters": [
                        {
                            "name": " limit ",
                            "in": "query",
                            "schema": {"type": "integer"},
                        }
                    ]
                }
            }
        },
    )

    with pytest.raises(OpenAPIError, match="non-empty name"):
        parse_openapi(path)
