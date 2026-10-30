from __future__ import annotations

import json
from pathlib import Path

import pytest

from authmatrix.errors import OpenAPIError
from authmatrix.openapi import parse_openapi, write_operation_inventory

ROOT = Path(__file__).resolve().parents[1]


def test_imports_local_openapi_operations(tmp_path: Path) -> None:
    inventory = parse_openapi(ROOT / "examples" / "openapi.yaml")
    assert inventory["title"] == "AuthMatrix Local Demo API"
    assert {item["method"] for item in inventory["operations"]} == {"GET"}
    output = tmp_path / "inventory.json"
    assert write_operation_inventory(ROOT / "examples" / "openapi.yaml", output) == 2
    assert json.loads(output.read_text(encoding="utf-8"))["openapi_version"] == "3.0.3"


def test_rejects_invalid_openapi(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("openapi: 2.0\npaths: {}", encoding="utf-8")
    with pytest.raises(OpenAPIError, match="OpenAPI 3.x"):
        parse_openapi(path)
