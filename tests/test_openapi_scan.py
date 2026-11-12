from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from authmatrix.config import load_config
from authmatrix.errors import OpenAPIError
from authmatrix.openapi_scan import compile_openapi_operations
from authmatrix.scanner import (
    _serialize_header_parameter,
    _serialize_path_parameter,
    _serialize_query_parameter,
    run_authorization_tests,
)

ROOT = Path(__file__).resolve().parents[1]


def _config(config_path: Path, tmp_path: Path, *, allow_destructive: bool = False):
    policy = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    policy["scope"]["base_url"] = "http://127.0.0.1:8000"
    policy["scope"]["allowed_hosts"] = ["127.0.0.1"]
    policy["scope"]["allow_destructive"] = allow_destructive
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    return load_config(path)


def _write_yaml(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_compiles_explicit_openapi_values_and_skips_unmapped_operations(
    config_path: Path,
    tmp_path: Path,
) -> None:
    config = _config(config_path, tmp_path)
    values = _write_yaml(
        tmp_path / "values.yaml",
        {
            "operations": {
                "read_item": {
                    "operation_id": "readItem",
                    "parameters": {
                        "item_id": {"$authmatrix_resource_id": True}
                    },
                }
            }
        },
    )

    compiled, skipped = compile_openapi_operations(
        config,
        ROOT / "examples" / "openapi.yaml",
        values,
    )

    assert [operation.operation_id for operation in compiled.operations] == [
        "read_item"
    ]
    assert compiled.operations[0].method == "GET"
    assert compiled.operations[0].path == "/items/{item_id}"
    assert skipped == [
        {
            "operation_id": "read_admin_reports",
            "method": "GET",
            "path": "/admin/reports",
            "reason": "No explicit OpenAPI value mapping was supplied.",
        }
    ]


def test_missing_required_openapi_parameter_is_skipped(
    config_path: Path,
    tmp_path: Path,
) -> None:
    config = _config(config_path, tmp_path)
    values = _write_yaml(
        tmp_path / "values.yaml",
        {"operations": {"read_item": {"operation_id": "readItem"}}},
    )

    compiled, skipped = compile_openapi_operations(
        config,
        ROOT / "examples" / "openapi.yaml",
        values,
    )

    assert all(
        operation.operation_id != "read_item" for operation in compiled.operations
    )
    assert "required path parameter 'item_id'" in skipped[0]["reason"]


def test_openapi_request_serialization_and_evidence_are_secret_safe(
    config_path: Path,
    tmp_path: Path,
    auth_env,
    monkeypatch,
) -> None:
    from authmatrix import scanner

    config = _config(config_path, tmp_path, allow_destructive=True)
    specification = _write_yaml(
        tmp_path / "spec.yaml",
        {
            "openapi": "3.0.3",
            "info": {"title": "Mapped API", "version": "1"},
            "paths": {
                "/lookup": {
                    "post": {
                        "operationId": "readAdminReports",
                        "parameters": [
                            {
                                "name": "tag",
                                "in": "query",
                                "required": True,
                                "schema": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            {
                                "name": "filter",
                                "in": "query",
                                "required": True,
                                "style": "deepObject",
                                "schema": {"type": "object"},
                            },
                            {
                                "name": "X-Tenant",
                                "in": "header",
                                "required": True,
                                "schema": {"type": "string"},
                            },
                        ],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            },
                        },
                    }
                }
            },
        },
    )
    values = _write_yaml(
        tmp_path / "values.yaml",
        {
            "operations": {
                "read_admin_reports": {
                    "operation_id": "readAdminReports",
                    "parameters": {
                        "tag": ["owned", "authorized"],
                        "filter": {"state": "open"},
                        "X-Tenant": {
                            "$authmatrix_by_identity": {
                                "alice": "tenant-alice-secret",
                                "bob": "tenant-bob-secret",
                                "admin": "tenant-admin-secret",
                            }
                        },
                    },
                    "body": {
                        "subject": {
                            "$authmatrix_by_identity": {
                                "alice": "alice",
                                "bob": "bob",
                                "admin": "admin",
                            }
                        }
                    },
                }
            }
        },
    )
    compiled, skipped = compile_openapi_operations(
        config,
        specification,
        values,
    )
    sent_requests = []

    class Response:
        status_code = 200
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_bytes(self):
            yield b'{"reports":["protected-report"]}'

    class Client:
        def __init__(self, **options):
            assert options == {
                "timeout": config.timeout_seconds,
                "follow_redirects": False,
                "trust_env": False,
            }

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, method, url, **options):
            sent_requests.append((method, url, options))
            return Response()

    monkeypatch.setattr(scanner.httpx, "Client", Client)
    result = run_authorization_tests(compiled)

    assert skipped == [
        {
            "operation_id": "read_item",
            "method": "GET",
            "path": "/items/{item_id}",
            "reason": "No explicit OpenAPI value mapping was supplied.",
        }
    ]
    assert len(sent_requests) == 3
    method, url, options = sent_requests[0]
    assert (method, url) == ("POST", "http://127.0.0.1:8000/lookup")
    assert options["params"] == [
        ("filter[state]", "open"),
        ("tag", "owned"),
        ("tag", "authorized"),
    ]
    assert options["headers"]["Content-Type"] == "application/json"
    expected_tenants = {
        "alice": "tenant-alice-secret",
        "bob": "tenant-bob-secret",
        "admin": "tenant-admin-secret",
    }
    for (_, _, request_options), identity_name in zip(
        sent_requests,
        compiled.identities,
        strict=True,
    ):
        assert request_options["headers"]["X-Tenant"] == expected_tenants[identity_name]
        assert request_options["json"] == {"subject": identity_name}
    assert result["summary"]["findings"] == 2
    assert result["checks"][0]["path"] == "/lookup"
    serialized = json.dumps(result)
    assert "tenant-alice-secret" not in serialized
    assert "tenant-bob-secret" not in serialized
    assert "protected-report" not in serialized


def test_destructive_openapi_operation_is_skipped_without_policy_opt_in(
    config_path: Path,
    tmp_path: Path,
) -> None:
    config = _config(config_path, tmp_path)
    spec = _write_yaml(
        tmp_path / "spec.yaml",
        {
            "openapi": "3.0.3",
            "info": {"title": "Unsafe API", "version": "1"},
            "paths": {
                "/admin/reports": {
                    "delete": {"operationId": "readAdminReports"}
                }
            },
        },
    )
    values = _write_yaml(
        tmp_path / "values.yaml",
        {"operations": {"read_admin_reports": {"operation_id": "readAdminReports"}}},
    )

    compiled, skipped = compile_openapi_operations(config, spec, values)

    assert compiled.operations == ()
    destructive_skip = next(
        item for item in skipped if item["operation_id"] == "read_admin_reports"
    )
    assert "destructive" in destructive_skip["reason"]


def test_required_openapi_json_body_without_mapping_is_skipped(
    config_path: Path,
    tmp_path: Path,
) -> None:
    config = _config(config_path, tmp_path)
    spec = _write_yaml(
        tmp_path / "spec.yaml",
        {
            "openapi": "3.0.3",
            "info": {"title": "Body API", "version": "1"},
            "paths": {
                "/reports": {
                    "get": {
                        "operationId": "readAdminReports",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            },
                        },
                    }
                }
            },
        },
    )
    values = _write_yaml(
        tmp_path / "values.yaml",
        {"operations": {"read_admin_reports": {"operation_id": "readAdminReports"}}},
    )

    compiled, skipped = compile_openapi_operations(config, spec, values)

    assert compiled.operations == ()
    body_skip = next(
        item for item in skipped if item["operation_id"] == "read_admin_reports"
    )
    assert "request body is required" in body_skip["reason"]


def test_openapi_network_path_is_rejected(
    config_path: Path,
    tmp_path: Path,
) -> None:
    config = _config(config_path, tmp_path)
    spec = _write_yaml(
        tmp_path / "spec.yaml",
        {
            "openapi": "3.0.3",
            "info": {"title": "Unsafe API", "version": "1"},
            "paths": {
                "//other-host/reports": {
                    "get": {"operationId": "readAdminReports"}
                }
            },
        },
    )
    values = _write_yaml(
        tmp_path / "values.yaml",
        {"operations": {"read_admin_reports": {"operation_id": "readAdminReports"}}},
    )

    with pytest.raises(OpenAPIError, match="unsafe request path"):
        compile_openapi_operations(config, spec, values)


@pytest.mark.parametrize(
    ("name", "definition", "value", "expected"),
    [
        ("id", {"style": "simple", "explode": False}, "a b", "a%20b"),
        ("id", {"style": "simple", "explode": False}, ["a", "b"], "a,b"),
        ("id", {"style": "label", "explode": True}, ["a", "b"], ".a.b"),
        ("id", {"style": "matrix", "explode": True}, ["a", "b"], ";id=a;id=b"),
        (
            "id",
            {"style": "simple", "explode": False},
            {"role": "admin"},
            "role,admin",
        ),
        (
            "id",
            {"style": "label", "explode": True},
            {"role": "admin", "name": "Ada"},
            ".role=admin.name=Ada",
        ),
        (
            "id",
            {"style": "matrix", "explode": False},
            {"role": "admin"},
            ";id=role,admin",
        ),
    ],
)
def test_serializes_openapi_path_parameter_styles(
    name: str,
    definition: dict,
    value: object,
    expected: str,
) -> None:
    assert _serialize_path_parameter(name, definition, value) == expected


@pytest.mark.parametrize(
    ("name", "definition", "value", "expected"),
    [
        (
            "tag",
            {"style": "form", "explode": True},
            ["a", "b"],
            [("tag", "a"), ("tag", "b")],
        ),
        (
            "tag",
            {"style": "form", "explode": False},
            ["a", "b"],
            [("tag", "a,b")],
        ),
        (
            "tag",
            {"style": "spaceDelimited", "explode": False},
            ["a", "b"],
            [("tag", "a b")],
        ),
        (
            "tag",
            {"style": "pipeDelimited", "explode": False},
            ["a", "b"],
            [("tag", "a|b")],
        ),
        (
            "filter",
            {"style": "form", "explode": True},
            {"state": "open"},
            [("state", "open")],
        ),
        (
            "filter",
            {"style": "form", "explode": False},
            {"state": "open"},
            [("filter", "state,open")],
        ),
        (
            "filter",
            {"style": "deepObject", "explode": True},
            {"state": "open"},
            [("filter[state]", "open")],
        ),
    ],
)
def test_serializes_openapi_query_parameter_styles(
    name: str,
    definition: dict,
    value: object,
    expected: list[tuple[str, str]],
) -> None:
    assert _serialize_query_parameter(name, definition, value) == expected


def test_serializes_openapi_header_objects() -> None:
    assert _serialize_header_parameter(
        "X-Filter",
        {"style": "simple", "explode": True},
        {"state": "open", "owner": "alice"},
    ) == "state=open,owner=alice"
