from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from authmatrix.config import AuthConfig, Identity, load_config
from authmatrix.errors import ScanError, ScopeError
from authmatrix.scanner import (
    _auth_for,
    _parse_returned_object_id,
    _parse_returned_object_ids,
    run_authorization_tests,
)


def _config(config_path: Path, port: int, tmp_path: Path):
    """Load the example policy and point it at the local test server."""
    import yaml

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    data["scope"]["base_url"] = f"http://127.0.0.1:{port}"
    data["scope"]["allowed_hosts"] = ["127.0.0.1"]

    path = tmp_path / "test-policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return load_config(path)


def test_vulnerable_lab_detects_authorization_failures(
    config_path: Path, demo_server: int, auth_env, tmp_path: Path
) -> None:
    config = _config(config_path, demo_server, tmp_path)

    result = run_authorization_tests(config)

    assert result["summary"] == {
        "requests": 9,
        "passed": 5,
        "failed": 4,
        "inconclusive": 0,
        "findings": 4,
    }

    assert {finding["category"] for finding in result["findings"]} == {
        "BOLA",
        "BFLA",
    }


@pytest.mark.parametrize("demo_server", ["fixed"], indirect=True)
def test_fixed_lab_has_no_authorization_findings(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
) -> None:
    config = _config(config_path, demo_server, tmp_path)

    result = run_authorization_tests(config)

    assert result["summary"]["findings"] == 0
    assert result["summary"]["failed"] == 0


def test_missing_credentials_are_reported(
    config_path: Path,
    demo_server: int,
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("AUTHMATRIX_ALICE_TOKEN", raising=False)
    monkeypatch.delenv("AUTHMATRIX_BOB_TOKEN", raising=False)
    monkeypatch.delenv("AUTHMATRIX_ADMIN_TOKEN", raising=False)

    config = _config(config_path, demo_server, tmp_path)

    with pytest.raises(ScanError, match="authentication environment variable"):
        run_authorization_tests(config)


def test_redirects_are_not_followed(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import authmatrix.scanner as scanner

    class RedirectClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            class Response:
                status_code = 302
                headers = {"location": "http://127.0.0.1:9999/"}

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return None

            return Response()

    monkeypatch.setattr(scanner.httpx, "Client", RedirectClient)

    config = _config(config_path, demo_server, tmp_path)

    with pytest.raises(ScopeError, match="redirects are never followed"):
        run_authorization_tests(config)


def test_report_does_not_contain_authentication_secrets(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
) -> None:
    config = _config(config_path, demo_server, tmp_path)

    result = run_authorization_tests(config)
    serialized = json.dumps(result)

    assert "alice-local-token" not in serialized
    assert "bob-local-token" not in serialized
    assert "admin-local-token" not in serialized


def test_basic_auth_uses_environment_credentials(monkeypatch) -> None:
    monkeypatch.setenv("TEST_BASIC_USER", "test-user")
    monkeypatch.setenv("TEST_BASIC_PASSWORD", "test-password")

    identity = Identity(
        name="tester",
        role="user",
        auth=AuthConfig(
            kind="basic",
            username_env="TEST_BASIC_USER",
            password_env="TEST_BASIC_PASSWORD",
        ),
    )

    headers, auth = _auth_for(identity)

    assert headers == {}
    assert isinstance(auth, httpx.BasicAuth)


def test_request_limit_is_checked_before_network(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
) -> None:
    config = _config(config_path, demo_server, tmp_path)
    config = replace(config, max_requests=1)

    with pytest.raises(ScanError, match="max_requests"):
        run_authorization_tests(config)


def test_response_size_limit_is_enforced(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
) -> None:
    config = _config(config_path, demo_server, tmp_path)
    config = replace(config, max_response_bytes=1)

    with pytest.raises(ScanError, match="exceeded"):
        run_authorization_tests(config)


def test_connection_error_is_reported_without_credentials(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import authmatrix.scanner as scanner

    class FailedClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(scanner.httpx, "Client", FailedClient)

    config = _config(config_path, demo_server, tmp_path)

    with pytest.raises(ScanError, match="ConnectError") as error:
        run_authorization_tests(config)

    assert "alice-local-token" not in str(error.value)
    assert "bob-local-token" not in str(error.value)
    assert "admin-local-token" not in str(error.value)


def test_policy_owner_mapping_identifies_cross_user_access(
    config_path: Path,
) -> None:
    config = load_config(config_path)
    owners = config.resources["items"].owner_by_id

    assert owners["1"] == "alice"
    assert owners["2"] == "bob"

    # Alice accessing Bob's resource is a cross-user access attempt.
    assert owners["2"] != "alice"

    # Bob accessing Alice's resource is a cross-user access attempt.
    assert owners["1"] != "bob"


@pytest.mark.parametrize(
    ("response_body", "expected_actual", "expected_inconclusive"),
    [
        (b'{"id":"1","value":"sample"}', "allow", False),
        (b'{"value":"sample"}', "unknown", True),
        (b'{"id":"2","value":"sample"}', "unknown", True),
        (b"not-valid-json", "unknown", True),
        (b"[]", "unknown", True),
    ],
)
def test_bola_response_object_id_verification(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
    monkeypatch,
    response_body: bytes,
    expected_actual: str,
    expected_inconclusive: bool,
) -> None:
    import authmatrix.scanner as scanner

    class MockResponse:
        status_code = 200
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_bytes(self):
            yield response_body

    class MockClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            return MockResponse()

    monkeypatch.setattr(scanner.httpx, "Client", MockClient)

    config = _config(config_path, demo_server, tmp_path)

    # Keep one BOLA operation and one identity/resource combination.
    operation = next(op for op in config.operations if op.category == "BOLA")
    identity_name = next(iter(config.identities))
    config = replace(
        config,
        identities={identity_name: config.identities[identity_name]},
        resources={
            operation.resource: replace(
                config.resources[operation.resource],
                ids=("1",),
            )
        },
        operations=(operation,),
    )

    result = run_authorization_tests(config)

    check = result["checks"][0]

    assert check["actual"] == expected_actual
    assert check["inconclusive"] is expected_inconclusive
    assert check["passed"] is (not expected_inconclusive)
    assert result["summary"]["inconclusive"] == int(expected_inconclusive)

    if expected_inconclusive:
        assert result["summary"]["failed"] == 0
        assert result["findings"] == []
    else:
        assert result["summary"]["passed"] == 1


def test_bola_uses_configured_nested_response_id_path(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import authmatrix.scanner as scanner

    class MockResponse:
        status_code = 200
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_bytes(self):
            yield b'{"data":{"order":{"id":"1"}}}'

    class MockClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            return MockResponse()

    monkeypatch.setattr(scanner.httpx, "Client", MockClient)

    config = _config(config_path, demo_server, tmp_path)
    operation = next(op for op in config.operations if op.category == "BOLA")

    operation = replace(operation, response_id_path="data.order.id")

    identity_name = next(iter(config.identities))

    config = replace(
        config,
        identities={identity_name: config.identities[identity_name]},
        resources={
            operation.resource: replace(
                config.resources[operation.resource],
                ids=("1",),
            )
        },
        operations=(operation,),
    )

    result = run_authorization_tests(config)

    check = result["checks"][0]

    assert check["actual"] == "allow"
    assert check["inconclusive"] is False
    assert check["passed"] is True
    assert result["summary"]["inconclusive"] == 0


def test_verified_unauthorized_object_access_creates_finding(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import authmatrix.scanner as scanner

    class MockResponse:
        status_code = 200
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_bytes(self):
            yield b'{"data":{"orders":[{"id":"1"},{"id":"2"},{"id":"1"}]}}'

    class MockClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            return MockResponse()

    monkeypatch.setattr(scanner.httpx, "Client", MockClient)

    config = _config(config_path, demo_server, tmp_path)

    operation = next(op for op in config.operations if op.category == "BOLA")
    identity_name = "bob"

    operation = replace(
        operation,
        expected={identity_name: {"1": "deny"}},
        response_id_path="data.orders[*].id",
    )

    config = replace(
        config,
        identities={identity_name: config.identities[identity_name]},
        resources={
            operation.resource: replace(
                config.resources[operation.resource],
                ids=("1",),
            )
        },
        operations=(operation,),
    )

    result = run_authorization_tests(config)

    assert result["summary"]["requests"] == 1
    assert result["summary"]["failed"] == 1
    assert result["summary"]["inconclusive"] == 0
    assert result["summary"]["findings"] == 1

    finding = result["findings"][0]

    assert finding["category"] == "BOLA"
    assert finding["severity"] == "high"
    assert finding["evidence"]["object_id_verified"] is True
    assert finding["evidence"]["requested_resource_id"] == "1"
    assert finding["evidence"]["returned_resource_ids"] == ["1", "2"]
    assert "returned_resource_id" not in finding["evidence"]


@pytest.mark.parametrize(
    ("body", "path", "expected"),
    [
        (b'{"id":"42"}', "id", "42"),
        (b'{"data":{"order":{"id":"42"}}}', "data.order.id", "42"),
        (
            b'{"data":{"orders":[{"id":"10"},{"id":"20"}]}}',
            "data.orders[0].id",
            "10",
        ),
        (
            b'{"data":{"orders":[{"id":"10"},{"id":"20"}]}}',
            "data.orders[1].id",
            "20",
        ),
        (
            b'{"data":{"orders":[{"items":[{"id":"99"}]}]}}',
            "data.orders[0].items[0].id",
            "99",
        ),
        (b'{"id":42}', "id", "42"),
    ],
)
def test_parse_returned_object_id_valid_paths(
    body: bytes,
    path: str,
    expected: str,
) -> None:
    assert _parse_returned_object_id(body, path) == expected


@pytest.mark.parametrize(
    ("body", "path"),
    [
        (b'{"data":{"orders":[]}}', "data.orders[0].id"),
        (
            b'{"data":{"orders":[{"id":"10"}]}}',
            "data.orders[1].id",
        ),
        (b'{"data":{"orders":[{"id":"10"}]}}', "data.orders[-1].id"),
        (b'{"data":{"orders":[{"id":"10"}]}}', "data.orders[].id"),
        (b'{"data":{"orders":[{"id":"10"}]}}', "data.orders[0]id"),
        (b'{"data":{"orders":[{"id":"10"}]}}', "data..orders[0].id"),
        (b'{"data":{"orders":[{"id":"10"}]}}', "data.orders[0]."),
        (b'{"id":true}', "id"),
        (b'{"id":null}', "id"),
        (b'{"id":{"value":"42"}}', "id"),
        (b'{"id":["42"]}', "id"),
        (b'{"id":42.5}', "id"),
        (b"not-valid-json", "id"),
        (b'{"id":"42"}', ""),
    ],
)
def test_parse_returned_object_id_invalid_or_missing_values(
    body: bytes,
    path: str,
) -> None:
    assert _parse_returned_object_id(body, path) is None


@pytest.mark.parametrize(
    ("body", "path", "expected"),
    [
        (
            b'{"data":{"orders":[{"id":"10"},{"id":"20"},{"id":"30"}]}}',
            "data.orders[*].id",
            ("10", "20", "30"),
        ),
        (
            b'{"data":{"orders":[{"id":"10"},{"id":"10"},{"id":"20"}]}}',
            "data.orders[*].id",
            ("10", "20"),
        ),
        (
            b'{"data":{"orders":[{"id":10},{"id":20}]}}',
            "data.orders[*].id",
            ("10", "20"),
        ),
        (
            b'{"data":{"orders":[{"id":"10"},{"id":true},{"id":null},{"id":{}},{"id":"20"}]}}',
            "data.orders[*].id",
            ("10", "20"),
        ),
        (
            b'{"data":{"groups":[{"items":[{"id":"1"},{"id":"2"}]},{"items":[{"id":"3"}]}]}}',
            "data.groups[*].items[*].id",
            ("1", "2", "3"),
        ),
        (
            b'{"data":{"orders":[{"id":"10"},{"id":"20"}]}}',
            "data.orders[1].id",
            ("20",),
        ),
    ],
)
def test_parse_returned_object_ids(
    body: bytes,
    path: str,
    expected: tuple[str, ...],
) -> None:
    assert _parse_returned_object_ids(body, path) == expected


@pytest.mark.parametrize(
    ("body", "path"),
    [
        (b'{"data":{"orders":[]}}', "data.orders[*].id"),
        (b'{"data":{"orders":[{"name":"missing"}]}}', "data.orders[*].id"),
        (b'{"data":{"orders":[{"id":true},{"id":null}]}}', "data.orders[*].id"),
        (b"not-valid-json", "data.orders[*].id"),
        (b'{"data":{"orders":[{"id":"1"}]}}', "data.orders[**].id"),
    ],
)
def test_parse_returned_object_ids_missing_or_invalid(
    body: bytes,
    path: str,
) -> None:
    assert _parse_returned_object_ids(body, path) is None


def test_parse_returned_object_ids_enforces_limit() -> None:
    body = (
        b'{"items":'
        + (
            b"["
            + b",".join(
                b'{"id":"' + str(index).encode() + b'"}' for index in range(101)
            )
            + b"]"
        )
        + b"}"
    )

    assert (
        _parse_returned_object_ids(
            body,
            "items[*].id",
            max_ids=100,
        )
        is None
    )


def test_parse_returned_object_ids_rejects_invalid_limit() -> None:
    body = b'{"id":"1"}'

    assert _parse_returned_object_ids(body, "id", max_ids=0) is None
    assert _parse_returned_object_ids(body, "id", max_ids=True) is None


def test_unrelated_returned_ids_are_inconclusive_not_a_finding(
    config_path: Path,
    demo_server: int,
    auth_env,
    tmp_path: Path,
    monkeypatch,
) -> None:
    import authmatrix.scanner as scanner

    class MockResponse:
        status_code = 200
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_bytes(self):
            yield b'{"data":{"orders":[{"id":"2"},{"id":"3"}]}}'

    class MockClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            return MockResponse()

    monkeypatch.setattr(scanner.httpx, "Client", MockClient)

    config = _config(config_path, demo_server, tmp_path)
    operation = next(op for op in config.operations if op.category == "BOLA")
    identity_name = "bob"

    operation = replace(
        operation,
        expected={identity_name: {"1": "deny"}},
        response_id_path="data.orders[*].id",
    )

    config = replace(
        config,
        identities={identity_name: config.identities[identity_name]},
        resources={
            operation.resource: replace(
                config.resources[operation.resource],
                ids=("1",),
            )
        },
        operations=(operation,),
    )

    result = run_authorization_tests(config)

    check = result["checks"][0]
    assert check["actual"] == "unknown"
    assert check["inconclusive"] is True
    assert check["returned_resource_ids"] == ["2", "3"]
    assert result["summary"]["findings"] == 0
    assert result["summary"]["inconclusive"] == 1
