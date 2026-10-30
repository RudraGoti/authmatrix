
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from authmatrix.config import AuthConfig, Identity, load_config
from authmatrix.errors import ScanError, ScopeError
from authmatrix.scanner import _auth_for, run_authorization_tests


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
