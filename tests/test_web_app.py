from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi.testclient import TestClient

from authmatrix.errors import AuthMatrixError, ConfigurationError, ScanError, ScopeError
from authmatrix.web.app import create_app


@pytest.fixture(autouse=True)
def isolate_web_database(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTHMATRIX_DATA_DIR", str(tmp_path / "authmatrix-data"))


def test_health_endpoint():
    client = TestClient(create_app())

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "version" in response.json()


def test_status_endpoint():
    client = TestClient(create_app())

    response = client.get("/api/status")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert "authorization_scanning" in response.json()["capabilities"]
    assert "persistent_scan_history" in response.json()["capabilities"]


def test_openapi_endpoint():
    client = TestClient(create_app())

    response = client.get("/api/openapi.json")

    assert response.status_code == 200
    assert "/api/health" in response.json()["paths"]
    assert "/api/scans" in response.json()["paths"]
    assert response.json()["paths"]["/api/scans"]["post"]["responses"]["409"]


def test_openapi_mapping_endpoint_lists_local_mapping_files(tmp_path, monkeypatch):
    mapping_dir = tmp_path / "mappings"
    mapping_dir.mkdir()
    (mapping_dir / "scan.mapping.yaml").write_text(
        "operations: {}\n",
        encoding="utf-8",
    )
    (mapping_dir / "ignore.yaml").write_text("not a mapping\n", encoding="utf-8")
    monkeypatch.setenv("AUTHMATRIX_OPENAPI_VALUES_DIR", str(mapping_dir))

    response = TestClient(create_app()).get("/api/openapi/mappings")

    assert response.status_code == 200
    assert response.json() == {"mappings": ["scan.mapping.yaml"]}


def test_scan_accepts_openapi_selection_and_returns_skipped_operations(
    tmp_path,
    monkeypatch,
):
    from authmatrix.web import app as app_module

    openapi_dir = tmp_path / "openapi"
    openapi_dir.mkdir()
    (openapi_dir / "spec.yaml").write_text("openapi: 3.0.3\n", encoding="utf-8")
    values_dir = tmp_path / "values"
    values_dir.mkdir()
    (values_dir / "scan.mapping.yaml").write_text(
        "operations: {}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AUTHMATRIX_OPENAPI_VALUES_DIR", str(values_dir))
    calls = []

    def fake_scan(*args):
        calls.append(args)
        return {
            "schema_version": 1,
            "scan_id": "scan-id",
            "generated_at": "2026-11-04T00:00:00+00:00",
            "target": "http://127.0.0.1:8000",
            "policy": "policy.yaml",
            "identities": [],
            "limitations": [],
            "summary": {
                "requests": 0,
                "passed": 0,
                "failed": 0,
                "inconclusive": 0,
                "findings": 0,
                "skipped": 1,
            },
            "findings": [],
            "checks": [],
            "skipped_operations": [
                {
                    "operation_id": "read_item",
                    "method": "GET",
                    "path": "/items/{item_id}",
                    "reason": "No explicit value mapping.",
                }
            ],
        }

    monkeypatch.setattr(app_module, "run_policy_scan", fake_scan)
    application = create_app(policy_dir=tmp_path, openapi_dir=openapi_dir)
    client = TestClient(application)

    response = client.post(
        "/api/scans",
        json={
            "policy_path": "policy.yaml",
            "authorization_confirmed": True,
            "openapi_spec": "spec.yaml",
            "values_mapping": "scan.mapping.yaml",
        },
    )

    assert response.status_code == 200
    assert response.json()["summary"]["skipped"] == 1
    assert response.json()["skipped_operations"][0]["reason"] == (
        "No explicit value mapping."
    )
    assert calls == [
        (
            "policy.yaml",
            application.state.policy_dir,
            "spec.yaml",
            "scan.mapping.yaml",
            application.state.openapi_dir,
            application.state.openapi_values_dir,
            application.state.openapi_max_bytes,
        )
    ]


def test_gui_scan_runs_existing_engine_and_exposes_final_result(
    tmp_path,
    config_path,
    demo_server,
    auth_env,
):
    policy_text = config_path.read_text(encoding="utf-8").replace(
        "http://127.0.0.1:8000",
        f"http://127.0.0.1:{demo_server}",
    )
    (tmp_path / "policy.yaml").write_text(policy_text, encoding="utf-8")
    client = TestClient(create_app(policy_dir=tmp_path))

    policy = client.get("/api/policies/policy.yaml")
    assert policy.status_code == 200
    metadata = policy.json()
    assert metadata["target"] == f"http://127.0.0.1:{demo_server}"
    assert metadata["allowed_hosts"] == ["127.0.0.1"]
    assert [(item["name"], item["role"]) for item in metadata["identities"]] == [
        ("alice", "user"),
        ("bob", "user"),
        ("admin", "admin"),
    ]
    assert [
        (item["id"], item["method"], item["path"])
        for item in metadata["operations"]
    ] == [
        ("read_item", "GET", "/items/{item_id}"),
        ("read_admin_reports", "GET", "/admin/reports"),
    ]
    assert metadata["max_requests"] == 12
    assert metadata["timeout_seconds"] == 3
    assert metadata["max_response_bytes"] == 65536

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "completed"
    assert result["summary"] == {
        "requests": 9,
        "passed": 5,
        "failed": 4,
        "inconclusive": 0,
        "findings": 4,
        "skipped": 0,
    }
    scan_id = result["scan_id"]
    assert client.get(f"/api/scans/{scan_id}").json() == result
    record = client.get("/api/scans").json()["scans"][0]
    assert record["scan_id"] == scan_id
    assert record["status"] == "completed"
    assert client.get(f"/api/scans/{scan_id}/report.json").json() == result


def test_out_of_scope_policy_is_rejected_before_http_client_creation(
    tmp_path,
    config_path,
    monkeypatch,
):
    from authmatrix import scanner

    policy_text = config_path.read_text(encoding="utf-8").replace(
        "http://127.0.0.1:8000",
        "http://192.0.2.1:8000",
    ).replace("    - 127.0.0.1\n", "    - 192.0.2.1\n", 1)
    (tmp_path / "policy.yaml").write_text(policy_text, encoding="utf-8")
    client = TestClient(create_app(policy_dir=tmp_path))
    client_created = False

    def unexpected_http_client(*args, **kwargs):
        nonlocal client_created
        client_created = True
        raise AssertionError("Out-of-scope policy attempted network access.")

    monkeypatch.setattr(scanner.httpx, "Client", unexpected_http_client)
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "scope_error"
    assert not client_created


def test_request_limit_is_enforced_before_http_client_creation(
    tmp_path,
    config_path,
    demo_server,
    monkeypatch,
):
    from authmatrix import scanner

    policy_text = (
        config_path.read_text(encoding="utf-8")
        .replace("http://127.0.0.1:8000", f"http://127.0.0.1:{demo_server}")
        .replace("  max_requests: 12\n", "  max_requests: 1\n")
    )
    (tmp_path / "policy.yaml").write_text(policy_text, encoding="utf-8")
    client = TestClient(create_app(policy_dir=tmp_path))
    client_created = False

    def unexpected_http_client(*args, **kwargs):
        nonlocal client_created
        client_created = True
        raise AssertionError("Over-limit scan attempted network access.")

    monkeypatch.setattr(scanner.httpx, "Client", unexpected_http_client)
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "scan_error"
    assert response.json()["detail"] == (
        "The scan exceeds the request limit configured by the policy."
    )
    assert not client_created


def test_scan_requires_openapi_spec_and_mapping_together():
    response = TestClient(create_app()).post(
        "/api/scans",
        json={
            "policy_path": "policy.yaml",
            "authorization_confirmed": True,
            "openapi_spec": "spec.yaml",
        },
    )

    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"


def test_scan_rejects_unknown_request_fields():
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={
            "policy_path": "policy.yaml",
            "authorization_confirmed": True,
            "base_url": "http://example.com",
        },
    )

    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"
    assert "base_url" not in response.text


def test_scan_rejects_missing_policy_path():
    client = TestClient(create_app())

    response = client.post("/api/scans", json={})

    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"


def test_scan_requires_explicit_authorization_confirmation():
    response = TestClient(create_app()).post(
        "/api/scans",
        json={"policy_path": "policy.yaml"},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "authorization_required"
    assert response.headers["cache-control"] == "no-store"


def test_scan_rejects_false_authorization_confirmation():
    response = TestClient(create_app()).post(
        "/api/scans",
        json={
            "policy_path": "policy.yaml",
            "authorization_confirmed": False,
        },
    )

    assert response.status_code == 403
    assert response.json()["error"] == "authorization_required"


def test_invalid_policy_is_rejected_before_http_client_creation(
    tmp_path,
    monkeypatch,
):
    from authmatrix import scanner

    (tmp_path / "invalid.yaml").write_text(
        "version: 1\n"
        "scope:\n"
        "  authorized: true\n"
        "  base_url: http://127.0.0.1:8000\n"
        "  allowed_hosts: [127.0.0.1]\n"
        "identities: {}\n",
        encoding="utf-8",
    )
    client = TestClient(create_app(policy_dir=tmp_path))
    client_created = False

    def unexpected_http_client(*args, **kwargs):
        nonlocal client_created
        client_created = True
        raise AssertionError("Invalid policy attempted network access.")

    monkeypatch.setattr(scanner.httpx, "Client", unexpected_http_client)
    response = client.post(
        "/api/scans",
        json={
            "policy_path": "invalid.yaml",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 422
    assert response.json()["error"] == "configuration_error"
    assert not client_created


def test_scan_returns_sanitized_configuration_error(tmp_path, monkeypatch):
    from authmatrix.web import app as app_module

    def raise_configuration_error(*args, **kwargs):
        raise ConfigurationError("Sensitive internal detail")

    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        raise_configuration_error,
    )

    client = TestClient(create_app(policy_dir=tmp_path))
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "configuration_error"
    assert "Sensitive internal detail" not in response.text


def test_scan_returns_sanitized_scope_error(tmp_path, monkeypatch):
    from authmatrix.web import app as app_module

    def raise_scope_error(*args, **kwargs):
        raise ScopeError("Sensitive internal detail")

    monkeypatch.setattr(app_module, "run_policy_scan", raise_scope_error)

    client = TestClient(create_app(policy_dir=tmp_path))
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "scope_error"
    assert "Sensitive internal detail" not in response.text


def test_scan_returns_sanitized_scan_error(tmp_path, monkeypatch):
    from authmatrix.web import app as app_module

    def raise_scan_error(*args, **kwargs):
        raise ScanError("Sensitive internal detail")

    monkeypatch.setattr(app_module, "run_policy_scan", raise_scan_error)

    client = TestClient(create_app(policy_dir=tmp_path))
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "scan_error"
    assert response.json()["detail"] == "The scan could not be completed safely."
    assert "Sensitive internal detail" not in response.text


def test_scan_returns_sanitized_missing_credentials_error(monkeypatch):
    for name in (
        "AUTHMATRIX_ALICE_TOKEN",
        "AUTHMATRIX_BOB_TOKEN",
        "AUTHMATRIX_ADMIN_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)

    client = TestClient(create_app())
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": "scan_error",
        "detail": (
            "A required authentication credential is not configured "
            "in the server environment."
        ),
    }


def test_scan_returns_sanitized_target_unavailable_error(monkeypatch):
    import httpx

    from authmatrix import scanner as scanner_module

    for name in (
        "AUTHMATRIX_ALICE_TOKEN",
        "AUTHMATRIX_BOB_TOKEN",
        "AUTHMATRIX_ADMIN_TOKEN",
    ):
        monkeypatch.setenv(name, "test-only-placeholder")

    class FailedClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            raise httpx.ConnectError("Sensitive internal detail")

    client = TestClient(create_app())
    monkeypatch.setattr(scanner_module.httpx, "Client", FailedClient)

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": "scan_error",
        "detail": (
            "Could not reach the authorized local target. "
            "Confirm it is running and accessible."
        ),
    }
    assert "Sensitive internal detail" not in response.text
    assert "test-only-placeholder" not in response.text


def test_scan_returns_sanitized_authmatrix_error(tmp_path, monkeypatch):
    from authmatrix.web import app as app_module

    def raise_authmatrix_error(*args, **kwargs):
        raise AuthMatrixError("Sensitive internal detail")

    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        raise_authmatrix_error,
    )

    client = TestClient(create_app(policy_dir=tmp_path))
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 400
    assert response.json()["error"] == "authmatrix_error"
    assert "Sensitive internal detail" not in response.text


def test_scan_returns_successful_result(tmp_path, monkeypatch):
    from authmatrix.web import app as app_module

    expected_result = {
        "schema_version": 1,
        "generated_at": "2026-10-31T12:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "summary": {
            "requests": 2,
            "passed": 1,
            "failed": 1,
            "inconclusive": 0,
            "findings": 1,
        },
        "findings": [],
        "checks": [],
    }

    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        lambda *args, **kwargs: expected_result,
    )

    client = TestClient(create_app(policy_dir=tmp_path))
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 200
    assert response.json()["schema_version"] == 1
    assert response.json()["summary"]["requests"] == 2
    assert response.json()["target"] == expected_result["target"]


def test_scan_history_findings_and_reports_use_real_scan_results(monkeypatch):
    from authmatrix.web import app as app_module

    finding = {
        "id": "read_item:bob:1",
        "category": "BOLA",
        "severity": "high",
        "title": "<script>unsafe()</script>",
        "operation_id": "read_item",
        "evidence": {"requested_resource_id": "1"},
        "reproduction": {
            "method": "GET",
            "path": "/items/1",
            "identity": "bob",
        },
        "remediation": "Enforce object-level authorization.",
    }
    expected_result = {
        "schema_version": 1,
        "generated_at": "2026-10-31T12:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "policy": "policy.yaml",
        "identities": [{"name": "bob", "role": "user"}],
        "limitations": ["Configured operations only."],
        "summary": {
            "requests": 1,
            "passed": 0,
            "failed": 1,
            "inconclusive": 0,
            "findings": 1,
        },
        "findings": [finding],
        "checks": [],
    }
    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        lambda *args, **kwargs: expected_result,
    )
    client = TestClient(create_app())

    initial_history = client.get("/api/scans")
    assert initial_history.json() == {
        "summary": {"total": 0, "completed": 0, "failed": 0, "findings": 0},
        "scans": [],
    }

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )
    scan_id = response.json()["scan_id"]

    assert response.status_code == 200
    assert scan_id
    assert response.json()["status"] == "completed"
    assert client.get("/api/scans").json()["summary"] == {
        "total": 1,
        "completed": 1,
        "failed": 0,
        "findings": 1,
    }
    assert client.get(f"/api/scans/{scan_id}").json()["findings"] == [finding]

    findings = client.get("/api/findings").json()["findings"]
    assert findings[0]["scan_id"] == scan_id
    assert findings[0]["title"] == finding["title"]

    json_report = client.get(f"/api/scans/{scan_id}/report.json")
    assert json_report.status_code == 200
    assert json_report.json()["policy"] == "policy.yaml"

    html_report = client.get(f"/api/scans/{scan_id}/report.html")
    assert html_report.status_code == 200
    assert "<script>unsafe()</script>" not in html_report.text
    assert "&lt;script&gt;unsafe()&lt;/script&gt;" in html_report.text
    assert "Configured operations only." in html_report.text
    _assert_security_headers(html_report)
    assert html_report.headers["cache-control"] == "no-store"

    missing = client.get("/api/scans/not-a-scan/report.json")
    assert missing.status_code == 404
    assert missing.json()["error"] == "report_not_found"


def test_scan_result_secrets_are_redacted_before_storage_and_api_access(
    monkeypatch,
):
    from authmatrix.web import app as app_module

    secret_values = (
        "bearer-secret-value",
        "private-api-key-value",
        "inline-password-value",
    )
    result = {
        "schema_version": 1,
        "generated_at": "2026-11-04T10:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "summary": {
            "requests": 1,
            "passed": 0,
            "failed": 1,
            "inconclusive": 0,
            "findings": 1,
        },
        "findings": [
            {
                "id": "read_status:alice",
                "title": "Authorization check",
                "severity": "high",
                "category": "BFLA",
                "operation_id": "read_status",
                "evidence": {"X-Api-Key": secret_values[1]},
                "reproduction": {
                    "method": "GET",
                    "path": "/status",
                    "identity": "alice",
                },
                "remediation": "Enforce access control.",
            }
        ],
        "checks": [
            {
                "request_headers": {
                    "Authorization": f"Bearer {secret_values[0]}"
                },
                "details": f"password={secret_values[2]}",
            }
        ],
    }
    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        lambda *args, **kwargs: result,
    )
    client = TestClient(create_app())
    scan_response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )
    scan = scan_response.json()
    scan_id = scan["scan_id"]
    stored = client.get(f"/api/scans/{scan_id}").text
    json_report = client.get(f"/api/scans/{scan_id}/report.json").text
    html_report = client.get(f"/api/scans/{scan_id}/report.html").text
    findings = client.get("/api/findings").text

    for secret in secret_values:
        assert secret not in scan_response.text
        assert secret not in stored
        assert secret not in json_report
        assert secret not in html_report
        assert secret not in findings


def test_scan_history_and_reports_persist_after_app_restart(tmp_path, monkeypatch):
    from authmatrix.web import app as app_module

    result = {
        "schema_version": 1,
        "generated_at": "2026-11-04T10:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "summary": {
            "requests": 1,
            "passed": 1,
            "failed": 0,
            "inconclusive": 0,
            "findings": 0,
        },
        "findings": [],
        "checks": [],
    }
    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        lambda *args, **kwargs: result.copy(),
    )
    first_client = TestClient(create_app(data_dir=tmp_path))
    scan_response = first_client.post(
        "/api/scans",
        json={
            "policy_path": "policy.yaml",
            "authorization_confirmed": True,
        },
    )
    scan_id = scan_response.json()["scan_id"]

    second_client = TestClient(create_app(data_dir=tmp_path))

    assert scan_response.status_code == 200
    assert second_client.get("/api/scans").json()["summary"]["completed"] == 1
    assert second_client.get(f"/api/scans/{scan_id}").json()["scan_id"] == scan_id
    assert second_client.get(
        f"/api/scans/{scan_id}/report.json"
    ).json()["status"] == "completed"


def test_baseline_comparison_api_compares_persisted_scan_results(monkeypatch):
    from authmatrix.web import app as app_module

    finding = {
        "id": "read_item:bob:1",
        "category": "BOLA",
        "severity": "high",
        "title": "Unauthorized object access",
        "operation_id": "read_item",
        "evidence": {"http_status": 200},
        "reproduction": {
            "method": "GET",
            "path": "/items/1",
            "identity": "bob",
            "resource_id": "1",
        },
        "remediation": "Enforce object-level authorization.",
    }
    results = [
        {
            "schema_version": 1,
            "generated_at": f"2026-11-04T10:0{index}:00+00:00",
            "target": "http://127.0.0.1:8000",
            "summary": {
                "requests": 1,
                "passed": 1,
                "failed": 0,
                "inconclusive": 0,
                "findings": len(findings_for_scan),
            },
            "findings": findings_for_scan,
            "checks": [],
        }
        for index, findings_for_scan in enumerate(([], [finding]))
    ]
    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        lambda *args, **kwargs: results.pop(0),
    )
    client = TestClient(create_app())

    scan_ids = []
    for _ in range(2):
        response = client.post(
            "/api/scans",
            json={
                "policy_path": "policy.yaml",
                "authorization_confirmed": True,
            },
        )
        scan_ids.append(response.json()["scan_id"])

    comparison = client.post(
        "/api/comparisons",
        json={
            "baseline_scan_id": scan_ids[0],
            "current_scan_id": scan_ids[1],
        },
    )

    assert comparison.status_code == 200
    assert comparison.json()["summary"] == {"new": 1, "fixed": 0, "recurring": 0}


def test_baseline_comparison_rejects_cross_origin_post():
    response = TestClient(create_app()).post(
        "/api/comparisons",
        json={
            "baseline_scan_id": "baseline",
            "current_scan_id": "current",
        },
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "csrf_error"


def test_failed_scan_is_counted_without_exposing_exception(monkeypatch):
    from authmatrix.web import app as app_module

    def fail_scan(*args, **kwargs):
        raise ScanError("Sensitive failure detail")

    monkeypatch.setattr(app_module, "run_policy_scan", fail_scan)
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 422
    assert "Sensitive failure detail" not in response.text
    assert client.get("/api/scans").json()["summary"] == {
        "total": 1,
        "completed": 0,
        "failed": 1,
        "findings": 0,
    }


def test_scan_accepts_request_without_origin_or_fetch_metadata(monkeypatch):
    from authmatrix.web import app as app_module

    expected_result = {
        "schema_version": 1,
        "generated_at": "2026-10-31T12:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "summary": {
            "requests": 0,
            "passed": 0,
            "failed": 0,
            "inconclusive": 0,
            "findings": 0,
        },
        "findings": [],
        "checks": [],
    }
    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        lambda *args, **kwargs: expected_result,
    )
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 200


@pytest.mark.parametrize("configured", ["", " ", "\t  "])
def test_empty_trusted_origins_configuration_is_rejected(monkeypatch, configured):
    monkeypatch.setenv("AUTHMATRIX_TRUSTED_ORIGINS", configured)

    with pytest.raises(ValueError, match="at least one valid origin"):
        create_app()


def test_scan_accepts_configured_codespaces_origin_behind_proxy(monkeypatch):
    from authmatrix.web import app as app_module

    monkeypatch.setenv(
        "AUTHMATRIX_TRUSTED_ORIGINS",
        "https://authmatrix-123.app.github.dev",
    )
    expected_result = {
        "schema_version": 1,
        "generated_at": "2026-10-31T12:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "summary": {
            "requests": 0,
            "passed": 0,
            "failed": 0,
            "inconclusive": 0,
            "findings": 0,
        },
        "findings": [],
        "checks": [],
    }
    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        lambda *args, **kwargs: expected_result,
    )
    origin = "https://authmatrix-123.app.github.dev"
    client = TestClient(create_app(), base_url="http://127.0.0.1:8001")

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
        headers={"Origin": origin, "Sec-Fetch-Site": "same-origin"},
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {
            "Host": "attacker.example",
            "Origin": "https://attacker.example",
        },
        {
            "Host": "127.0.0.1:8001",
            "Origin": "https://attacker.example",
            "X-Forwarded-Host": "attacker.example",
            "X-Forwarded-Proto": "https",
        },
    ],
)
def test_scan_rejects_origin_matching_attacker_controlled_host_or_forwarded_headers(
    monkeypatch,
    headers,
):
    monkeypatch.setenv(
        "AUTHMATRIX_TRUSTED_ORIGINS",
        "http://127.0.0.1:8001, http://localhost:8001",
    )
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": "csrf_error",
        "detail": "Cross-origin requests are not allowed.",
    }


@pytest.mark.parametrize(
    "origin",
    ["https://attacker.example", "null", "https://testserver/path"],
)
def test_scan_rejects_malformed_or_cross_origin_origin(origin):
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
        headers={"Origin": origin},
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": "csrf_error",
        "detail": "Cross-origin requests are not allowed.",
    }


@pytest.mark.parametrize(
    "fetch_site",
    ["cross-site", "same-site", "unknown", ""],
)
def test_scan_rejects_disallowed_fetch_metadata(fetch_site):
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
        headers={"Sec-Fetch-Site": fetch_site},
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": "csrf_error",
        "detail": "Cross-origin requests are not allowed.",
    }


@pytest.mark.parametrize("fetch_site", ["same-origin", "none"])
def test_scan_accepts_allowed_fetch_metadata(monkeypatch, fetch_site):
    from authmatrix.web import app as app_module

    expected_result = {
        "schema_version": 1,
        "generated_at": "2026-10-31T12:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "summary": {
            "requests": 0,
            "passed": 0,
            "failed": 0,
            "inconclusive": 0,
            "findings": 0,
        },
        "findings": [],
        "checks": [],
    }
    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        lambda *args, **kwargs: expected_result,
    )
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
        headers={"Sec-Fetch-Site": fetch_site},
    )

    assert response.status_code == 200


def test_scan_rejects_duplicate_fetch_metadata_headers():
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
        headers=[
            ("Sec-Fetch-Site", "same-origin"),
            ("Sec-Fetch-Site", "none"),
        ],
    )

    assert response.status_code == 403
    assert response.json() == {
        "error": "csrf_error",
        "detail": "Cross-origin requests are not allowed.",
    }


def test_scan_lock_rejects_concurrent_scan_and_releases_after_completion(
    monkeypatch,
):
    from authmatrix.web import app as app_module

    scan_started = Event()
    allow_scan_to_finish = Event()
    expected_result = {
        "schema_version": 1,
        "generated_at": "2026-10-31T12:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "summary": {
            "requests": 0,
            "passed": 0,
            "failed": 0,
            "inconclusive": 0,
            "findings": 0,
        },
        "findings": [],
        "checks": [],
    }

    def blocked_scan(*args, **kwargs):
        scan_started.set()
        if not allow_scan_to_finish.wait(timeout=5):
            raise TimeoutError("Test did not release the blocked scan.")
        return expected_result

    monkeypatch.setattr(app_module, "run_policy_scan", blocked_scan)
    app = create_app()
    client = TestClient(app)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_scan = executor.submit(
            client.post,
            "/api/scans",
            json={"policy_path": "policy.yaml", "authorization_confirmed": True},
        )
        scan_id = None
        try:
            assert scan_started.wait(timeout=5)
            active = client.get("/api/scans").json()["scans"]
            assert active[0]["status"] == "running"
            scan_id = active[0]["scan_id"]
            assert scan_id
            assert client.get(f"/api/scans/{scan_id}").json()["status"] == "running"
            concurrent_response = client.post(
                "/api/scans",
                json={"policy_path": "policy.yaml", "authorization_confirmed": True},
            )
        finally:
            allow_scan_to_finish.set()

        assert concurrent_response.status_code == 409
        assert concurrent_response.json() == {
            "error": "scan_in_progress",
            "detail": "Another scan is already running.",
        }
        assert first_scan.result(timeout=5).status_code == 200
        assert first_scan.result(timeout=5).json()["scan_id"] == scan_id

    assert not app.state.scan_lock.locked()
    completed = client.get(f"/api/scans/{scan_id}").json()
    assert completed["status"] == "completed"
    assert client.get(f"/api/scans/{scan_id}/report.json").json()["status"] == (
        "completed"
    )
    assert client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    ).status_code == 200


def test_scan_returns_sanitized_unexpected_error(tmp_path, monkeypatch, caplog):
    from authmatrix.web import app as app_module

    def raise_unexpected_error(*args, **kwargs):
        raise RuntimeError("Sensitive internal detail")

    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        raise_unexpected_error,
    )

    app = create_app(policy_dir=tmp_path)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 500
    assert response.json()["error"] == "internal_server_error"
    assert response.json()["detail"] == "An unexpected server error occurred."
    assert "Sensitive internal detail" not in response.text
    assert "RuntimeError" in caplog.text
    assert "Sensitive internal detail" not in caplog.text
    assert not app.state.scan_lock.locked()
    _assert_security_headers(response)
    assert response.headers["cache-control"] == "no-store"


def test_scan_lock_releases_after_scan_exception(monkeypatch):
    from authmatrix.web import app as app_module

    def raise_scan_error(*args, **kwargs):
        raise RuntimeError("internal test error")

    monkeypatch.setattr(app_module, "run_policy_scan", raise_scan_error)
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml", "authorization_confirmed": True},
    )

    assert response.status_code == 500
    assert response.json() == {
        "error": "internal_server_error",
        "detail": "An unexpected server error occurred.",
    }
    assert "internal test error" not in response.text
    assert app.state.scan_lock.acquire(blocking=False)
    app.state.scan_lock.release()


def test_scan_rejects_malformed_json():
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        content='{"policy_path":',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"


def test_dashboard_homepage_serves_html():
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "AuthMatrix | Security Dashboard" in response.text
    assert '<link rel="icon" href="data:,">' in response.text
    assert '<nav class="navigation" aria-label="Main navigation">' in response.text
    for page in (
        "dashboard",
        "new-scan",
        "policies",
        "openapi",
        "findings",
        "reports",
        "history",
    ):
        assert f'data-page="{page}"' in response.text
    assert 'id="recent-activity"' in response.text
    assert 'aria-busy="true"' in response.text
    assert "Loading recent activity..." in response.text
    _assert_security_headers(response)


def test_dashboard_stylesheet_is_served():
    client = TestClient(create_app())

    response = client.get("/static/styles.css")

    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]
    assert ":root" in response.text
    assert "@media (max-width: 720px)" in response.text
    assert ":focus-visible" in response.text
    _assert_security_headers(response)


def test_dashboard_javascript_is_served():
    client = TestClient(create_app())

    response = client.get("/static/app.js")

    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "refreshApiStatus" in response.text
    assert 'typeof data.detail === "string"' in response.text
    assert "Scan could not be completed: ${error.message}" in response.text
    assert "Policy authorization: ${details.authorized" in response.text
    assert "Authorized hosts: ${details.allowed_hosts.join" in response.text
    assert "Operations:\\n${details.operations.map" in response.text
    assert (
        "authorization_confirmed: elements.authorizationConfirmed.checked"
        in response.text
    )
    assert "window.setInterval(pollScanState, 1000)" in response.text
    assert 'health: "/api/health"' in response.text
    assert 'status: "/api/status"' in response.text
    assert 'link.setAttribute("aria-current", "page")' in response.text
    assert 'history.pushState({ page }, "", `#${page}`)' in response.text
    assert '"API connected"' in response.text
    assert '"API offline"' in response.text
    assert "Could not load recent activity:" in response.text
    assert "localStorage" not in response.text
    assert "sessionStorage" not in response.text
    _assert_security_headers(response)


def test_api_responses_have_security_headers_and_no_store():
    response = TestClient(create_app()).get("/api/health")

    assert response.status_code == 200
    _assert_security_headers(response)
    assert response.headers["cache-control"] == "no-store"


def test_api_errors_have_security_headers_and_no_store():
    response = TestClient(create_app()).post("/api/scans", json={})

    assert response.status_code == 422
    _assert_security_headers(response)
    assert response.headers["cache-control"] == "no-store"


def _assert_security_headers(response):
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["content-security-policy"] == (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )


def test_policy_list_returns_yaml_files_only(tmp_path):
    valid_policy = """version: 1
scope:
  authorized: true
  base_url: http://127.0.0.1:8000
  allowed_hosts:
    - 127.0.0.1
identities:
  alice:
    role: user
    auth:
      type: bearer
      token_env: AUTHMATRIX_TEST_TOKEN
operations:
  - id: read_status
    category: BFLA
    method: GET
    path: /status
    expected:
      alice: allow
"""
    (tmp_path / "alpha.yaml").write_text(valid_policy)
    (tmp_path / "beta.yml").write_text(valid_policy)
    (tmp_path / "notes.txt").write_text("not a policy")
    (tmp_path / "nested").mkdir()

    client = TestClient(create_app(policy_dir=tmp_path))
    response = client.get("/api/policies")

    assert response.status_code == 200
    assert response.json() == {"policies": ["alpha.yaml", "beta.yml"]}


def test_openapi_inventory_endpoints_are_local_and_allowlisted(tmp_path):
    from pathlib import Path

    spec_dir = Path(__file__).resolve().parents[1] / "examples"
    client = TestClient(create_app(openapi_dir=spec_dir))

    documents = client.get("/api/openapi/specs")
    assert "openapi.yaml" in documents.json()["specifications"]

    inventory = client.get("/api/openapi/specs/openapi.yaml")
    assert inventory.status_code == 200
    assert inventory.json()["title"] == "AuthMatrix Local Demo API"
    assert len(inventory.json()["operations"]) == 2

    traversal = client.get("/api/openapi/specs/%2e%2e/README.md")
    assert traversal.status_code in {404, 422}


def test_openapi_endpoint_rejects_symlink_outside_configured_directory(tmp_path):
    openapi_dir = tmp_path / "openapi"
    openapi_dir.mkdir()
    outside_spec = tmp_path / "outside.yaml"
    outside_spec.write_text(
        "openapi: 3.0.3\ninfo:\n  title: Outside\n  version: 1.0.0\npaths: {}\n"
    )
    try:
        (openapi_dir / "outside.yaml").symlink_to(outside_spec)
    except (OSError, NotImplementedError):
        return

    client = TestClient(create_app(openapi_dir=openapi_dir))

    assert client.get("/api/openapi/specs").json() == {"specifications": []}
    response = client.get("/api/openapi/specs/outside.yaml")
    assert response.status_code == 400
    assert "outside.yaml" not in response.text


def test_openapi_inventory_omits_sample_values_from_parameter_schemas(tmp_path):
    spec = tmp_path / "api.yaml"
    spec.write_text(
        """\
openapi: 3.0.3
info:
  title: Local API
  version: 1.0.0
paths:
  /records:
    get:
      summary: "Bearer secret-summary-value"
      parameters:
        - in: query
          name: filter
          schema:
            type: object
            default: secret-default-value
            example: secret-example-value
            enum: [secret-enum-value]
            properties:
              token:
                type: string
                example: secret-nested-value
      responses:
        "200":
          description: OK
"""
    )
    client = TestClient(create_app(openapi_dir=tmp_path))

    response = client.get("/api/openapi/specs/api.yaml")

    assert response.status_code == 200
    schema = response.json()["operations"][0]["parameters"][0]["schema"]
    assert schema["type"] == "object"
    for sample in (
        "secret-default-value",
        "secret-example-value",
        "secret-enum-value",
        "secret-nested-value",
        "secret-summary-value",
    ):
        assert sample not in response.text


def test_openapi_inventory_endpoint_uses_configured_size_limit(tmp_path):
    spec = tmp_path / "large.yaml"
    spec.write_text("openapi: 3.0.3\n" + (" " * 2048), encoding="utf-8")
    client = TestClient(
        create_app(openapi_dir=tmp_path, openapi_max_bytes=128)
    )

    assert client.get("/api/openapi/specs").json() == {"specifications": []}
    response = client.get("/api/openapi/specs/large.yaml")
    assert response.status_code == 400
    assert "size limit" not in response.text


def test_policy_detail_exposes_safe_metadata_only():
    client = TestClient(create_app())

    response = client.get("/api/policies/policy.yaml")

    assert response.status_code == 200
    assert response.json()["name"] == "policy.yaml"
    assert response.json()["target"] == "http://127.0.0.1:8000"
    assert [item["name"] for item in response.json()["identities"]] == [
        "alice",
        "bob",
        "admin",
    ]
    assert "AUTHMATRIX_ALICE_TOKEN" not in response.text
    assert "alice-local-token" not in response.text


def test_policy_list_excludes_symlinks_outside_policy_directory(tmp_path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()

    outside_policy = tmp_path / "outside.yaml"
    outside_policy.write_text("""\
version: 1
scope:
  authorized: true
  base_url: http://127.0.0.1:8000
  allowed_hosts:
    - 127.0.0.1
identities:
  alice:
    role: user
    auth:
      type: bearer
      token_env: AUTHMATRIX_TEST_TOKEN
operations:
  - id: read_status
    category: BFLA
    method: GET
    path: /status
    expected:
      alice: allow
""")

    try:
        (policy_dir / "external.yaml").symlink_to(outside_policy)
    except (OSError, NotImplementedError):
        return

    (policy_dir / "local.yaml").write_text(outside_policy.read_text())

    client = TestClient(create_app(policy_dir=policy_dir))
    response = client.get("/api/policies")

    assert response.status_code == 200
    assert response.json() == {"policies": ["local.yaml"]}


def test_policy_list_returns_empty_list_for_missing_directory(tmp_path):
    client = TestClient(create_app(policy_dir=tmp_path / "missing"))

    response = client.get("/api/policies")

    assert response.status_code == 200
    assert response.json() == {"policies": []}
