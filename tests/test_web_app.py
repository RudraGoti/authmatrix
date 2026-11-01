from fastapi.testclient import TestClient

from authmatrix.errors import AuthMatrixError, ConfigurationError, ScanError, ScopeError
from authmatrix.web.app import create_app


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


def test_openapi_endpoint():
    client = TestClient(create_app())

    response = client.get("/api/openapi.json")

    assert response.status_code == 200
    assert "/api/health" in response.json()["paths"]
    assert "/api/scans" in response.json()["paths"]


def test_scan_rejects_unknown_request_fields():
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        json={
            "policy_path": "policy.yaml",
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
        json={"policy_path": "policy.yaml"},
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
        json={"policy_path": "policy.yaml"},
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
        json={"policy_path": "policy.yaml"},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "scan_error"
    assert "Sensitive internal detail" not in response.text


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
        json={"policy_path": "policy.yaml"},
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
        json={"policy_path": "policy.yaml"},
    )

    assert response.status_code == 200
    assert response.json()["schema_version"] == 1
    assert response.json()["summary"]["requests"] == 2
    assert response.json()["target"] == expected_result["target"]


def test_scan_returns_sanitized_unexpected_error(tmp_path, monkeypatch):
    from authmatrix.web import app as app_module

    def raise_unexpected_error(*args, **kwargs):
        raise RuntimeError("Sensitive internal detail")

    monkeypatch.setattr(
        app_module,
        "run_policy_scan",
        raise_unexpected_error,
    )

    client = TestClient(
        create_app(policy_dir=tmp_path),
        raise_server_exceptions=False,
    )
    response = client.post(
        "/api/scans",
        json={"policy_path": "policy.yaml"},
    )

    assert response.status_code == 500
    assert response.json()["error"] == "internal_server_error"
    assert response.json()["detail"] == "An unexpected server error occurred."
    assert "Sensitive internal detail" not in response.text


def test_scan_rejects_malformed_json():
    client = TestClient(create_app())

    response = client.post(
        "/api/scans",
        content='{"policy_path":',
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["error"] == "validation_error"
