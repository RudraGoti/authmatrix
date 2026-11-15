from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi.testclient import TestClient

from authmatrix.web.app import create_app


@pytest.fixture(autouse=True)
def isolate_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTHMATRIX_DATA_DIR", str(tmp_path))


def enable_web_posture(monkeypatch):
    monkeypatch.setenv("AUTHMATRIX_INVENTORY_EXECUTION_ENABLED", "true")
    monkeypatch.setenv("AUTHMATRIX_WEB_POSTURE_ENABLED", "true")
    return TestClient(create_app())


def create_authorized_asset(client):
    response = client.post(
        "/api/assets",
        json={
            "name": "Authorized posture target",
            "asset_type": "hostname",
            "value": "posture.example.com",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-POSTURE-01",
        },
    )
    assert response.status_code == 201
    return response.json()["asset_id"]


def test_web_posture_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AUTHMATRIX_INVENTORY_EXECUTION_ENABLED", raising=False)
    monkeypatch.delenv("AUTHMATRIX_WEB_POSTURE_ENABLED", raising=False)

    response = TestClient(create_app()).post(
        "/api/posture",
        json={"asset_id": "asset-id", "authorization_confirmed": True},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "inventory_execution_disabled"


def test_web_posture_requires_both_server_policies(monkeypatch):
    monkeypatch.setenv("AUTHMATRIX_INVENTORY_EXECUTION_ENABLED", "true")
    monkeypatch.delenv("AUTHMATRIX_WEB_POSTURE_ENABLED", raising=False)

    response = TestClient(create_app()).post(
        "/api/posture",
        json={"asset_id": "asset-id", "authorization_confirmed": True},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "web_posture_disabled"


def test_web_posture_requires_explicit_authorization(monkeypatch):
    client = enable_web_posture(monkeypatch)

    response = client.post(
        "/api/posture",
        json={"asset_id": "asset-id"},
    )

    assert response.status_code == 403
    assert response.json()["error"] == "authorization_required"


def test_web_posture_endpoint_uses_server_policies_and_asset_selector(
    monkeypatch,
):
    from authmatrix.web import app as app_module

    client = enable_web_posture(monkeypatch)
    asset_id = create_authorized_asset(client)
    calls = []

    expected_result = {
        "schema_version": 1,
        "asset_id": asset_id,
        "method": "HEAD",
        "path": "/",
        "outcome": "completed",
        "observations": [],
    }

    def fake_assessment(*args, **kwargs):
        calls.append((args, kwargs))
        return expected_result

    monkeypatch.setattr(
        app_module,
        "run_web_posture_assessment",
        fake_assessment,
    )

    response = client.post(
        "/api/posture",
        json={
            "asset_id": asset_id,
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 200
    assert response.json() == expected_result
    assert len(calls) == 1

    args, kwargs = calls[0]
    assert args[0] is client.app.state.scan_store
    assert args[1] == asset_id
    assert args[2] is client.app.state.inventory_execution_policy
    assert args[2].enabled is True
    assert args[3] is client.app.state.web_posture_policy
    assert args[3].enabled is True
    assert kwargs == {"authorization_confirmed": True}
    assert not client.app.state.scan_lock.locked()


def test_web_posture_rejects_browser_transport_overrides(monkeypatch):
    client = enable_web_posture(monkeypatch)

    response = client.post(
        "/api/posture",
        json={
            "asset_id": "asset-id",
            "authorization_confirmed": True,
            "url": "https://attacker.example/",
            "scheme": "http",
            "port": 80,
            "path": "/admin",
            "headers": {"Host": "attacker.example"},
            "resolver": "attacker-controlled",
        },
    )

    assert response.status_code == 422


def test_web_posture_capability_requires_both_policies(monkeypatch):
    monkeypatch.setenv("AUTHMATRIX_INVENTORY_EXECUTION_ENABLED", "true")
    monkeypatch.delenv("AUTHMATRIX_WEB_POSTURE_ENABLED", raising=False)

    client = TestClient(create_app())
    capabilities = client.get("/api/status").json()["capabilities"]

    assert "inventory_scoped_gui_execution" in capabilities
    assert "web_posture_assessment" not in capabilities

    monkeypatch.setenv("AUTHMATRIX_WEB_POSTURE_ENABLED", "true")
    enabled_client = TestClient(create_app())

    enabled_capabilities = enabled_client.get("/api/status").json()["capabilities"]
    assert "web_posture_assessment" in enabled_capabilities


def test_web_posture_route_is_documented_in_openapi():
    document = create_app().openapi()

    assert "post" in document["paths"]["/api/posture"]
    schema = document["components"]["schemas"]["WebPostureRequest"]
    assert set(schema["properties"]) == {
        "asset_id",
        "authorization_confirmed",
    }


def test_web_posture_lock_rejects_concurrent_assessment_and_releases(
    monkeypatch,
):
    from authmatrix.web import app as app_module

    client = enable_web_posture(monkeypatch)
    asset_id = create_authorized_asset(client)
    assessment_started = Event()
    allow_assessment_to_finish = Event()

    expected_result = {
        "schema_version": 1,
        "asset_id": asset_id,
        "method": "HEAD",
        "path": "/",
        "outcome": "completed",
        "observations": [],
    }

    def blocked_assessment(*args, **kwargs):
        assessment_started.set()
        if not allow_assessment_to_finish.wait(timeout=5):
            raise TimeoutError("Test did not release the blocked assessment.")
        return expected_result

    monkeypatch.setattr(
        app_module,
        "run_web_posture_assessment",
        blocked_assessment,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_assessment = executor.submit(
            client.post,
            "/api/posture",
            json={
                "asset_id": asset_id,
                "authorization_confirmed": True,
            },
        )
        try:
            assert assessment_started.wait(timeout=5)
            concurrent_response = client.post(
                "/api/posture",
                json={
                    "asset_id": asset_id,
                    "authorization_confirmed": True,
                },
            )
        finally:
            allow_assessment_to_finish.set()

        first_response = first_assessment.result(timeout=5)

    assert concurrent_response.status_code == 409
    assert concurrent_response.json()["error"] == "scan_in_progress"
    assert first_response.status_code == 200
    assert not client.app.state.scan_lock.locked()


def test_web_posture_lock_releases_after_unexpected_exception(monkeypatch):
    from authmatrix.web import app as app_module

    client = enable_web_posture(monkeypatch)
    asset_id = create_authorized_asset(client)

    def raise_unexpected_error(*args, **kwargs):
        raise RuntimeError("Sensitive posture implementation detail")

    monkeypatch.setattr(
        app_module,
        "run_web_posture_assessment",
        raise_unexpected_error,
    )

    response = TestClient(
        client.app,
        raise_server_exceptions=False,
    ).post(
        "/api/posture",
        json={
            "asset_id": asset_id,
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 500
    assert response.json()["error"] == "internal_server_error"
    assert "Sensitive posture implementation detail" not in response.text
    assert not client.app.state.scan_lock.locked()


def test_web_posture_returns_sanitized_scope_error_and_releases_lock(
    monkeypatch,
):
    from authmatrix.errors import ScopeError
    from authmatrix.web import app as app_module

    client = enable_web_posture(monkeypatch)
    asset_id = create_authorized_asset(client)

    def raise_scope_error(*args, **kwargs):
        raise ScopeError("Sensitive authorization or target details")

    monkeypatch.setattr(
        app_module,
        "run_web_posture_assessment",
        raise_scope_error,
    )

    response = client.post(
        "/api/posture",
        json={
            "asset_id": asset_id,
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 403
    assert response.json()["error"] == "scope_error"
    assert "Sensitive authorization or target details" not in response.text
    assert not client.app.state.scan_lock.locked()
