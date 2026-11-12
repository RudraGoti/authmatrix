from pathlib import Path

import pytest

from authmatrix.errors import ScopeError
from authmatrix.execution_scope import InventoryExecutionPolicy
from authmatrix.web.services import run_inventory_policy_scan
from authmatrix.web.storage import ScanStore

EXAMPLES = Path(__file__).parents[1] / "examples"


def _policy():
    return InventoryExecutionPolicy(
        enabled=True,
        scheme="https",
        port=443,
        allowed_ports=frozenset({443}),
        allow_http=False,
        allow_public_egress=True,
        allowed_restricted_classes=frozenset(),
    )


def _store(path, *, status="authorized"):
    store = ScanStore(path)
    store.create_asset(
        {
            "asset_id": "target",
            "name": "Target",
            "asset_type": "hostname",
            "canonical_value": "api.example.com",
            "description": "",
            "tags": [],
            "organization": "Local workspace",
            "authorization_status": status,
            "authorization_confirmed": status == "authorized",
            "authorization_reference": "AUTH-1" if status == "authorized" else None,
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "created_at": "2026-11-12T00:00:00+00:00",
            "updated_at": "2026-11-12T00:00:00+00:00",
        }
    )
    store.set_scope_entry("target", "include", "2026-11-12T00:00:00+00:00")
    return store


def test_inventory_service_uses_database_hostname_and_gated_transport(
    monkeypatch, tmp_path
):
    from authmatrix.web import services

    calls = []

    def fake_run(config, transport):
        calls.append((config, transport))
        return {
            "summary": {"skipped": 0},
            "limitations": [],
        }

    monkeypatch.setattr(services, "run_inventory_authorization_tests", fake_run)
    store = _store(tmp_path / "scans.sqlite3")

    result = run_inventory_policy_scan(
        "policy.yaml",
        EXAMPLES,
        store,
        "target",
        _policy(),
        resolver=object(),
    )

    config, transport = calls[0]
    assert config.base_url == "https://api.example.com:443"
    assert transport._asset_id == "target"
    assert transport._canonical_value == "api.example.com"
    assert len(result["limitations"]) == 1


def test_inventory_service_rejects_unconfirmed_asset_before_scan(tmp_path):
    store = _store(tmp_path / "scans.sqlite3", status="pending")
    with pytest.raises(ScopeError):
        run_inventory_policy_scan(
            "policy.yaml",
            EXAMPLES,
            store,
            "target",
            _policy(),
            resolver=object(),
        )


def test_inventory_service_requires_server_side_enablement(tmp_path):
    store = _store(tmp_path / "scans.sqlite3")
    policy = InventoryExecutionPolicy(
        enabled=False,
        scheme="https",
        port=443,
        allowed_ports=frozenset({443}),
        allow_http=False,
        allow_public_egress=False,
        allowed_restricted_classes=frozenset(),
    )
    with pytest.raises(ScopeError, match="disabled"):
        run_inventory_policy_scan(
            "policy.yaml",
            EXAMPLES,
            store,
            "target",
            policy,
        )
