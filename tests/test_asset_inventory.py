from fastapi.testclient import TestClient

from authmatrix.web.app import create_app
from authmatrix.web.asset_inventory import (
    authorization_eligibility,
    authorization_state,
    canonicalize_asset_value,
    evaluate_target,
)


def _create_asset(client, name, asset_type, value, **extra):
    return client.post(
        "/api/assets",
        json={
            "name": name,
            "asset_type": asset_type,
            "value": value,
            **extra,
        },
    )


def _authorized_asset(asset_id, asset_type, value, **overrides):
    return {
        "asset_id": asset_id,
        "name": asset_id,
        "asset_type": asset_type,
        "canonical_value": value,
        "authorization_status": "authorized",
        "authorization_confirmed": True,
        "authorization_reference": f"AUTH-{asset_id}",
        "authorization_starts_at": None,
        "authorization_expires_at": None,
        "active": True,
        **overrides,
    }


def test_asset_value_canonicalization():
    cases = [
        ("domain", "EXAMPLE.COM", "example.com"),
        ("subdomain", "Api.Example.com.", "api.example.com"),
        ("hostname", "bücher.example", "xn--bcher-kva.example"),
        ("ipv4", "192.0.2.10", "192.0.2.10"),
        ("ipv6", "2001:0db8::10", "2001:db8::10"),
        ("ipv4_cidr", "192.0.2.0/24", "192.0.2.0/24"),
        ("ipv6_cidr", "2001:db8::/64", "2001:db8::/64"),
    ]
    for asset_type, value, expected in cases:
        assert canonicalize_asset_value(asset_type, value) == expected


def test_asset_value_rejects_malformed_and_ambiguous_values():
    cases = [
        ("domain", ""),
        ("domain", "example"),
        ("domain", "bad..example.com"),
        ("domain", "https://example.com"),
        ("domain", "user@example.com"),
        ("domain", "example.com/path"),
        ("ipv4", "192.0.2"),
        ("ipv4", "192.0.2.1/24"),
        ("ipv6", "192.0.2.1"),
        ("ipv6", "fe80::1%eth0"),
        ("ipv6", "::ffff:192.0.2.1"),
        ("ipv4_cidr", "192.0.2.1/24"),
        ("ipv4_cidr", "192.0.2.0/33"),
        ("ipv6_cidr", "192.0.2.0/24"),
        ("ipv6_cidr", "::ffff:192.0.2.0/120"),
        ("hostname", "a" * 254),
        ("ipv6", "2001:db8::1 "),
    ]
    for asset_type, value in cases:
        try:
            canonicalize_asset_value(asset_type, value)
        except ValueError:
            continue
        raise AssertionError(f"Accepted invalid asset {asset_type}: {value!r}")


def test_authorization_date_and_active_state_controls_eligibility():
    base = {
        "authorization_status": "authorized",
        "authorization_confirmed": True,
        "authorization_reference": "AUTH-1",
        "authorization_expires_at": None,
        "authorization_starts_at": "2999-01-01",
        "active": True,
    }
    assert authorization_state(base) == "authorized"
    assert authorization_eligibility(base) == (False, "not_started")
    base["authorization_starts_at"] = None
    base["authorization_expires_at"] = "2000-01-01"
    assert authorization_state(base) == "expired"
    base["authorization_expires_at"] = None
    base["active"] = False
    assert authorization_eligibility(base) == (False, "inactive")


def test_scope_parent_child_exclusions_and_network_overlap():
    assets = [
        {
            "asset_id": "parent",
            "name": "parent",
            "asset_type": "domain",
            "canonical_value": "example.com",
            "authorization_status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-PARENT",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "active": True,
        },
        {
            "asset_id": "child-exclusion",
            "name": "staging",
            "asset_type": "hostname",
            "canonical_value": "staging.example.com",
            "authorization_status": "pending",
            "authorization_confirmed": False,
            "authorization_reference": None,
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "active": True,
        },
    ]
    entries = [
        {"asset_id": "parent", "direction": "include"},
        {"asset_id": "child-exclusion", "direction": "exclude"},
    ]
    assert evaluate_target(assets, entries, "hostname", "api.example.com")[
        "eligible"
    ]
    assert not evaluate_target(assets, entries, "hostname", "staging.example.com")[
        "eligible"
    ]
    assert evaluate_target(assets, entries, "domain", "example.com")["reason"] == (
        "explicitly_excluded"
    )

    network = {
        "asset_id": "network",
        "name": "network",
        "asset_type": "ipv4_cidr",
        "canonical_value": "192.0.2.0/24",
        "authorization_status": "authorized",
        "authorization_starts_at": None,
        "authorization_expires_at": None,
        "active": True,
    }
    host_exclusion = {
        "asset_id": "host",
        "name": "host",
        "asset_type": "ipv4",
        "canonical_value": "192.0.2.15",
        "authorization_status": "pending",
        "authorization_starts_at": None,
        "authorization_expires_at": None,
        "active": True,
    }
    result = evaluate_target(
        [network, host_exclusion],
        [
            {"asset_id": "network", "direction": "include"},
            {"asset_id": "host", "direction": "exclude"},
        ],
        "ipv4",
        "192.0.2.15",
    )
    assert result["reason"] == "explicitly_excluded"
    broad_target = evaluate_target(
        [network, host_exclusion],
        [
            {"asset_id": "network", "direction": "include"},
            {"asset_id": "host", "direction": "exclude"},
        ],
        "ipv4_cidr",
        "192.0.2.0/25",
    )
    assert broad_target["reason"] == "explicitly_excluded"


def test_hostname_inclusion_is_exact_and_domain_matching_uses_label_boundaries():
    assets = [
        _authorized_asset("hostname", "hostname", "api.example.com"),
        _authorized_asset("domain", "domain", "example.com"),
    ]
    entries = [
        {"asset_id": "hostname", "direction": "include"},
        {"asset_id": "domain", "direction": "include"},
    ]

    exact_hostname = evaluate_target(
        assets,
        entries[:1],
        "hostname",
        "API.EXAMPLE.COM.",
    )
    descendant_hostname = evaluate_target(
        assets,
        entries[:1],
        "hostname",
        "admin.api.example.com",
    )
    similar_prefix_hostname = evaluate_target(
        assets,
        entries[:1],
        "hostname",
        "evilapi.example.com",
    )
    assert exact_hostname["eligible"] is True
    assert descendant_hostname["eligible"] is False
    assert similar_prefix_hostname["eligible"] is False

    assert evaluate_target(
        assets,
        entries[1:],
        "hostname",
        "example.com",
    )["eligible"]
    assert evaluate_target(
        assets,
        entries[1:],
        "hostname",
        "api.example.com",
    )["eligible"]
    assert not evaluate_target(
        assets,
        entries[1:],
        "hostname",
        "notexample.com",
    )["eligible"]
    assert not evaluate_target(
        assets,
        entries[1:],
        "hostname",
        "example.com.attacker.test",
    )["eligible"]


def test_subdomain_inclusion_covers_only_its_label_bounded_subtree():
    assets = [_authorized_asset("subdomain", "subdomain", "team.example.com")]
    entries = [{"asset_id": "subdomain", "direction": "include"}]

    assert evaluate_target(
        assets,
        entries,
        "hostname",
        "team.example.com",
    )["eligible"]
    assert evaluate_target(
        assets,
        entries,
        "hostname",
        "dev.team.example.com",
    )["eligible"]
    assert not evaluate_target(
        assets,
        entries,
        "hostname",
        "evilteam.example.com",
    )["eligible"]
    assert not evaluate_target(
        assets,
        entries,
        "hostname",
        "team.example.com.attacker.test",
    )["eligible"]


def test_dns_exclusions_override_matching_inclusions_and_parent_targets():
    assets = [
        _authorized_asset("domain", "domain", "example.com"),
        _authorized_asset("excluded-host", "hostname", "api.example.com"),
    ]
    entries = [
        {"asset_id": "domain", "direction": "include"},
        {"asset_id": "excluded-host", "direction": "exclude"},
    ]

    assert evaluate_target(
        assets,
        entries,
        "hostname",
        "api.example.com",
    )["reason"] == "explicitly_excluded"
    assert evaluate_target(
        assets,
        entries,
        "domain",
        "example.com",
    )["reason"] == "explicitly_excluded"
    assert evaluate_target(
        assets,
        entries,
        "hostname",
        "other.example.com",
    )["eligible"]


def test_ineligible_assets_never_match_hierarchical_domain_scope():
    assets = [
        _authorized_asset("pending", "domain", "pending.example.com",
                          authorization_status="pending"),
        _authorized_asset("revoked", "domain", "revoked.example.com",
                          authorization_status="revoked"),
        _authorized_asset("expired", "domain", "expired.example.com",
                          authorization_expires_at="2000-01-01"),
        _authorized_asset("inactive", "domain", "inactive.example.com",
                          active=False),
        _authorized_asset("unverified", "domain", "unverified.example.com",
                          authorization_confirmed=False),
    ]
    entries = [
        {"asset_id": asset["asset_id"], "direction": "include"} for asset in assets
    ]

    for asset in assets:
        result = evaluate_target(
            assets,
            entries,
            "hostname",
            f"api.{asset['canonical_value']}",
        )
        assert result["eligible"] is False
        assert result["reason"] == "authorization_ineligible"


def test_scope_uses_literal_hosts_and_ipv6_network_containment():
    assets = [
        {
            "asset_id": "ipv6-network",
            "name": "IPv6 network",
            "asset_type": "ipv6_cidr",
            "canonical_value": "2001:db8::/64",
            "authorization_status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-IPv6",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "active": True,
        },
        {
            "asset_id": "domain",
            "name": "Domain",
            "asset_type": "domain",
            "canonical_value": "example.com",
            "authorization_status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-DNS",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "active": True,
        },
    ]
    entries = [
        {"asset_id": "ipv6-network", "direction": "include"},
        {"asset_id": "domain", "direction": "include"},
    ]
    assert evaluate_target(assets, entries, "ipv6", "2001:db8::123")["eligible"]
    assert not evaluate_target(assets, entries, "ipv6_cidr", "2001:db8:1::/64")[
        "eligible"
    ]
    assert not evaluate_target(assets, entries, "ipv4", "192.0.2.1")["eligible"]


def test_scope_api_requires_authorization_and_exclusions_override_parent(tmp_path):
    client = TestClient(create_app(data_dir=tmp_path))
    parent = _create_asset(
        client,
        "Production",
        "domain",
        "example.com",
        authorization_confirmed=True,
        authorization_reference="APPROVAL-123",
    )
    child = _create_asset(client, "Staging", "hostname", "staging.example.com")
    assert parent.status_code == child.status_code == 201
    assert parent.json()["authorization_status"] == "authorized"
    assert child.json()["authorization_status"] == "pending"

    client.post(
        "/api/scope",
        json={"asset_id": parent.json()["asset_id"], "direction": "include"},
    )
    client.post(
        "/api/scope",
        json={"asset_id": child.json()["asset_id"], "direction": "exclude"},
    )

    allowed = client.post(
        "/api/scope/validate",
        json={"asset_type": "hostname", "value": "api.example.com"},
    )
    excluded = client.post(
        "/api/scope/validate",
        json={"asset_type": "hostname", "value": "staging.example.com"},
    )
    parent_target = client.post(
        "/api/scope/validate",
        json={"asset_type": "domain", "value": "example.com"},
    )
    assert allowed.json()["eligible"] is True
    assert excluded.json()["reason"] == "explicitly_excluded"
    assert parent_target.json()["eligible"] is False


def test_asset_api_crud_authorization_and_validation(tmp_path):
    client = TestClient(create_app(data_dir=tmp_path))
    pending = _create_asset(client, "Test", "ipv6", "2001:db8::1")
    assert pending.status_code == 201
    asset_id = pending.json()["asset_id"]
    assert pending.json()["effective_scope_eligible"] is False

    invalid_authorization = client.put(
        f"/api/assets/{asset_id}/authorization",
        json={
            "status": "authorized",
            "authorization_confirmed": False,
            "authorization_reference": "TICKET-1",
        },
    )
    assert invalid_authorization.status_code == 422

    authorized = client.put(
        f"/api/assets/{asset_id}/authorization",
        json={
            "status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "TICKET-1",
            "authorization_expires_at": "2999-01-01",
        },
    )
    assert authorized.status_code == 200
    assert authorized.json()["effective_scope_eligible"] is True

    duplicate = _create_asset(client, "Duplicate", "ipv6", "2001:db8::1")
    assert duplicate.status_code == 409
    assert duplicate.json()["error"] == "asset_conflict"
    metadata_update = client.put(
        f"/api/assets/{asset_id}",
        json={
            "name": "Updated",
            "asset_type": "ipv6",
            "value": "2001:0db8::1",
            "tags": ["prod"],
        },
    )
    assert metadata_update.status_code == 200
    assert metadata_update.json()["canonical_value"] == "2001:db8::1"
    assert metadata_update.json()["authorization_status"] == "authorized"
    assert metadata_update.json()["tags"] == ["prod"]

    client.post("/api/scope", json={"asset_id": asset_id, "direction": "include"})
    assert client.get("/api/scope").json()["eligible_count"] == 1
    changed_target = client.put(
        f"/api/assets/{asset_id}",
        json={
            "name": "Updated",
            "asset_type": "ipv6",
            "value": "2001:db8::2",
            "tags": ["prod"],
        },
    )
    assert changed_target.status_code == 200
    assert changed_target.json()["authorization_status"] == "pending"
    assert changed_target.json()["authorization_confirmed"] is False
    assert changed_target.json()["authorization_reference"] is None
    assert changed_target.json()["authorization_expires_at"] is None
    assert changed_target.json()["effective_scope_eligible"] is False
    target_check = client.post(
        "/api/scope/validate",
        json={"asset_type": "ipv6", "value": "2001:db8::2"},
    )
    assert target_check.json()["eligible"] is False
    assert target_check.json()["reason"] == "authorization_ineligible"

    reauthorized = client.put(
        f"/api/assets/{asset_id}/authorization",
        json={
            "status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "NEW-TICKET",
        },
    )
    assert reauthorized.json()["effective_scope_eligible"] is True
    assert client.get("/api/scope").json()["eligible_count"] == 1

    deactivated = client.patch(
        f"/api/assets/{asset_id}/active",
        json={"active": False},
    )
    assert deactivated.json()["effective_scope_eligible"] is False
    revoked = client.post(f"/api/assets/{asset_id}/revoke")
    assert revoked.json()["authorization_status"] == "revoked"
    assert revoked.json()["effective_scope_eligible"] is False
    assert client.delete(f"/api/assets/{asset_id}").status_code == 204
    missing = client.get(f"/api/assets/{asset_id}")
    assert missing.status_code == 404
    assert missing.json()["error"] == "asset_not_found"
    assert client.get("/api/scope").json()["included"] == []


def test_changing_asset_type_invalidates_authorization_even_when_value_is_same(
    tmp_path,
):
    client = TestClient(create_app(data_dir=tmp_path))
    created = _create_asset(
        client,
        "Application",
        "hostname",
        "app.example.com",
        authorization_confirmed=True,
        authorization_reference="HOST-APPROVAL",
    )
    asset_id = created.json()["asset_id"]

    updated = client.put(
        f"/api/assets/{asset_id}",
        json={
            "name": "Application",
            "asset_type": "domain",
            "value": "app.example.com",
        },
    )

    assert updated.status_code == 200
    assert updated.json()["authorization_status"] == "pending"
    assert updated.json()["authorization_confirmed"] is False
    assert updated.json()["authorization_reference"] is None


def test_asset_api_rejects_urls_dates_and_unknown_fields(tmp_path):
    client = TestClient(create_app(data_dir=tmp_path))
    malformed = _create_asset(client, "URL", "domain", "https://example.com")
    assert malformed.status_code == 422
    invalid_dates = _create_asset(
        client,
        "Dates",
        "domain",
        "dates.example.com",
        authorization_starts_at="2030-01-01",
        authorization_expires_at="2029-01-01",
    )
    assert invalid_dates.status_code == 422
    unknown = _create_asset(
        client,
        "Unknown",
        "domain",
        "unknown.example.com",
        authorization_status="authorized",
    )
    assert unknown.status_code == 422


def test_authorized_assets_require_reference_confirmation_and_current_dates(tmp_path):
    client = TestClient(create_app(data_dir=tmp_path))
    missing_reference = _create_asset(
        client,
        "Missing reference",
        "domain",
        "missing.example.com",
        authorization_confirmed=True,
    )
    assert missing_reference.status_code == 422

    expired = _create_asset(
        client,
        "Expired",
        "domain",
        "expired.example.com",
        authorization_confirmed=True,
        authorization_reference="OLD-APPROVAL",
        authorization_expires_at="2000-01-01",
    )
    assert expired.status_code == 201
    assert expired.json()["authorization_status"] == "expired"
    assert expired.json()["effective_scope_eligible"] is False


def test_api_filters_and_scope_entries_survive_store_reopen(tmp_path):
    from authmatrix.web.storage import ScanStore

    store = ScanStore(tmp_path / "authmatrix-scans.sqlite3")
    now = "2026-11-12T10:00:00+00:00"
    asset = {
        "asset_id": "persistent-asset",
        "name": "Persisted domain",
        "asset_type": "domain",
        "canonical_value": "persistent.example",
        "description": "",
        "tags": ["prod"],
        "organization": "Local workspace",
        "authorization_status": "authorized",
        "authorization_confirmed": True,
        "authorization_reference": "AUTH-42",
        "authorization_starts_at": None,
        "authorization_expires_at": None,
        "created_at": now,
        "updated_at": now,
    }
    store.create_asset(asset)
    assert store.set_scope_entry(asset["asset_id"], "include", now)

    reopened = ScanStore(tmp_path / "authmatrix-scans.sqlite3")
    assert reopened.get_asset(asset["asset_id"])["authorization_reference"] == "AUTH-42"
    assert reopened.list_scope_entries() == [
        {
            "asset_id": asset["asset_id"],
            "direction": "include",
            "created_at": now,
        }
    ]
    assert reopened.delete_asset(asset["asset_id"])
    assert reopened.list_scope_entries() == []
