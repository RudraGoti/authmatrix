import sqlite3

import pytest

from authmatrix.web.storage import ScanStore


def test_database_file_is_private_and_symlinks_are_rejected(tmp_path):
    database = tmp_path / "scans.sqlite3"
    ScanStore(database)

    assert database.stat().st_mode & 0o777 == 0o600
    database.chmod(0o640)

    linked_database = tmp_path / "linked.sqlite3"
    try:
        linked_database.symlink_to(database)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not supported.")

    with pytest.raises(ValueError, match="must not be a symlink"):
        ScanStore(linked_database)
    assert database.stat().st_mode & 0o777 == 0o640


def test_existing_data_directory_is_restricted_without_removing_files(tmp_path):
    database = tmp_path / "scans.sqlite3"
    marker = tmp_path / "keep.txt"
    marker.write_text("existing data")
    database_store = ScanStore(database)
    database_store.start("preserve-me", "2026-11-04T10:00:00+00:00", "policy.yaml")
    database_store.fail("preserve-me")
    database.chmod(0o666)
    tmp_path.chmod(0o777)

    reopened_store = ScanStore(database)

    assert tmp_path.stat().st_mode & 0o777 == 0o700
    assert database.stat().st_mode & 0o777 == 0o600
    assert marker.read_text() == "existing data"
    assert reopened_store.get_scan("preserve-me")["status"] == "failed"


def test_database_symlink_directory_and_hardlinks_are_rejected(tmp_path):
    target_directory = tmp_path / "target"
    target_directory.mkdir()
    link_directory = tmp_path / "linked-directory"
    try:
        link_directory.symlink_to(target_directory, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not supported.")

    with pytest.raises(ValueError, match="real directory"):
        ScanStore(link_directory / "scans.sqlite3")

    database = target_directory / "scans.sqlite3"
    ScanStore(database)
    hardlink = target_directory / "alias.sqlite3"
    try:
        hardlink.hardlink_to(database)
    except (OSError, NotImplementedError):
        pytest.skip("Hardlink creation is not supported.")

    with pytest.raises(ValueError, match="single-link regular file"):
        ScanStore(hardlink)
    assert database.stat().st_mode & 0o777 == 0o600


def test_replaced_directory_is_rejected_without_chmodding_replacement(tmp_path):
    database = tmp_path / "data" / "scans.sqlite3"
    store = ScanStore(database)
    original_directory = tmp_path / "data"
    original_directory.rename(tmp_path / "original-data")
    replacement_directory = tmp_path / "data"
    replacement_directory.mkdir(mode=0o700)
    replacement_directory.chmod(0o777)

    with pytest.raises(ValueError, match="directory changed unexpectedly"):
        store.list_scans()

    assert replacement_directory.stat().st_mode & 0o777 == 0o777


def test_replaced_database_is_rejected_without_chmodding_replacement(tmp_path):
    database = tmp_path / "data" / "scans.sqlite3"
    store = ScanStore(database)
    database.unlink()
    database.write_text("not the existing database")
    database.chmod(0o666)

    with pytest.raises(ValueError, match="database file changed unexpectedly"):
        store.list_scans()

    assert database.stat().st_mode & 0o777 == 0o666


def test_running_scan_is_marked_failed_after_restart(tmp_path):
    database = tmp_path / "scans.sqlite3"
    first_store = ScanStore(database)
    first_store.start("interrupted-scan", "2026-11-04T10:00:00+00:00", "policy.yaml")

    restarted_store = ScanStore(database)

    assert restarted_store.get_scan("interrupted-scan") == {
        "scan_id": "interrupted-scan",
        "generated_at": "2026-11-04T10:00:00+00:00",
        "target": None,
        "policy": "policy.yaml",
        "status": "failed",
        "requests": 0,
        "findings": 0,
        "failed": 1,
    }


def _insert_authorized_asset(store, asset_id="host"):
    store.create_asset(
        {
            "asset_id": asset_id,
            "name": asset_id,
            "asset_type": "hostname",
            "canonical_value": f"{asset_id}.example.com",
            "description": "",
            "tags": [],
            "organization": "Local workspace",
            "authorization_status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-1",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "created_at": "2026-11-12T00:00:00+00:00",
            "updated_at": "2026-11-12T00:00:00+00:00",
        }
    )


def test_authorization_snapshot_reads_assets_and_scope_consistently(tmp_path):
    store = ScanStore(tmp_path / "scans.sqlite3")
    _insert_authorized_asset(store)
    store.set_scope_entry("host", "include", "2026-11-12T00:00:00+00:00")

    assets, entries = store.authorization_snapshot()

    assert [asset["canonical_value"] for asset in assets] == ["host.example.com"]
    assert entries == [
        {
            "asset_id": "host",
            "direction": "include",
            "created_at": "2026-11-12T00:00:00+00:00",
        }
    ]


def test_authorization_transaction_holds_sqlite_writer_reservation(tmp_path):
    store = ScanStore(tmp_path / "scans.sqlite3")
    _insert_authorized_asset(store)
    with store.locked_authorization_snapshot(timeout=0.1) as (assets, _entries):
        assert assets[0]["authorization_status"] == "authorized"
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            with store._connect(timeout=0.05) as connection:
                connection.execute(
                    "UPDATE assets SET authorization_status = 'revoked' "
                    "WHERE asset_id = 'host'"
                )


def test_authorization_transaction_fails_on_writer_lock_timeout(tmp_path):
    store = ScanStore(tmp_path / "scans.sqlite3")
    _insert_authorized_asset(store)
    with store._connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            with store.locked_authorization_snapshot(timeout=0.05):
                pytest.fail("The authorization transaction should not be acquired.")


def test_authorization_snapshot_rejects_malformed_stored_tags(tmp_path):
    store = ScanStore(tmp_path / "scans.sqlite3")
    _insert_authorized_asset(store)
    with store._connect() as connection:
        connection.execute("UPDATE assets SET tags_json = '{' WHERE asset_id = 'host'")
    with pytest.raises(ValueError):
        store.authorization_snapshot()
