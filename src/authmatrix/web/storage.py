"""SQLite persistence for sanitized web scan history and results."""

from __future__ import annotations

import errno
import json
import os
import sqlite3
import stat
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class ScanStore:
    """Persist bounded scan history and local asset inventory records."""

    max_scans = 1000
    max_assets = 5000

    def __init__(self, database_path: Path) -> None:
        self.path = database_path.expanduser().absolute()
        self.directory = self.path.parent
        self.name = self.path.name
        if self.name in {"", ".", ".."}:
            raise ValueError("The AuthMatrix database path must name a file.")

        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory_fd = self._open_directory()
        database_fd = None
        try:
            self._restrict_directory(directory_fd)
            database_fd = self._open_database_file(directory_fd)
            database_info = os.fstat(database_fd)
            self._database_identity = (
                database_info.st_dev,
                database_info.st_ino,
            )
            directory_info = os.fstat(directory_fd)
            self._directory_identity = (
                directory_info.st_dev,
                directory_info.st_ino,
            )
            os.fchmod(directory_fd, 0o700)
            self._database_fd_finalizer = weakref.finalize(
                self,
                os.close,
                database_fd,
            )
            database_fd = None
        finally:
            if database_fd is not None:
                os.close(database_fd)
            os.close(directory_fd)

        self._initialize()
        self.fail_interrupted()

    @staticmethod
    def _file_open_flags() -> int:
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        return flags

    def _open_directory(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.directory, flags)
        except OSError as exc:
            raise ValueError(
                "The AuthMatrix data directory must be a real directory."
            ) from exc

        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            os.close(descriptor)
            raise ValueError(
                "The AuthMatrix data directory must be owned by the current user."
            )
        return descriptor

    @staticmethod
    def _restrict_directory(directory_fd: int) -> None:
        os.fchmod(directory_fd, 0o700)

    def _open_database_file(
        self,
        directory_fd: int,
        expected_identity: tuple[int, int] | None = None,
    ) -> int:
        flags = self._file_open_flags()
        try:
            descriptor = os.open(
                self.name,
                flags,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    self.name,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                try:
                    descriptor = os.open(
                        self.name,
                        flags,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise ValueError(
                            "The AuthMatrix database path must not be a symlink."
                        ) from exc
                    raise ValueError(
                        "The AuthMatrix database file could not be opened safely."
                    ) from exc
            except OSError as exc:
                raise ValueError(
                    "The AuthMatrix database file could not be created safely."
                ) from exc
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(
                    "The AuthMatrix database path must not be a symlink."
                ) from exc
            raise ValueError(
                "The AuthMatrix database file could not be opened safely."
            ) from exc

        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            os.close(descriptor)
            raise ValueError(
                "The AuthMatrix database must be a single-link regular file "
                "owned by the current user."
            )
        if expected_identity is not None and (
            info.st_dev,
            info.st_ino,
        ) != expected_identity:
            os.close(descriptor)
            raise ValueError("The AuthMatrix database file changed unexpectedly.")
        os.fchmod(descriptor, 0o600)
        return descriptor

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        directory_fd = self._open_directory()
        database_fd = None
        connection = None
        try:
            directory_info = os.fstat(directory_fd)
            if (
                directory_info.st_dev,
                directory_info.st_ino,
            ) != self._directory_identity:
                raise ValueError("The AuthMatrix data directory changed unexpectedly.")
            self._restrict_directory(directory_fd)

            database_fd = self._open_database_file(
                directory_fd,
                expected_identity=self._database_identity,
            )
            database_info = os.fstat(database_fd)
            if (
                database_info.st_dev,
                database_info.st_ino,
            ) != self._database_identity:
                raise ValueError("The AuthMatrix database file changed unexpectedly.")

            anchored_path = Path("/proc/self/fd") / str(directory_fd) / self.name
            database_path = (
                str(anchored_path)
                if Path("/proc/self/fd").is_dir()
                else str(self.path)
            )
            connection = sqlite3.connect(database_path, timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            current_info = os.stat(
                self.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(current_info.st_mode)
                or (current_info.st_dev, current_info.st_ino)
                != self._database_identity
            ):
                raise ValueError("The AuthMatrix database file changed unexpectedly.")
            yield connection
            connection.commit()
        except Exception:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()
            if database_fd is not None:
                os.close(database_fd)
            os.close(directory_fd)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    generated_at TEXT NOT NULL,
                    target TEXT,
                    policy TEXT,
                    status TEXT NOT NULL CHECK (
                        status IN ('running', 'completed', 'failed')
                    ),
                    requests INTEGER NOT NULL DEFAULT 0,
                    findings INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    result_json TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scans_generated_at "
                "ON scans(generated_at DESC)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
                    asset_type TEXT NOT NULL CHECK (asset_type IN (
                        'domain', 'subdomain', 'hostname', 'ipv4', 'ipv6',
                        'ipv4_cidr', 'ipv6_cidr'
                    )),
                    canonical_value TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    organization TEXT NOT NULL DEFAULT 'Local workspace',
                    authorization_status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (authorization_status IN (
                            'pending', 'authorized', 'unverified', 'revoked'
                        )),
                    authorization_confirmed INTEGER NOT NULL DEFAULT 0
                        CHECK (authorization_confirmed IN (0, 1)),
                    authorization_reference TEXT,
                    authorization_starts_at TEXT,
                    authorization_expires_at TEXT,
                    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK (authorization_status != 'authorized' OR (
                        authorization_confirmed = 1
                        AND authorization_reference IS NOT NULL
                        AND length(trim(authorization_reference)) > 0
                    ))
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS assets_type ON assets(asset_type)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS assets_authorization "
                "ON assets(authorization_status, active)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scope_entries (
                    asset_id TEXT PRIMARY KEY REFERENCES assets(asset_id)
                        ON DELETE CASCADE,
                    direction TEXT NOT NULL CHECK (direction IN ('include', 'exclude')),
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scope_direction ON scope_entries(direction)"
            )

    @staticmethod
    def _asset_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        asset = dict(row)
        asset["tags"] = json.loads(asset.pop("tags_json"))
        asset["authorization_confirmed"] = bool(asset["authorization_confirmed"])
        asset["active"] = bool(asset["active"])
        return asset

    def create_asset(self, asset: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            if count >= self.max_assets:
                raise ValueError("The asset inventory has reached its size limit.")
            connection.execute(
                """
                INSERT INTO assets (
                    asset_id, name, asset_type, canonical_value, description,
                    tags_json, organization, authorization_status,
                    authorization_confirmed, authorization_reference,
                    authorization_starts_at, authorization_expires_at,
                    active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    asset["asset_id"],
                    asset["name"],
                    asset["asset_type"],
                    asset["canonical_value"],
                    asset["description"],
                    json.dumps(asset["tags"], ensure_ascii=False),
                    asset["organization"],
                    asset["authorization_status"],
                    int(asset["authorization_confirmed"]),
                    asset["authorization_reference"],
                    asset["authorization_starts_at"],
                    asset["authorization_expires_at"],
                    asset["created_at"],
                    asset["updated_at"],
                ),
            )

    def list_assets(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM assets ORDER BY name COLLATE NOCASE, asset_id "
                "LIMIT ?",
                (self.max_assets,),
            ).fetchall()
        return [self._asset_from_row(row) for row in rows]

    def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)
            ).fetchone()
        return self._asset_from_row(row)

    def update_asset(self, asset_id: str, asset: dict[str, Any]) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE assets SET name = ?, asset_type = ?, canonical_value = ?,
                    description = ?, tags_json = ?, organization = ?, updated_at = ?,
                    authorization_status = CASE
                        WHEN asset_type != ? OR canonical_value != ?
                        THEN 'pending' ELSE authorization_status END,
                    authorization_confirmed = CASE
                        WHEN asset_type != ? OR canonical_value != ?
                        THEN 0 ELSE authorization_confirmed END,
                    authorization_reference = CASE
                        WHEN asset_type != ? OR canonical_value != ?
                        THEN NULL ELSE authorization_reference END,
                    authorization_starts_at = CASE
                        WHEN asset_type != ? OR canonical_value != ?
                        THEN NULL ELSE authorization_starts_at END,
                    authorization_expires_at = CASE
                        WHEN asset_type != ? OR canonical_value != ?
                        THEN NULL ELSE authorization_expires_at END
                WHERE asset_id = ?
                """,
                (
                    asset["name"],
                    asset["asset_type"],
                    asset["canonical_value"],
                    asset["description"],
                    json.dumps(asset["tags"], ensure_ascii=False),
                    asset["organization"],
                    asset["updated_at"],
                    asset["asset_type"],
                    asset["canonical_value"],
                    asset["asset_type"],
                    asset["canonical_value"],
                    asset["asset_type"],
                    asset["canonical_value"],
                    asset["asset_type"],
                    asset["canonical_value"],
                    asset["asset_type"],
                    asset["canonical_value"],
                    asset_id,
                ),
            )
            return cursor.rowcount == 1

    def update_authorization(
        self,
        asset_id: str,
        authorization: dict[str, Any],
    ) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE assets SET authorization_status = ?,
                    authorization_confirmed = ?, authorization_reference = ?,
                    authorization_starts_at = ?, authorization_expires_at = ?,
                    updated_at = ?
                WHERE asset_id = ?
                """,
                (
                    authorization["authorization_status"],
                    int(authorization["authorization_confirmed"]),
                    authorization["authorization_reference"],
                    authorization["authorization_starts_at"],
                    authorization["authorization_expires_at"],
                    authorization["updated_at"],
                    asset_id,
                ),
            )
            return cursor.rowcount == 1

    def set_asset_active(self, asset_id: str, active: bool, updated_at: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE assets SET active = ?, updated_at = ? WHERE asset_id = ?",
                (int(active), updated_at, asset_id),
            )
            return cursor.rowcount == 1

    def delete_asset(self, asset_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM assets WHERE asset_id = ?", (asset_id,)
            )
            return cursor.rowcount == 1

    def set_scope_entry(
        self,
        asset_id: str,
        direction: str,
        created_at: str,
    ) -> bool:
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM assets WHERE asset_id = ?", (asset_id,)
            ).fetchone() is None:
                return False
            connection.execute(
                """
                INSERT INTO scope_entries (asset_id, direction, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    direction = excluded.direction, created_at = excluded.created_at
                """,
                (asset_id, direction, created_at),
            )
        return True

    def remove_scope_entry(self, asset_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM scope_entries WHERE asset_id = ?", (asset_id,)
            )
            return cursor.rowcount == 1

    def list_scope_entries(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT asset_id, direction, created_at FROM scope_entries "
                "ORDER BY direction, created_at, asset_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def start(
        self,
        scan_id: str,
        generated_at: str,
        policy: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scans (
                    scan_id, generated_at, policy, status
                ) VALUES (?, ?, ?, 'running')
                """,
                (scan_id, generated_at, policy),
            )
            self._prune(connection)

    def complete(self, scan_id: str, result: dict[str, Any]) -> None:
        result_json = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE scans
                SET generated_at = ?, target = ?, policy = ?, status = 'completed',
                    requests = ?, findings = ?, failed = ?, result_json = ?
                WHERE scan_id = ? AND status = 'running'
                """,
                (
                    result["generated_at"],
                    result["target"],
                    result.get("policy"),
                    result["summary"]["requests"],
                    result["summary"]["findings"],
                    result["summary"]["failed"],
                    result_json,
                    scan_id,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("The running scan record is unavailable.")
            self._prune(connection)

    def fail(self, scan_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE scans SET status = 'failed', failed = 1 "
                "WHERE scan_id = ? AND status = 'running'",
                (scan_id,),
            )
            self._prune(connection)

    def fail_interrupted(self) -> None:
        """Mark scans left running by a prior process as failed after restart."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE scans SET status = 'failed', failed = 1 "
                "WHERE status = 'running'"
            )

    def list_scans(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scan_id, generated_at, target, policy, status,
                       requests, findings, failed
                FROM scans ORDER BY generated_at DESC, rowid DESC
                LIMIT ?
                """,
                (self.max_scans,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_result(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM scans "
                "WHERE scan_id = ? AND status = 'completed'",
                (scan_id,),
            ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def get_completed_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT scan_id, generated_at, target, policy, status, "
                "requests, findings, failed FROM scans "
                "WHERE scan_id = ? AND status = 'completed'",
                (scan_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT scan_id, generated_at, target, policy, status, "
                "requests, findings, failed FROM scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_findings(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT scan_id, generated_at, target, policy, result_json "
                "FROM scans WHERE status = 'completed' ORDER BY generated_at DESC"
            ).fetchall()
        findings = []
        for row in rows:
            result = json.loads(row["result_json"])
            for finding in result.get("findings", []):
                findings.append(
                    {
                        "scan_id": row["scan_id"],
                        "generated_at": row["generated_at"],
                        "target": row["target"],
                        "policy": row["policy"],
                        **finding,
                    }
                )
        return findings

    def _prune(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            DELETE FROM scans
            WHERE scan_id IN (
                SELECT scan_id FROM scans
                ORDER BY generated_at DESC, rowid DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.max_scans,),
        )
