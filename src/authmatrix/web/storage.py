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
    """Persist bounded scan metadata and sanitized result documents."""

    max_scans = 1000

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
