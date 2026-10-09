"""Shared read-only and fenced authority for disruptive Runtime lifecycle work."""

from __future__ import annotations

import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .errors import ConflictError, RealmAdmissionError, ValidationError
from .catalog import _safe_path


def _regular_database(root: str | Path) -> tuple[Path, Path]:
    try:
        root = _safe_path(root, "realm root").resolve()
    except ValueError as exc:
        raise RealmAdmissionError(str(exc)) from exc
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise RealmAdmissionError("realm root is missing or invalid")
    database = root / "realm.sqlite3"
    try:
        mode = database.lstat().st_mode
    except FileNotFoundError as exc:
        raise RealmAdmissionError("realm database is missing") from exc
    if not stat.S_ISREG(mode) or database.is_symlink():
        raise RealmAdmissionError("realm database must be an ordinary file")
    return root, database


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _expired(value: object, *, observed_at: datetime) -> bool | None:
    if value is None or str(value) == "":
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed <= observed_at
    except (TypeError, ValueError):
        return None


def _interruption_report(connection: sqlite3.Connection) -> dict[str, object]:
    """Describe every durable reason a stop/restart/upgrade is unsafe."""
    tables = _tables(connection)
    if not {"tasks", "attempts"}.issubset(tables):
        raise ValidationError(
            "cannot establish runtime interruption safety: task/attempt tables are missing"
        )
    observed_at = datetime.now(timezone.utc)
    active_tasks = [
        {"task_id": str(row[0]), "status": str(row[1])}
        for row in connection.execute(
            "SELECT id, status FROM tasks WHERE lower(status)='running' ORDER BY id"
        )
    ]
    unreconciled_attempts = []
    for row in connection.execute(
        "SELECT id, task_id, lease_id, lease_expires_at, runtime_epoch "
        "FROM attempts WHERE settled=0 ORDER BY id"
    ):
        unreconciled_attempts.append(
            {
                "attempt_id": str(row[0]),
                "task_id": str(row[1]),
                "lease_id": str(row[2]),
                "lease_expires_at": row[3],
                "lease_expired": _expired(row[3], observed_at=observed_at),
                "runtime_epoch": int(row[4]),
            }
        )
    claimed_bindings = []
    if "execution_bindings" in tables:
        claimed_bindings = [
            {"binding_id": str(row[0]), "task_id": str(row[1]), "status": str(row[2])}
            for row in connection.execute(
                "SELECT binding_id, task_id, status FROM execution_bindings "
                "WHERE status IN ('claimed', 'stale') ORDER BY binding_id"
            )
        ]
    unreleased_reservations = []
    if "reservations" in tables:
        unreleased_reservations = [
            {"task_id": str(row[0]), "resource_key": str(row[1]), "lease_token": str(row[2])}
            for row in connection.execute(
                "SELECT task_id, resource_key, lease_token FROM reservations "
                "WHERE released_at IS NULL ORDER BY task_id, resource_key"
            )
        ]
    blockers = bool(
        active_tasks
        or unreconciled_attempts
        or claimed_bindings
        or unreleased_reservations
    )
    return {
        "safe": not blockers,
        "active_tasks": active_tasks,
        "unreconciled_attempts": unreconciled_attempts,
        "claimed_or_stale_bindings": claimed_bindings,
        "unreleased_reservations": unreleased_reservations,
    }


def inspect_interruption_state(root: str | Path) -> dict[str, object]:
    """Observe lifecycle blockers without creating files, sidecars, or rows."""
    _, database = _regular_database(root)
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    try:
        return _interruption_report(connection)
    finally:
        connection.close()


def assert_interruption_safe(root: str | Path) -> dict[str, object]:
    report = inspect_interruption_state(root)
    if not report["safe"]:
        raise ConflictError(
            "runtime lifecycle refused while work is active or unreconciled",
            details=report,
        )
    return report


@contextmanager
def interruption_fence(
    root: str | Path,
    *,
    timeout_seconds: float = 5.0,
) -> Iterator[dict[str, object]]:
    """Hold SQLite's write fence while a live owner is identity-stopped.

    The initial read-only check gives a side-effect-free refusal path.  The
    immediate transaction then serializes with admission/claim/settlement, so
    no claim can land between the final idle decision and the process signal.
    The transaction is always rolled back because this authority writes no
    lifecycle rows itself.
    """
    assert_interruption_safe(root)
    _, database = _regular_database(root)
    connection = sqlite3.connect(database, timeout=float(timeout_seconds))
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN IMMEDIATE")
        report = _interruption_report(connection)
        if not report["safe"]:
            raise ConflictError(
                "runtime lifecycle refused while work became active or unreconciled",
                details=report,
            )
        yield report
    finally:
        connection.rollback()
        connection.close()


__all__ = [
    "assert_interruption_safe",
    "inspect_interruption_state",
    "interruption_fence",
]
