"""One guarded operator workflow for upgrading and relocating Astrid runtime data."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid
from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    RuntimeBoundary,
    _bootstrap_locked,
    _bootstrap_mutex,
    _read_catalog,
    _read_support_json,
    _selected_realm,
)
from .io import atomic_write_json, remove_file
from .paths import RuntimePaths
from .relocation import _reject_live_pack_host, relocate
from runtime_protocol.upgrade import (
    DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    HISTORICAL_OUTPUT_MIGRATION_CONFIRMATION,
    _open_readonly,
    migrate_historical_managed_outputs,
    upgrade_realm,
)


class OperatorUpgradeError(BootstrapError):
    """A guarded upgrade workflow could not safely advance."""


_ACTIVE_TASK_STATES = frozenset({"running"})
_JOURNAL_VERSION = 1


def _realm_from_catalog(paths: RuntimePaths) -> tuple[str, Path]:
    catalog = _read_catalog(paths)
    realm = _selected_realm(catalog)
    if not realm:
        raise OperatorUpgradeError("upgrade requires one selected Astrid realm")
    realm_id = str(realm.get("realm_id") or "")
    root = Path(str(realm.get("data_root") or "")).expanduser()
    if not realm_id or not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise OperatorUpgradeError("selected Astrid realm root is missing or unsafe")
    return realm_id, root.resolve()


def _schema_kind(root: Path) -> str:
    connection = _open_readonly(root / "realm.sqlite3")
    try:
        tables = {
            str(row[0]) for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if "runtime_schema" in tables:
            row = connection.execute("SELECT format_id, version FROM runtime_schema WHERE id=1").fetchone()
            if row and str(row[0]) == "astrid-runtime-sqlite-v1" and int(row[1]) == 24:
                return "v24"
            raise OperatorUpgradeError("realm has an unsupported canonical runtime schema")
        if "schema_migrations" in tables:
            version = int(connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0])
            if version == 23:
                return "v23"
            raise OperatorUpgradeError(f"realm has unsupported legacy schema version {version}")
        raise OperatorUpgradeError("realm is neither canonical v24 nor the supported v23 format")
    finally:
        connection.close()


def _assert_idle(root: Path) -> dict[str, Any]:
    """Refuse a cutover while a task is executing or an attempt lease is live."""
    connection = _open_readonly(root / "realm.sqlite3")
    try:
        tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "tasks" not in tables or "attempts" not in tables:
            raise OperatorUpgradeError("cannot establish runtime idleness: task/attempt tables are missing")
        active_tasks = [
            {"task_id": str(row[0]), "status": str(row[1])}
            for row in connection.execute("SELECT id, status FROM tasks ORDER BY id")
            if str(row[1]).lower() in _ACTIVE_TASK_STATES
        ]
        unsettled = []
        for row in connection.execute(
            "SELECT a.id, a.lease_expires_at, t.status FROM attempts a JOIN tasks t ON t.id=a.task_id WHERE a.settled=0 ORDER BY a.id"
        ):
            live_lease = True
            if row[1]:
                try:
                    live_lease = datetime.fromisoformat(str(row[1]).replace("Z", "+00:00")) > datetime.now(timezone.utc)
                except ValueError:
                    live_lease = True
            if str(row[2]).lower() in _ACTIVE_TASK_STATES or live_lease:
                unsettled.append(str(row[0]))
        if active_tasks or unsettled:
            raise OperatorUpgradeError(
                "upgrade refused while runtime work is active; stop or settle tasks first: "
                + json.dumps({"tasks": active_tasks[:10], "unsettled_attempts": unsettled[:10]}, sort_keys=True)
            )
        return {"active_tasks": 0, "unsettled_attempts": 0}
    finally:
        connection.close()


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if is_dataclass(value):
        return asdict(value)
    return {}


def _journal(paths: RuntimePaths, *, operation_id: str, state: str, journal_root: Path | None = None, **details: Any) -> Path:
    path = (journal_root or paths.runtime_support) / "upgrade-journal.json"
    if not path.parent.is_dir():
        raise OperatorUpgradeError(f"cannot persist upgrade journal because support root is unavailable: {path.parent}")
    previous = _read_support_json(path) or {}
    history = list(previous.get("history", [])) if isinstance(previous.get("history"), list) else []
    history.append({"state": state, "updated_at": time.time(), **details})
    payload = {
        "version": _JOURNAL_VERSION,
        "operation": "astrid-runtime-upgrade/v1",
        "operation_id": operation_id,
        "state": state,
        "updated_at": time.time(),
        "history": history,
        **details,
    }
    atomic_write_json(path, payload)
    return path


def _owner_record(paths: RuntimePaths, realm_id: str, boundary: RuntimeBoundary) -> dict[str, Any] | None:
    discovery = _read_support_json(paths.discovery_path)
    if not discovery or not discovery.get("pid"):
        marker = _read_support_json(paths.instance_lock_path)
        if marker and int(marker.get("pid", 0) or 0) > 0:
            if boundary.is_pid_alive(int(marker["pid"])):
                raise OperatorUpgradeError("runtime owner identity is incomplete; use banodoco-local restart before upgrading")
        return None
    if str(discovery.get("active_realm")) != realm_id:
        raise OperatorUpgradeError("runtime discovery does not match the selected realm")
    required = ("endpoint", "pid", "runtime_instance_id", "process_birth_id")
    if any(not discovery.get(key) for key in required):
        raise OperatorUpgradeError("runtime owner identity is incomplete; refusing to signal it")
    return discovery


def _verify_running(paths: RuntimePaths, boundary: RuntimeBoundary, result: Any) -> dict[str, Any]:
    discovery = _read_support_json(paths.discovery_path) or {}
    endpoint = str(discovery.get("endpoint") or getattr(result, "endpoint", ""))
    pid = int(discovery.get("pid") or getattr(result, "pid", 0) or 0)
    instance = str(discovery.get("runtime_instance_id") or getattr(result, "runtime_instance_id", ""))
    if not endpoint or pid <= 0 or not instance or not boundary.health(endpoint=endpoint, pid=pid, instance_id=instance):
        raise OperatorUpgradeError("runtime restarted but failed the health check")
    token_path = paths.runtime_support / "credentials" / "owner.token"
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise OperatorUpgradeError("runtime restarted but owner credential is unavailable") from exc
    if not token:
        raise OperatorUpgradeError("runtime restarted but owner credential is empty")
    connection = boundary.connect(endpoint=endpoint, credential=token)
    report = _mapping(connection.doctor())
    if not report or not bool(report.get("ok")):
        raise OperatorUpgradeError("runtime restarted but integrity verification failed")
    return {"health": True, "integrity": dict(report)}


def upgrade_workspace(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    config: BootstrapConfig,
    *,
    destination: str | Path | None = None,
    timeout_seconds: float = DEFAULT_UPGRADE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Upgrade/reconcile one selected realm and optionally relocate its support root."""
    if config.profile != "astrid":
        raise OperatorUpgradeError("only the astrid profile is supported")
    if not hasattr(boundary, "prepare_restart") or not hasattr(boundary, "stop_owner"):
        raise OperatorUpgradeError("runtime boundary lacks the birth-checked stop handoff")
    from .bootstrap import _validate_support_paths
    _validate_support_paths(paths)
    prior_journal = _read_support_json(paths.runtime_support / "upgrade-journal.json")
    if prior_journal and prior_journal.get("state") in {"planned", "stopping", "stopped", "activated", "restarted", "relocating"}:
        raise OperatorUpgradeError(
            "an upgrade operation is already in progress or needs recovery: "
            + str(prior_journal.get("operation_id") or "unknown")
        )
    realm_id, realm_root = _realm_from_catalog(paths)
    config.resolve_source_profile(paths)
    _reject_live_pack_host(paths)
    idle = _assert_idle(realm_root)
    kind = _schema_kind(realm_root)
    operation_id = uuid.uuid4().hex
    source_support = paths.app_support
    _journal(
        paths, operation_id=operation_id, state="planned", realm_id=realm_id,
        source_support_root=str(source_support), realm_root=str(realm_root), schema_before=kind,
    )
    owner = None
    stopped = False
    activated = False
    restarted = False
    try:
        with _bootstrap_mutex(paths):
            owner = _owner_record(paths, realm_id, boundary)
            if owner:
                source = config.resolve_source_profile(paths)
                prepare = getattr(boundary, "prepare_restart", None)
                stop_owner = getattr(boundary, "stop_owner", None)
                if not callable(prepare) or not callable(stop_owner):
                    raise OperatorUpgradeError("runtime boundary lacks the birth-checked stop handoff")
                prepare(
                    source_profile=source, realm_id=realm_id, realm_root=realm_root,
                    support_root=paths.runtime_support, pid=int(owner["pid"]),
                )
                _journal(paths, operation_id=operation_id, state="stopping", realm_id=realm_id, schema_before=kind, idle=idle)
                stop_owner(
                    endpoint=str(owner["endpoint"]), pid=int(owner["pid"]),
                    instance_id=str(owner["runtime_instance_id"]), process_birth_id=str(owner["process_birth_id"]),
                    realm_id=realm_id, owner_lock=paths.instance_lock_path,
                    discovery_path=paths.discovery_path, require_health=False,
                )
                stopped = True
                remove_file(paths.discovery_path)
                remove_file(paths.instance_lock_path)
                # The owner can only have changed durable state before its
                # birth-checked stop. Re-read after the stop so a race with a
                # remote executor is a safe failure before activation.
                idle = _assert_idle(realm_root)
            _journal(paths, operation_id=operation_id, state="stopped", realm_id=realm_id, schema_before=kind, idle=idle)
            if kind == "v23":
                migration = upgrade_realm(realm_root, timeout_seconds=timeout_seconds, confirmation=f"UPGRADE {realm_id}")
            else:
                migration = migrate_historical_managed_outputs(
                    realm_root, timeout_seconds=timeout_seconds,
                    confirmation=f"{HISTORICAL_OUTPUT_MIGRATION_CONFIRMATION} {realm_id}",
                )
            activated = True
            _journal(paths, operation_id=operation_id, state="activated", realm_id=realm_id, schema_before=kind, migration=migration)
            restarted_result = _bootstrap_locked(paths, boundary, config)
            restarted = True
            verification = _verify_running(paths, boundary, restarted_result)
            _journal(paths, operation_id=operation_id, state="restarted", realm_id=realm_id, migration=migration, verification=verification)
        relocation_result = None
        if destination is not None:
            _journal(paths, operation_id=operation_id, state="relocating", realm_id=realm_id, migration=migration)
            relocation_result = relocate(
                paths, boundary, config, None, destination=destination,
                confirmation=f"RELOCATE {realm_id}",
            )
            final_paths = RuntimePaths.current_mac(data_root=destination)
            _journal(final_paths, operation_id=operation_id, state="complete", realm_id=realm_id, migration=migration, verification=verification, relocation=relocation_result)
        else:
            _journal(paths, operation_id=operation_id, state="complete", realm_id=realm_id, migration=migration, verification=verification)
        return {"ok": True, "operation_id": operation_id, "realm_id": realm_id, "schema_before": kind, "migration": migration, "verification": verification, "relocation": relocation_result}
    except Exception as exc:
        # Before activation the offline helper leaves the original database
        # untouched. Make a best-effort restart through the same fenced owner
        # boundary, but report recovery_required if that restart cannot be
        # verified; never describe a restart failure as a data rollback.
        restart_error = None
        if stopped and not activated:
            try:
                with _bootstrap_mutex(paths):
                    _bootstrap_locked(paths, boundary, config)
                restarted = True
            except Exception as restart_exc:  # pragma: no cover - platform/runtime dependent
                restart_error = str(restart_exc)
        state = "failed" if restarted or not stopped else "recovery_required"
        journal_root = paths.runtime_support if paths.runtime_support.is_dir() else None
        if journal_root is None and destination is not None:
            candidate = RuntimePaths.current_mac(data_root=destination).runtime_support
            if candidate.is_dir():
                journal_root = candidate
        if journal_root is not None:
            _journal(
                paths, journal_root=journal_root, operation_id=operation_id, state=state, realm_id=realm_id,
                schema_before=kind, activated=activated, error=str(exc), restart_error=restart_error,
            )
        raise OperatorUpgradeError(str(exc)) from exc


__all__ = ["OperatorUpgradeError", "upgrade_workspace"]
