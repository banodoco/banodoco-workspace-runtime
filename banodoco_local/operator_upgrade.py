"""One guarded operator workflow for upgrading and relocating Astrid runtime data."""

from __future__ import annotations

import json
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
    _canonical_realm_root,
    _lock_matches,
    _read_catalog,
    _read_support_json,
    _selected_realm,
)
from .io import atomic_write_json, remove_file
from .paths import RuntimePaths
from .relocation import _reject_live_pack_host, relocate
from runtime_protocol.upgrade import (
    DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    _open_readonly,
    inspect_canonical_schema,
    migrate_canonical_to_current,
    upgrade_realm,
)
from runtime_protocol.lifecycle import inspect_interruption_state, interruption_fence


class OperatorUpgradeError(BootstrapError):
    """A guarded upgrade workflow could not safely advance."""


_JOURNAL_VERSION = 1


def _realm_from_catalog(paths: RuntimePaths) -> tuple[str, Path]:
    catalog = _read_catalog(paths)
    realm = _selected_realm(catalog)
    if not realm:
        raise OperatorUpgradeError("upgrade requires one selected Astrid realm")
    realm_id = str(realm.get("realm_id") or "")
    root = Path(str(realm.get("data_root") or "")).expanduser()
    if not realm_id:
        raise OperatorUpgradeError("selected Astrid realm root is missing or unsafe")
    try:
        root = _canonical_realm_root(root)
    except BootstrapError as exc:
        raise OperatorUpgradeError("selected Astrid realm root is missing or unsafe") from exc
    return realm_id, root


def _schema_kind(root: Path, *, expected_realm_id: str) -> str:
    connection = _open_readonly(root / "realm.sqlite3")
    try:
        tables = {
            str(row[0]) for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if "runtime_schema" in tables:
            try:
                return str(
                    inspect_canonical_schema(
                        root, expected_realm_id=expected_realm_id
                    )["kind"]
                )
            except Exception as exc:
                raise OperatorUpgradeError(str(exc)) from exc
        if "schema_migrations" in tables:
            version = int(connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0])
            if version == 23:
                realm_rows = connection.execute("SELECT id FROM realm ORDER BY id").fetchall()
                if len(realm_rows) != 1 or str(realm_rows[0][0]) != expected_realm_id:
                    raise OperatorUpgradeError("legacy realm identity does not match the selected workspace")
                return "v23"
            raise OperatorUpgradeError(f"realm has unsupported legacy schema version {version}")
        raise OperatorUpgradeError("realm is neither canonical v24/v25/v26 nor the supported v23 format")
    finally:
        connection.close()


def _assert_idle(root: Path) -> dict[str, Any]:
    try:
        report = inspect_interruption_state(root)
        if not report["safe"]:
            raise OperatorUpgradeError(
                "upgrade refused while runtime work is active or unreconciled; reconcile attempts first: "
                + json.dumps(report, sort_keys=True)
            )
        return report
    except OperatorUpgradeError:
        raise
    except Exception as exc:
        raise OperatorUpgradeError(str(exc)) from exc


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


def _owner_record(paths: RuntimePaths, realm_id: str, realm_root: Path, boundary: RuntimeBoundary) -> dict[str, Any] | None:
    discovery = _read_support_json(paths.discovery_path)
    if not discovery or not discovery.get("pid"):
        marker = _read_support_json(paths.instance_lock_path)
        if marker and int(marker.get("pid", 0) or 0) > 0:
            if boundary.is_pid_alive(int(marker["pid"])):
                raise OperatorUpgradeError("runtime owner identity is incomplete; use banodoco-local restart before upgrading")
        return None
    if str(discovery.get("active_realm")) != realm_id:
        raise OperatorUpgradeError("runtime discovery does not match the selected realm")
    required = ("endpoint", "pid", "runtime_instance_id", "process_birth_id", "realm_root")
    if any(not discovery.get(key) for key in required):
        raise OperatorUpgradeError("runtime owner identity is incomplete; refusing to signal it")
    canonical_root = _canonical_realm_root(realm_root)
    if _canonical_realm_root(str(discovery["realm_root"])) != canonical_root:
        raise OperatorUpgradeError("runtime discovery root does not match the selected realm")
    pid = int(discovery["pid"])
    instance_id = str(discovery["runtime_instance_id"])
    birth_id = str(discovery["process_birth_id"])
    if not _lock_matches(paths, pid, instance_id, realm_id, birth_id, canonical_root):
        raise OperatorUpgradeError("runtime owner lock does not match discovery")
    if not boundary.validate_owner(
        endpoint=str(discovery["endpoint"]), pid=pid, instance_id=instance_id,
        owner_lock=paths.instance_lock_path, process_birth_id=birth_id,
        expected_realm_id=realm_id, expected_realm_root=canonical_root,
    ):
        raise OperatorUpgradeError("runtime endpoint or process identity does not match discovery")
    metadata = boundary.endpoint_metadata(
        endpoint=str(discovery["endpoint"]),
        credential_file=paths.runtime_support / "credentials" / "owner.token",
    )
    if str(metadata.get("runtime_instance_id") or "") != instance_id or str(metadata.get("realm_id") or "") != realm_id:
        raise OperatorUpgradeError("runtime authenticated endpoint identity does not match discovery")
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
    # Classify exact schema and realm identity before journaling or signaling.
    # Unknown/newer/alternate layouts therefore retain byte-identical source
    # and support state on refusal.
    kind = _schema_kind(realm_root, expected_realm_id=realm_id)
    idle = _assert_idle(realm_root)
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
            owner = _owner_record(paths, realm_id, realm_root, boundary)
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
                # BEGIN IMMEDIATE serializes with admission/claim/settlement.
                # Hold it across the final identity-checked signal so a claim
                # cannot land between the idle decision and owner shutdown.
                try:
                    with interruption_fence(realm_root, timeout_seconds=timeout_seconds) as fenced_idle:
                        stop_owner(
                            endpoint=str(owner["endpoint"]), pid=int(owner["pid"]),
                            instance_id=str(owner["runtime_instance_id"]), process_birth_id=str(owner["process_birth_id"]),
                            realm_id=realm_id, owner_lock=paths.instance_lock_path,
                            discovery_path=paths.discovery_path, require_health=False,
                        )
                        stopped = True
                        idle = fenced_idle
                except Exception as exc:
                    raise OperatorUpgradeError(str(exc)) from exc
                remove_file(paths.discovery_path)
                remove_file(paths.instance_lock_path)
            _journal(paths, operation_id=operation_id, state="stopped", realm_id=realm_id, schema_before=kind, idle=idle)
            if kind == "v23":
                migration = upgrade_realm(realm_root, timeout_seconds=timeout_seconds, confirmation=f"UPGRADE {realm_id}")
            else:
                migration = migrate_canonical_to_current(
                    realm_root, timeout_seconds=timeout_seconds,
                    confirmation=f"MIGRATE CANONICAL {realm_id}",
                    expected_realm_id=realm_id,
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
