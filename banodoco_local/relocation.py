"""Launcher-owned support-root relocation with an offline cutover."""

from __future__ import annotations

import hashlib
from dataclasses import replace
import os
from pathlib import Path
import time
from typing import Any, Mapping

from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    RuntimeBoundary,
    _bootstrap_mutex,
    _bootstrap_locked,
    _read_support_json,
    _validate_support_paths,
)
from .io import atomic_write_json, owner_only, remove_file
from .paths import RuntimePaths


class RelocationError(BootstrapError):
    """A relocation precondition or handoff failed."""


def _absolute(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise RelocationError(f"{label} must be an absolute path")
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise RelocationError(f"{label} contains a symlink component: {path}")
    return path


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _selected(catalog: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    realm_id = str(catalog.get("selected_realm_id") or "")
    rows = [row for row in catalog.get("realms", ()) if isinstance(row, Mapping) and str(row.get("realm_id")) == realm_id]
    if not realm_id or len(rows) != 1:
        raise RelocationError("relocation requires exactly one selected realm")
    return realm_id, dict(rows[0])


def _read_relocation_catalog(paths: RuntimePaths) -> dict[str, Any]:
    """Read support metadata without applying Stage 1's one-realm limit."""

    catalog = _read_support_json(paths.catalog_path)
    if catalog is None or catalog.get("version") != 1:
        raise RelocationError("relocation requires a valid neutral realm catalog")
    realms = catalog.get("realms")
    if not isinstance(realms, list):
        raise RelocationError("realm catalog must contain a list of realms")
    seen: set[str] = set()
    for row in realms:
        if not isinstance(row, Mapping):
            raise RelocationError("realm catalog contains an invalid realm entry")
        realm_id = str(row.get("realm_id") or "")
        if not realm_id or realm_id in seen:
            raise RelocationError("realm catalog contains duplicate or empty realm ids")
        _absolute(str(row.get("data_root") or ""), "catalog realm root")
        seen.add(realm_id)
    _selected(catalog)
    return catalog


def _rewrite_path(value: Any, old_root: Path, new_root: Path) -> Any:
    if not isinstance(value, str):
        return value
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        return value
    candidate = Path(os.path.abspath(candidate))
    if not _inside(candidate, old_root):
        return value
    return str(new_root / candidate.relative_to(old_root))


def _catalog_for_support_root(catalog: Mapping[str, Any], old_root: Path, new_root: Path) -> dict[str, Any]:
    result = dict(catalog)
    result["realms"] = [
        {**dict(row), "data_root": _rewrite_path(row.get("data_root"), old_root, new_root)}
        for row in catalog.get("realms", [])
    ]
    profiles = catalog.get("source_profiles")
    if isinstance(profiles, Mapping):
        result["source_profiles"] = {
            name: ({**dict(profile), "runtime_environment": _rewrite_path(profile.get("runtime_environment"), old_root, new_root)} if isinstance(profile, Mapping) else profile)
            for name, profile in profiles.items()
        }
    return result


def catalog_with_relocated_root(catalog: Mapping[str, Any], realm_id: str, destination: str | Path) -> dict[str, Any]:
    """Return a catalog copy with one realm root changed, preserving all rows."""

    rows = catalog.get("realms")
    if not isinstance(rows, list):
        raise RelocationError("realm catalog must contain a list of realms")
    target = str(_absolute(destination, "relocation destination"))
    updated: list[dict[str, Any]] = []
    matches = 0
    for row in rows:
        if not isinstance(row, Mapping):
            raise RelocationError("realm catalog contains an invalid realm entry")
        copy = dict(row)
        if str(copy.get("realm_id")) == str(realm_id):
            copy["data_root"] = target
            matches += 1
        updated.append(copy)
    if matches != 1:
        raise RelocationError(f"realm catalog must contain exactly one realm {realm_id!r}")
    result = dict(catalog)
    result["realms"] = updated
    return result


def _snapshot_metadata(paths: RuntimePaths) -> dict[Path, bytes]:
    files = [paths.catalog_path, paths.discovery_path, paths.instance_lock_path]
    files.extend(sorted(paths.source_profiles_dir.glob("*.json")))
    return {
        path.relative_to(paths.app_support): path.read_bytes()
        for path in files
        if path.is_file() and not path.is_symlink()
    }


def _restore_metadata(root: Path, snapshot: Mapping[Path, bytes]) -> None:
    for relative, payload in snapshot.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        owner_only(path)


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _validate_move(old_root: Path, new_root: Path) -> None:
    if not old_root.is_dir() or old_root.is_symlink():
        raise RelocationError(f"current support root is unavailable: {old_root}")
    if new_root.exists() or new_root.is_symlink():
        raise RelocationError(f"relocation destination must be new: {new_root}")
    if _inside(new_root, old_root) or _inside(old_root, new_root):
        raise RelocationError("relocation destination must not be inside the current support root")
    if not new_root.parent.is_dir() or new_root.parent.is_symlink():
        raise RelocationError("relocation destination parent must be an existing regular directory")
    try:
        if old_root.stat().st_dev != new_root.parent.stat().st_dev:
            raise RelocationError("relocation requires a same-filesystem destination")
    except OSError as exc:
        raise RelocationError("relocation filesystem identity is unavailable") from exc


def plan_relocation(paths: RuntimePaths, destination: str | Path, backup: str | Path | None = None) -> dict[str, Any]:
    """Return a read-only support-root relocation plan bound to the owner."""

    _validate_support_paths(paths)
    catalog = _read_relocation_catalog(paths)
    realm_id, realm = _selected(catalog)
    old_support = _absolute(paths.app_support, "current support root")
    target_support = _absolute(destination, "relocation destination")
    backup_path = _absolute(backup, "backup destination") if backup is not None else None
    _validate_move(old_support, target_support)
    old_realm = _absolute(str(realm.get("data_root") or ""), "current realm root")
    discovery = _read_support_json(paths.discovery_path) or {}
    if not discovery.get("pid"):
        raise RelocationError("relocation requires a live selected runtime owner")
    return {
        "operation": "realm-relocation",
        "state": "planned",
        "realm_id": realm_id,
        "current_support_root": str(old_support),
        "destination_support_root": str(target_support),
        "current_root": str(old_realm),
        "destination_root": str(target_support / old_realm.relative_to(old_support)),
        "backup": str(backup_path) if backup_path is not None else None,
        "execution": "same-volume-offline-cutover",
        "steps": [
            "acquire launcher bootstrap lock and verify owner birth identity",
            "stop the selected owner through the birth-checked boundary",
            "atomically rename the complete support root and rewrite owned absolute pointers",
            "cold-start the selected realm from the new support root and verify health",
            "retire the old path after successful verification; rollback by renaming it back on failure",
        ],
        "confirmation": f"RELOCATE {realm_id}",
    }


def relocate(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig, client: Any, *, destination: str | Path, backup: str | Path | None = None, confirmation: str) -> dict[str, Any]:
    """Move one complete support root after a birth-checked offline stop."""

    plan = plan_relocation(paths, destination, backup)
    if confirmation != plan["confirmation"]:
        raise RelocationError(f"relocation requires confirmation exactly {plan['confirmation']!r}")
    old_support = Path(plan["current_support_root"])
    new_support = Path(plan["destination_support_root"])
    target_paths = RuntimePaths.current_mac(data_root=new_support)

    with _bootstrap_mutex(paths):
        # Recheck paths after acquiring the launcher fence.
        _validate_move(old_support, new_support)
        snapshot = _snapshot_metadata(paths)
        catalog = _read_relocation_catalog(paths)
        realm_id, realm = _selected(catalog)
        source = config.resolve_source_profile(paths)
        discovery = _read_support_json(paths.discovery_path) or {}
        if str(discovery.get("active_realm")) != realm_id:
            raise RelocationError("runtime discovery does not match selected realm")
        prepare = getattr(boundary, "prepare_restart", None)
        stop_owner = getattr(boundary, "stop_owner", None)
        if prepare is None or stop_owner is None:
            raise RelocationError("runtime boundary lacks the birth-checked stop handoff")
        prepare(source_profile=source, realm_id=realm_id, realm_root=Path(str(realm["data_root"])), support_root=paths.runtime_support, pid=int(discovery["pid"]))
        stop_owner(endpoint=str(discovery["endpoint"]), pid=int(discovery["pid"]), instance_id=str(discovery["runtime_instance_id"]), process_birth_id=str(discovery["process_birth_id"]), realm_id=realm_id, owner_lock=paths.instance_lock_path, discovery_path=paths.discovery_path)
        remove_file(paths.discovery_path)
        remove_file(paths.instance_lock_path)

        moved = False
        try:
            os.replace(old_support, new_support)
            moved = True
            _fsync_directory(old_support.parent)
            _fsync_directory(new_support.parent)
            atomic_write_json(target_paths.catalog_path, _catalog_for_support_root(catalog, old_support, new_support))
            for profile_path in sorted(target_paths.source_profiles_dir.glob("*.json")):
                if profile_path.is_symlink() or not profile_path.is_file():
                    continue
                value = _read_support_json(profile_path)
                if value is not None:
                    atomic_write_json(profile_path, {**value, "runtime_environment": _rewrite_path(value.get("runtime_environment"), old_support, new_support)})
            atomic_write_json(new_support / "relocation-handoff.json", {"version": 1, "state": "moved", "realm_id": realm_id, "old_support_root": str(old_support), "new_support_root": str(new_support), "catalog_sha256": hashlib.sha256(target_paths.catalog_path.read_bytes()).hexdigest()})
            # The renamed bootstrap.lock is the same inode we already hold.
            # Calling bootstrap() would acquire it again and deadlock.
            relocated_source = replace(source, runtime_environment=_rewrite_path(source.runtime_environment, old_support, new_support))
            relocated_config = replace(config, source_profile=relocated_source)
            _validate_support_paths(target_paths)
            result = _bootstrap_locked(target_paths, boundary, relocated_config)
            if not result.ready or result.realm_id != realm_id:
                raise RelocationError("new support root failed cold-start verification")
            atomic_write_json(new_support / "relocation-handoff.json", {"version": 1, "state": "verified", "realm_id": realm_id, "old_support_root": str(old_support), "new_support_root": str(new_support), "catalog_sha256": hashlib.sha256(target_paths.catalog_path.read_bytes()).hexdigest(), "verified_at": time.time()})
            return {"status": "relocated", "realm_id": realm_id, "support_root": str(new_support), "data_root": str(new_support / Path(str(realm["data_root"])).relative_to(old_support)), "old_support_root": str(old_support)}
        except Exception as exc:
            try:
                if moved and new_support.exists() and not old_support.exists():
                    candidate_discovery = _read_support_json(target_paths.discovery_path) or {}
                    if candidate_discovery.get("pid"):
                        try:
                            boundary.stop_owner(
                                endpoint=str(candidate_discovery.get("endpoint", "")),
                                pid=int(candidate_discovery["pid"]),
                                instance_id=str(candidate_discovery.get("runtime_instance_id", "")),
                                process_birth_id=str(candidate_discovery.get("process_birth_id", "")),
                                realm_id=realm_id,
                                owner_lock=target_paths.instance_lock_path,
                                discovery_path=target_paths.discovery_path,
                            )
                        except Exception as stop_exc:
                            raise RelocationError("relocation rollback cannot proceed while the candidate owner is live") from stop_exc
                    os.replace(new_support, old_support)
                    _restore_metadata(old_support, snapshot)
                    _fsync_directory(old_support.parent)
            except OSError as rollback_exc:
                raise RelocationError(f"relocation failed and rollback failed: {rollback_exc}") from exc
            raise RelocationError(f"relocation rolled back: {exc}") from exc


__all__ = ["RelocationError", "catalog_with_relocated_root", "plan_relocation", "relocate"]
