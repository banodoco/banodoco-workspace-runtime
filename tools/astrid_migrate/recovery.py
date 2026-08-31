"""B13.2 recovery, disposable purge, reboot-R2, and final reactivation.

This module is deliberately an operator-side composition of the neutral runtime
and the already verified backup/restore primitives.  It does not make a live
realm disposable, and it never treats a missing path or a journal label as
proof that a destructive operation happened.  Every destructive step is
bound to the selected realm, durable artifact digests, and a one-shot
authorization digest.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile
import time
from typing import Any, Callable, Mapping

from runtime_protocol.backup import restore_backup, verify_backup, verify_restore_candidate
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import atomic_json_write, canonical_json, new_id

from .migrator import MigrationError, _sha256_file
from .rehearsal import RuntimeServiceAdapter, _tree_digest


B13_AUTHORIZATION_IDS = (
    "AUTH-PURGE-B13",
    "AUTH-REBOOT-R2",
    "AUTH-ROLLBACK-B13",
    "AUTH-REACTIVATION-B13",
)


def _absolute_path(value: str | Path) -> Path:
    """Make a lexical absolute path without following symlinks."""
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _has_symlink_component(path: Path) -> bool:
    """Return whether any existing component of ``path`` is a symlink."""
    path = _absolute_path(path)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def _database_snapshot_sha256(path: Path) -> str:
    """Hash a consistent SQLite view, including committed WAL frames."""
    source = sqlite3.connect(str(path), timeout=10)
    snapshot_fd, snapshot_name = tempfile.mkstemp(prefix=".b13-db-snapshot-", dir=str(path.parent))
    os.close(snapshot_fd)
    snapshot = Path(snapshot_name)
    snapshot.unlink(missing_ok=True)
    try:
        target = sqlite3.connect(str(snapshot), timeout=10)
        try:
            source.backup(target)
            target.commit()
        finally:
            target.close()
        return _sha256_file(snapshot)
    finally:
        source.close()
        snapshot.unlink(missing_ok=True)


def issue_b13_authorizations(*, selected_realm_id: str | None = None, ttl_seconds: int = 3600) -> dict[str, dict[str, Any]]:
    """Issue distinct, short-lived operator inputs for the B13 commands."""
    if ttl_seconds <= 0:
        raise ValueError("authorization TTL must be positive")
    if not isinstance(selected_realm_id, str) or not selected_realm_id.strip():
        raise ValueError("B13 authorizations require a concrete selected realm")
    expires_at = time.time() + ttl_seconds
    return {
        authorization_id: {
            "authorization_id": authorization_id,
            "scope": authorization_id.removeprefix("AUTH-").lower(),
            "nonce": secrets.token_urlsafe(32),
            "selected_realm_id": selected_realm_id,
            "expires_at": expires_at,
        }
        for authorization_id in B13_AUTHORIZATION_IDS
    }


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _semantic_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Remove the database digest, which changes when the boot epoch advances."""
    return {str(key): value for key, value in snapshot.items() if key != "database_sha256"}


class RecoveryJournal:
    """Durable B13 cursor with append-only transitions and effects."""

    _states = (
        "prepared", "recovery_base", "purged", "checkpointed",
        "reboot_requested", "recovered", "rolled_back", "reactivated",
    )
    _allowed = {
        "prepared": {"recovery_base"},
        "recovery_base": {"purged"},
        "purged": {"checkpointed"},
        "checkpointed": {"reboot_requested"},
        "reboot_requested": {"recovered"},
        "recovered": {"rolled_back"},
        "rolled_back": {"reactivated"},
        "reactivated": set(),
    }

    def __init__(self, path: str | Path, *, crash_at: str | None = None, fault_injector: Callable[[str], None] | None = None):
        self.path = Path(path).expanduser().resolve()
        self.crash_at = crash_at
        self.fault_injector = fault_injector

    def _inject(self, seam: str) -> None:
        if self.crash_at == seam:
            raise MigrationError(f"injected B13.2 crash at {seam}")
        if self.fault_injector is not None:
            self.fault_injector(seam)

    @staticmethod
    def _hash(value: Mapping[str, Any]) -> str:
        return _canonical_digest({key: item for key, item in value.items() if key not in {"entry_sha256", "effect_sha256"}})

    def read(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"format_version": 1, "generation": 0, "state": "prepared", "entries": [], "effects": []}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MigrationError("B13.2 recovery journal is corrupt or interrupted") from exc
        if not isinstance(value, dict) or value.get("format_version") != 1 or not isinstance(value.get("entries"), list) or not isinstance(value.get("effects"), list):
            raise MigrationError("B13.2 recovery journal has an invalid envelope")
        state = value.get("state")
        if state not in self._states or not isinstance(value.get("generation"), int):
            raise MigrationError("B13.2 recovery journal has an invalid state")
        previous, generation = "prepared", 0
        for entry in value["entries"]:
            if not isinstance(entry, dict) or entry.get("from") != previous or entry.get("to") not in self._states or int(entry.get("generation", -1)) != generation + 1 or entry.get("entry_sha256") != self._hash(entry):
                raise MigrationError("B13.2 recovery journal has a broken transition chain")
            previous, generation = entry["to"], generation + 1
        if previous != state or generation != value["generation"]:
            raise MigrationError("B13.2 recovery journal generation/state mismatch")
        for effect in value["effects"]:
            if not isinstance(effect, dict) or not effect.get("name") or effect.get("effect_sha256") != self._hash(effect):
                raise MigrationError("B13.2 recovery journal has a broken effect record")
        return value

    def effects(self) -> dict[str, dict[str, Any]]:
        return {str(effect["name"]): effect for effect in self.read().get("effects", []) if isinstance(effect, dict) and effect.get("name")}

    def bind(self, **payload: Any) -> dict[str, Any]:
        current = self.read()
        if current.get("binding") is not None:
            if current["binding"] != payload:
                raise MigrationError("B13.2 recovery request binding conflict")
            return current
        if current["state"] != "prepared":
            raise MigrationError("B13.2 recovery binding must be established while prepared")
        result = current | {"binding": dict(payload)}
        self._inject("before_bind")
        atomic_json_write(self.path, result)
        self._inject("after_bind")
        return result

    def effect(self, name: str, **payload: Any) -> dict[str, Any]:
        current = self.read()
        for effect in current["effects"]:
            if effect.get("name") == name:
                if effect.get("payload") != payload:
                    raise MigrationError(f"B13.2 effect {name!r} conflicts with its durable record")
                return current
        effect = {"name": name, "payload": payload, "generation": current["generation"]}
        effect["effect_sha256"] = self._hash(effect)
        result = current | {"effects": [*current["effects"], effect]}
        self._inject(f"before_effect_{name}")
        atomic_json_write(self.path, result)
        self._inject(f"after_effect_{name}")
        return result

    def transition(self, state: str, **payload: Any) -> dict[str, Any]:
        current = self.read()
        if current["state"] == state:
            if payload:
                last = current["entries"][-1] if current["entries"] else {}
                for key, value in payload.items():
                    if last.get(key) != value:
                        raise MigrationError(f"B13.2 terminal replay conflicts on {key}")
            return current
        if state not in self._allowed.get(current["state"], set()):
            raise MigrationError(f"invalid B13.2 recovery transition {current['state']} -> {state}")
        entry = {"from": current["state"], "to": state, "generation": current["generation"] + 1, **payload}
        entry["entry_sha256"] = self._hash(entry)
        result = current | {"state": state, "generation": entry["generation"], "entries": [*current["entries"], entry]}
        self._inject(f"before_{current['state']}_to_{state}")
        atomic_json_write(self.path, result)
        self._inject(f"after_{current['state']}_to_{state}")
        return result


@dataclass
class B13Recovery:
    """Run the product-level B13.2 recovery journey against one selected realm."""

    active_runtime: RuntimeService
    recovery_base_backup: Path
    rollback_archive: Path
    evidence_root: Path
    disposable_root: Path
    authorizations: Mapping[str, Mapping[str, Any]]
    crash_at: str | None = None
    fault_injector: Callable[[str], None] | None = None

    def __post_init__(self) -> None:
        missing = [item for item in B13_AUTHORIZATION_IDS if item not in self.authorizations]
        if missing:
            raise MigrationError(f"B13.2 requires fresh authorizations: {', '.join(missing)}")
        nonces = [str(self.authorizations[item].get("nonce") or "") for item in B13_AUTHORIZATION_IDS]
        if any(not nonce for nonce in nonces) or len(set(nonces)) != len(nonces):
            raise MigrationError("B13.2 authorizations must have distinct nonces")
        for authorization_id in B13_AUTHORIZATION_IDS:
            value = self.authorizations[authorization_id]
            expected_scope = authorization_id.removeprefix("AUTH-").lower()
            if value.get("scope") != expected_scope:
                raise MigrationError(f"{authorization_id} scope does not match the requested operation")
            selected_realm_id = value.get("selected_realm_id")
            if not isinstance(selected_realm_id, str) or not selected_realm_id.strip():
                raise MigrationError(f"{authorization_id} requires a concrete selected realm")
        # Preserve lexical paths until safety checks have rejected symlinks.
        self.recovery_base_backup = _absolute_path(self.recovery_base_backup)
        self.rollback_archive = _absolute_path(self.rollback_archive)
        self.evidence_root = _absolute_path(self.evidence_root)
        self.disposable_root = _absolute_path(self.disposable_root)

    @staticmethod
    def _nonce_digest(value: Mapping[str, Any]) -> str:
        return hashlib.sha256(str(value["nonce"]).encode("utf-8")).hexdigest()

    def _validate_auth(self, authorization_id: str, realm_id: str) -> Mapping[str, Any]:
        value = self.authorizations[authorization_id]
        if value.get("authorization_id") != authorization_id:
            raise MigrationError(f"invalid B13.2 authorization instance {authorization_id}")
        expected_scope = authorization_id.removeprefix("AUTH-").lower()
        if value.get("scope") != expected_scope:
            raise MigrationError(f"{authorization_id} scope does not match the requested operation")
        if value.get("selected_realm_id") != realm_id:
            raise MigrationError(f"{authorization_id} is bound to a different selected realm")
        try:
            if float(value.get("expires_at", 0)) <= time.time():
                raise MigrationError(f"{authorization_id} has expired")
        except (TypeError, ValueError) as exc:
            raise MigrationError(f"{authorization_id} has an invalid expiry") from exc
        return value

    def _consume_auth(self, journal: RecoveryJournal, authorization_id: str, realm_id: str) -> None:
        value = self._validate_auth(authorization_id, realm_id)
        digest = self._nonce_digest(value)
        name = f"authorization:{authorization_id}"
        existing = journal.effects().get(name)
        if existing:
            if existing.get("payload") != {"authorization_id": authorization_id, "nonce_sha256": digest, "realm_id": realm_id}:
                raise MigrationError(f"{authorization_id} conflicts with its durable consumption")
            return
        journal.effect(name, authorization_id=authorization_id, nonce_sha256=digest, realm_id=realm_id)

    def _write(self, name: str, value: Mapping[str, Any]) -> Path:
        path = self.evidence_root / name
        atomic_json_write(path, dict(value))
        return path

    def _verify_backup(self, path: Path, realm_id: str) -> dict[str, Any]:
        try:
            verified = verify_backup(path)
        except Exception as exc:
            raise MigrationError(f"B13.2 backup is not authenticated and complete: {path}") from exc
        if verified["manifest"].get("realm_id") != realm_id:
            raise MigrationError(f"B13.2 backup belongs to a different realm: {path}")
        return verified

    def _restore_or_reuse(self, backup: Path, destination: Path, *, realm_id: str, journal: RecoveryJournal, effect_name: str, seam: str) -> dict[str, Any]:
        existing = journal.effects().get(effect_name)
        if existing:
            payload = existing["payload"]
            if payload.get("destination") != str(destination) or payload.get("realm_id") != realm_id:
                raise MigrationError(f"B13.2 {effect_name} has a conflicting destination")
            try:
                verification = verify_restore_candidate(destination)
            except Exception as exc:
                raise MigrationError(f"B13.2 durable restore candidate is invalid: {destination}") from exc
        elif os.path.lexists(str(destination)):
            try:
                verification = verify_restore_candidate(destination)
            except Exception as exc:
                raise MigrationError(f"B13.2 pre-existing restore candidate is not reusable: {destination}") from exc
        else:
            journal._inject(f"before_{seam}")
            restore_backup(backup, destination)
            journal._inject(f"after_{seam}")
            verification = verify_restore_candidate(destination)
        if verification["manifest"].get("realm_id") != realm_id:
            raise MigrationError("B13.2 restore candidate realm identity mismatch")
        journal.effect(effect_name, destination=str(destination), realm_id=realm_id, database_sha256=verification["database_sha256"], source_manifest_sha256=verification["handoff"].get("source_manifest_sha256"))
        return {"destination": str(destination), "realm_id": realm_id, "verification": verification}

    def _safe_disposable_target(self, realm_id: str) -> dict[str, Any]:
        target = self.disposable_root
        # Check the lexical path before resolving it: resolving a pre-existing
        # symlink would turn an unsafe delete into an apparently safe target.
        if _has_symlink_component(target):
            raise MigrationError("B13.2 purge target is not a fresh ordinary path")
        if os.path.lexists(str(target)):
            raise MigrationError("B13.2 purge target must not pre-exist")
        forbidden = {self.active_runtime.store.root.resolve(), self.recovery_base_backup.resolve(), self.rollback_archive.resolve()}
        if target.resolve() in forbidden:
            raise MigrationError("B13.2 purge target is not separate from an authoritative root")
        catalog = self.active_runtime.support_root / "catalog.json" if self.active_runtime.support_root else None
        selected = bool(catalog and catalog.is_file() and str(target) in catalog.read_text(encoding="utf-8"))
        return {"realm_class": "disposable", "selected": selected, "live": False, "migration_source": False, "migration_destination": False, "backup": False, "rollback_archive": False, "realm_id": realm_id, "root": str(target)}

    def _purge_disposable(self, journal: RecoveryJournal, realm_id: str, base: Mapping[str, Any]) -> dict[str, Any]:
        target = self.disposable_root
        existing = journal.effects().get("purge-complete")
        if existing:
            if target.exists() or os.path.lexists(str(target)):
                raise MigrationError("B13.2 purge receipt says target is gone but the target exists")
            return dict(existing["payload"])
        # Tombstoning is the irreversible lifecycle precondition for purge;
        # require the dedicated purge authorization before changing it.
        self._validate_auth("AUTH-PURGE-B13", realm_id)
        self._consume_auth(journal, "AUTH-PURGE-B13", realm_id)
        if not journal.effects().get("purge-started"):
            if _has_symlink_component(target):
                raise MigrationError("B13.2 unsafe purge target")
            if not os.path.lexists(str(target)) or not target.exists():
                raise MigrationError("B13.2 disposable purge target is missing before purge")
            if target.resolve() in {self.active_runtime.store.root.resolve(), self.recovery_base_backup.resolve(), self.rollback_archive.resolve()}:
                raise MigrationError("B13.2 unsafe purge target")
            target_store = RealmStore(target, acquire_owner=True)
            try:
                lifecycle = target_store.realm_lifecycle()
                if target_store.realm["id"] != realm_id or lifecycle["state"] != "active":
                    if target_store.realm["id"] != realm_id or lifecycle["state"] != "tombstoned":
                        raise MigrationError("B13.2 disposable target identity/lifecycle is invalid")
                pre_purge_tree = _tree_digest(target)
                pre_purge_database = _sha256_file(target / "realm.sqlite3")
                if lifecycle["state"] == "active":
                    target_store.tombstone_realm(reason="B13.2 disposable purge")
                tombstoned = target_store.realm_lifecycle()
            finally:
                target_store.close()
            payload = {"target": str(target), "realm_id": realm_id, "pre_purge_tree_sha256": pre_purge_tree, "pre_purge_database_sha256": pre_purge_database, "tombstoned_database_sha256": _sha256_file(target / "realm.sqlite3"), "lifecycle": tombstoned, "classification": dict(base)}
            journal.effect("purge-started", **payload)
        journal._inject("before_purge")
        if target.exists():
            shutil.rmtree(target)
        if os.path.lexists(str(target)):
            raise MigrationError("B13.2 disposable purge did not remove its exact target")
        journal._inject("after_purge")
        payload = journal.effects()["purge-started"]["payload"] | {"purged": True, "post_purge_exists": False}
        journal.effect("purge-complete", **payload)
        return payload

    def _open_after_reboot(self, runtime: RuntimeService, *, realm_id: str, expected_epoch: int) -> tuple[RuntimeService, dict[str, Any]]:
        root = runtime.store.root.resolve()
        display_name = runtime.realm["display_name"] if getattr(runtime.store, "conn", None) is not None else "Workspace"
        support_root = runtime.support_root
        runtime.close()
        reopened = RuntimeService(root, display_name=display_name, realm_id=realm_id, support_root=support_root)
        health = reopened.health()
        if int(health["runtime_epoch"]) != expected_epoch + 1:
            reopened.close()
            raise MigrationError(f"B13.2 R2 runtime epoch did not advance exactly once: expected {expected_epoch + 1}, got {health['runtime_epoch']}")
        report = reopened.doctor()
        if not report["ok"] or reopened.realm["id"] != realm_id:
            reopened.close()
            raise MigrationError("B13.2 R2 reopened runtime failed identity or integrity checks")
        return reopened, {"runtime_epoch": health["runtime_epoch"], "doctor": report}

    def _resume_reboot(self, journal: RecoveryJournal, realm_id: str, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        expected = int(checkpoint["runtime_epoch"])
        current_runtime = self.active_runtime
        current_epoch = None
        if getattr(current_runtime.store, "conn", None) is not None:
            current_epoch = int(current_runtime.health()["runtime_epoch"])
        effect = journal.effects().get("reboot-complete")
        if effect:
            payload = effect["payload"]
            if int(payload["runtime_epoch_before"]) != expected or int(payload["runtime_epoch_after"]) != expected + 1:
                raise MigrationError("B13.2 R2 reboot receipt has an invalid epoch transition")
            if current_epoch != expected + 1:
                raise MigrationError("B13.2 R2 reboot receipt does not match the current runtime")
            return dict(payload)
        if current_epoch not in (None, expected):
            if current_epoch != expected + 1:
                raise MigrationError("B13.2 runtime is at an unexpected epoch while resuming R2")
            # The process may have restarted successfully and then failed
            # before its receipt was committed.  Do not boot a second time;
            # seal the already-observed post-boot state instead.
            if current_runtime.realm["id"] != realm_id or not current_runtime.doctor()["ok"]:
                raise MigrationError("B13.2 post-R2 runtime is unhealthy or has the wrong realm")
            snapshot = RuntimeServiceAdapter(current_runtime).destination_snapshot()
            payload = {"realm_id": realm_id, "root": str(current_runtime.store.root), "runtime_epoch_before": expected, "runtime_epoch_after": current_epoch, "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(snapshot)), "doctor_ok": True}
            self.active_runtime = current_runtime
            journal._inject("after_reboot_execute")
            journal.effect("reboot-complete", **payload)
            return payload
        reopened, result = self._open_after_reboot(current_runtime, realm_id=realm_id, expected_epoch=expected)
        # Publish the new owner before any post-boot failpoint.  If the
        # process dies after the real reopen but before the receipt write, the
        # caller can resume through this already-open independent runtime.
        self.active_runtime = reopened
        snapshot = RuntimeServiceAdapter(reopened).destination_snapshot()
        payload = {"realm_id": realm_id, "root": str(reopened.store.root), "runtime_epoch_before": expected, "runtime_epoch_after": int(result["runtime_epoch"]), "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(snapshot)), "doctor_ok": bool(result["doctor"]["ok"])}
        journal._inject("after_reboot_execute")
        journal.effect("reboot-complete", **payload)
        return payload

    def _activate(self, candidate: Path, state: str, *, realm_id: str, journal: RecoveryJournal, seam: str) -> dict[str, Any]:
        if candidate.is_symlink() or not candidate.is_dir():
            raise MigrationError(f"B13.2 {state} candidate is not an ordinary directory")
        journal._inject(f"before_{seam}")
        result = RuntimeServiceAdapter(self.active_runtime).activate_destination(candidate, state=state)
        journal._inject(f"after_{seam}")
        if self.active_runtime.realm["id"] != realm_id or not self.active_runtime.doctor()["ok"]:
            raise MigrationError(f"B13.2 {state} activation failed identity/integrity verification")
        return result

    def _terminal_replay(self, journal: RecoveryJournal, realm_id: str) -> dict[str, Any]:
        current = journal.read()
        binding = current.get("binding") or {}
        for authorization_id in B13_AUTHORIZATION_IDS:
            self._validate_auth(authorization_id, realm_id)
        expected_binding = self._request_binding(realm_id)
        if binding != expected_binding:
            raise MigrationError("B13.2 terminal replay conflicts with the durable request binding")
        identity = current["entries"][-1].get("identity") if current["entries"] else None
        if not isinstance(identity, Mapping):
            raise MigrationError("B13.2 terminal journal has no final identity")
        if identity.get("realm_id") != realm_id or identity.get("root") != str(self.active_runtime.store.root.resolve()):
            raise MigrationError("B13.2 terminal identity binding is invalid")
        if not self.active_runtime.doctor()["ok"]:
            raise MigrationError("B13.2 terminal replay current runtime is unhealthy")
        snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
        if identity.get("semantic_snapshot_sha256") != _canonical_digest(_semantic_snapshot(snapshot)):
            raise MigrationError("B13.2 terminal replay conflicts with active final identity")
        if identity.get("database_sha256") != _database_snapshot_sha256(self.active_runtime.store.db_path):
            raise MigrationError("B13.2 terminal replay conflicts with active live database identity")
        return {"packet": "B13.2", "journal": current, "identity": dict(identity), "idempotent": True, "active_runtime": self.active_runtime}

    def _request_binding(self, realm_id: str) -> dict[str, Any]:
        return {
            "realm_id": realm_id,
            "active_root": str(self.active_runtime.store.root.resolve()),
            "recovery_base_backup": str(self.recovery_base_backup),
            "rollback_archive": str(self.rollback_archive),
            "evidence_root": str(self.evidence_root),
            "disposable_root": str(self.disposable_root),
            "authorization_nonce_sha256": {item: self._nonce_digest(self.authorizations[item]) for item in B13_AUTHORIZATION_IDS},
            "authorization_binding": {
                item: {
                    "authorization_id": self.authorizations[item].get("authorization_id"),
                    "scope": self.authorizations[item].get("scope"),
                    "selected_realm_id": self.authorizations[item].get("selected_realm_id"),
                    "nonce_sha256": self._nonce_digest(self.authorizations[item]),
                }
                for item in B13_AUTHORIZATION_IDS
            },
        }

    def run(self) -> dict[str, Any]:
        realm_id = str(self.active_runtime.realm["id"])
        for authorization_id in B13_AUTHORIZATION_IDS:
            self._validate_auth(authorization_id, realm_id)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        journal = RecoveryJournal(self.evidence_root / "migration-journal-b13.json", crash_at=self.crash_at, fault_injector=self.fault_injector)
        current = journal.read()
        if current["state"] == "reactivated":
            return self._terminal_replay(journal, realm_id)
        binding = self._request_binding(realm_id)
        journal.bind(**binding)
        current = journal.read()

        if current["state"] == "prepared":
            if self.recovery_base_backup.exists():
                self._verify_backup(self.recovery_base_backup, realm_id)
            else:
                self.active_runtime.backup(self.recovery_base_backup)
            base = self._verify_backup(self.recovery_base_backup, realm_id)
            rollback = self._verify_backup(self.rollback_archive, realm_id)
            classification = self._safe_disposable_target(realm_id)
            base_receipt = {"packet": "B13.2", "realm_id": realm_id, "active_root": str(self.active_runtime.store.root), "recovery_base_backup": str(self.recovery_base_backup), "recovery_base_manifest_sha256": _sha256_file(self.recovery_base_backup / "manifest.json"), "rollback_archive": str(self.rollback_archive), "rollback_archive_manifest_sha256": _sha256_file(self.rollback_archive / "manifest.json"), "active_runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "classification": classification}
            self._write("b13-recovery-base.json", base_receipt)
            journal.effect("recovery-base", **base_receipt)
            self._restore_or_reuse(self.recovery_base_backup, self.disposable_root, realm_id=realm_id, journal=journal, effect_name="disposable-restore", seam="disposable_restore")
            journal.transition("recovery_base", recovery_base_manifest_sha256=base["manifest"].get("manifest_sha256"), rollback_manifest_sha256=rollback["manifest"].get("manifest_sha256"), disposable_root=str(self.disposable_root))
            journal._inject("after_recovery_base")
            current = journal.read()

        if current["state"] == "recovery_base":
            base_effect = journal.effects().get("recovery-base")
            classification = (base_effect or {}).get("payload", {}).get("classification") or self._safe_disposable_target(realm_id)
            purge = self._purge_disposable(journal, realm_id, classification)
            self._write("purge-receipt-b13.json", {"packet": "B13.2", **purge})
            journal.transition("purged", purge_receipt_sha256=_sha256_file(self.evidence_root / "purge-receipt-b13.json"))
            current = journal.read()

        if current["state"] == "purged":
            checkpoint = journal.effects().get("checkpoint")
            if checkpoint:
                checkpoint_payload = checkpoint["payload"]
            else:
                snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
                checkpoint_payload = {"packet": "B13.2", "checkpoint_id": new_id(), "realm_id": realm_id, "active_root": str(self.active_runtime.store.root.resolve()), "runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(snapshot)), "recovery_base_manifest_sha256": _sha256_file(self.recovery_base_backup / "manifest.json"), "rollback_archive_manifest_sha256": _sha256_file(self.rollback_archive / "manifest.json"), "created_at": time.time()}
                self._write("checkpoint-r2.json", checkpoint_payload)
                journal.effect("checkpoint", **checkpoint_payload)
            self._consume_auth(journal, "AUTH-REBOOT-R2", realm_id)
            journal.transition("checkpointed", checkpoint_id=checkpoint_payload["checkpoint_id"], runtime_epoch=checkpoint_payload["runtime_epoch"])
            current = journal.read()

        if current["state"] == "checkpointed":
            checkpoint = journal.effects()["checkpoint"]["payload"]
            self._consume_auth(journal, "AUTH-REBOOT-R2", realm_id)
            journal.transition("reboot_requested", checkpoint_id=checkpoint["checkpoint_id"])
            current = journal.read()

        if current["state"] == "reboot_requested":
            checkpoint = journal.effects()["checkpoint"]["payload"]
            reboot = self._resume_reboot(journal, realm_id, checkpoint)
            journal.transition("recovered", reboot=reboot, checkpoint_id=checkpoint["checkpoint_id"])
            current = journal.read()

        if current["state"] == "recovered":
            rollback_effect = journal.effects().get("final-rollback-restore")
            candidate = self.evidence_root / "b13-final-rollback-candidate"
            if rollback_effect:
                candidate = Path(rollback_effect["payload"]["destination"])
                verify_restore_candidate(candidate)
            else:
                self._restore_or_reuse(self.rollback_archive, candidate, realm_id=realm_id, journal=journal, effect_name="final-rollback-restore", seam="final_rollback_restore")
            self._consume_auth(journal, "AUTH-ROLLBACK-B13", realm_id)
            activation = journal.effects().get("final-rollback-activation")
            if activation:
                rollback = activation["payload"]["activation"]
            else:
                rollback = self._activate(candidate, "rolled_back", realm_id=realm_id, journal=journal, seam="final_rollback_activation")
                journal.effect("final-rollback-activation", activation=rollback, destination=str(candidate), runtime_epoch=int(self.active_runtime.health()["runtime_epoch"]))
            rollback_snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
            rollback_identity = {"realm_id": realm_id, "runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(rollback_snapshot)), "database_sha256": _database_snapshot_sha256(self.active_runtime.store.db_path)}
            self._write("activated-destination-b13-rollback.json", {"packet": "B13.2", "state": "rolled_back", **rollback_identity})
            journal.transition("rolled_back", activation=rollback, identity=rollback_identity)
            current = journal.read()

        if current["state"] == "rolled_back":
            react_effect = journal.effects().get("final-reactivation-restore")
            candidate = self.evidence_root / "b13-final-reactivation-candidate"
            if react_effect:
                candidate = Path(react_effect["payload"]["destination"])
                verify_restore_candidate(candidate)
            else:
                self._restore_or_reuse(self.recovery_base_backup, candidate, realm_id=realm_id, journal=journal, effect_name="final-reactivation-restore", seam="final_reactivation_restore")
            self._consume_auth(journal, "AUTH-REACTIVATION-B13", realm_id)
            activation = journal.effects().get("final-reactivation-activation")
            if activation:
                reactivated = activation["payload"]["activation"]
            else:
                reactivated = self._activate(candidate, "reactivated", realm_id=realm_id, journal=journal, seam="final_reactivation_activation")
                journal.effect("final-reactivation-activation", activation=reactivated, destination=str(candidate), runtime_epoch=int(self.active_runtime.health()["runtime_epoch"]))
            final_snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
            checkpoint = journal.effects()["checkpoint"]["payload"]
            identity = {"packet": "B13.2", "state": "reactivated", "realm_id": realm_id, "root": str(self.active_runtime.store.root.resolve()), "runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(final_snapshot)), "database_sha256": _database_snapshot_sha256(self.active_runtime.store.db_path), "recovery_base_manifest_sha256": checkpoint["recovery_base_manifest_sha256"], "rollback_archive_manifest_sha256": checkpoint["rollback_archive_manifest_sha256"], "purged_disposable_root": str(self.disposable_root), "integrity_ok": bool(self.active_runtime.doctor()["ok"])}
            if not identity["integrity_ok"] or identity["semantic_snapshot_sha256"] != checkpoint["semantic_snapshot_sha256"]:
                raise MigrationError("B13.2 final reactivation does not match the pre-R2 active identity")
            self._write("activated-destination-b13.json", identity)
            journal.effect("final-identity", identity=identity)
            final = journal.transition("reactivated", activation=reactivated, identity=identity)
            return {"packet": "B13.2", "journal": final, "recovery_base": journal.effects().get("recovery-base", {}).get("payload"), "purge": journal.effects().get("purge-complete", {}).get("payload"), "reboot": journal.effects().get("reboot-complete", {}).get("payload"), "rollback": rollback_identity if "rollback_identity" in locals() else None, "reactivation": reactivated, "identity": identity, "active_runtime": self.active_runtime, "idempotent": False}

        raise MigrationError(f"B13.2 recovery stopped in unexpected state {journal.read()['state']!r}")


def run_b13_recovery(active_runtime: RuntimeService, *, recovery_base_backup: str | Path, rollback_archive: str | Path, evidence_root: str | Path, disposable_root: str | Path, authorizations: Mapping[str, Mapping[str, Any]], crash_at: str | None = None, fault_injector: Callable[[str], None] | None = None) -> dict[str, Any]:
    return B13Recovery(active_runtime, Path(recovery_base_backup), Path(rollback_archive), Path(evidence_root), Path(disposable_root), authorizations, crash_at=crash_at, fault_injector=fault_injector).run()


__all__ = ["B13_AUTHORIZATION_IDS", "B13Recovery", "RecoveryJournal", "issue_b13_authorizations", "run_b13_recovery"]
