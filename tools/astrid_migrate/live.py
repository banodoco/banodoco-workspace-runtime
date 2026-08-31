"""Serialized live Astrid migration (B12).

The ordinary migrator is deliberately source-scoped and the rehearsal is
disposable.  This module composes those two primitives for the one selected
realm migration: a caller must provide fresh, mutually distinct authorizations
and an explicit writer-stop boundary.  Destination writes happen in a fresh
runtime realm; the selected realm is changed only by the verified activation
swap, and rollback/reactivation use the same durable journal.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass, replace
import hashlib
import json
import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from runtime_protocol.backup import restore_backup, verify_backup, verify_restore_candidate
from runtime_protocol.service import RuntimeService

from .migrator import MigrationConfig, MigrationError, Migrator, _sha256_file, _tree_size
from .rehearsal import MigrationJournal, RuntimeServiceAdapter, _tree_digest, _write_json


LIVE_AUTHORIZATION_IDS = (
    "AUTH-LIVE-INPUT-B12",
    "AUTH-WRITER-STOP-B12",
    "AUTH-LIVE-MIGRATION-B12",
    "AUTH-ACTIVATION-B12",
    "AUTH-ROLLBACK-B12",
    "AUTH-REACTIVATION-B12",
)


def issue_live_authorizations(*, source_manifest_sha256: str | None = None, selected_realm_id: str | None = None, ttl_seconds: int = 3600) -> dict[str, dict[str, Any]]:
    """Create a fresh set of B12 command authorizations.

    The returned values are operator input, not durable authority.  The live
    runner records only a SHA-256 of each nonce in its journal, so credentials
    never enter migration evidence.
    """
    if ttl_seconds <= 0:
        raise ValueError("authorization TTL must be positive")
    expires_at = time.time() + ttl_seconds
    result = {}
    for authorization_id in LIVE_AUTHORIZATION_IDS:
        result[authorization_id] = {
            "authorization_id": authorization_id,
            "scope": authorization_id.removeprefix("AUTH-").lower(),
            "nonce": secrets.token_urlsafe(32),
            "source_manifest_sha256": source_manifest_sha256,
            "selected_realm_id": selected_realm_id,
            "expires_at": expires_at,
        }
    return result


@dataclass(frozen=True)
class LiveMigration:
    """Execute B12 against a selected runtime and an immutable source root."""

    config: MigrationConfig
    active_runtime: RuntimeService
    authorizations: Mapping[str, Mapping[str, Any]]
    writer_stop: Callable[[], Any]
    fault_injector: Callable[[str], None] | None = None
    crash_at: str | None = None

    def __post_init__(self) -> None:
        missing = [item for item in LIVE_AUTHORIZATION_IDS if item not in self.authorizations]
        if missing:
            raise MigrationError(f"B12 requires fresh authorizations: {', '.join(missing)}")
        nonces = []
        for authorization_id in LIVE_AUTHORIZATION_IDS:
            value = self.authorizations[authorization_id]
            if value.get("authorization_id") != authorization_id or not value.get("nonce"):
                raise MigrationError(f"invalid authorization instance {authorization_id}")
            nonces.append(str(value["nonce"]))
        if len(set(nonces)) != len(nonces):
            raise MigrationError("B12 authorizations must use distinct nonces")
        if self.config.destination_root == Path(self.active_runtime.store.root).resolve():
            raise MigrationError("B12 destination must be separate from the selected realm")
        if self.config.dry_run:
            raise MigrationError("B12 live runner does not accept dry_run; use Migrator for dry-run")

    @staticmethod
    def _nonce_digest(value: Mapping[str, Any]) -> str:
        return hashlib.sha256(str(value["nonce"]).encode("utf-8")).hexdigest()

    def _validate_authorization(self, authorization_id: str, *, source_manifest_sha256: str | None, realm_id: str) -> dict[str, Any]:
        value = self.authorizations[authorization_id]
        if value.get("selected_realm_id") not in (None, realm_id):
            raise MigrationError(f"{authorization_id} selected realm does not match the active realm")
        bound_source = value.get("source_manifest_sha256")
        if bound_source not in (None, source_manifest_sha256):
            raise MigrationError(f"{authorization_id} source manifest does not match the frozen source")
        try:
            if float(value.get("expires_at", 0)) <= time.time():
                raise MigrationError(f"{authorization_id} has expired")
        except (TypeError, ValueError) as exc:
            raise MigrationError(f"{authorization_id} has an invalid expiry") from exc
        return dict(value)

    def _consume_authorization(self, authorization_id: str, *, source_manifest_sha256: str, realm_id: str, journal: MigrationJournal) -> dict[str, Any]:
        value = self._validate_authorization(authorization_id, source_manifest_sha256=source_manifest_sha256, realm_id=realm_id)
        effect_name = f"authorization:{authorization_id}"
        digest = self._nonce_digest(value)
        existing = journal.effects().get(effect_name)
        if existing:
            payload = existing.get("payload", {})
            if (payload.get("nonce_sha256") != digest or
                    payload.get("source_manifest_sha256") != source_manifest_sha256 or
                    payload.get("selected_realm_id") != realm_id):
                raise MigrationError(f"{authorization_id} replay conflicts with the durable journal")
            return existing
        journal.effect(effect_name, authorization_id=authorization_id, nonce_sha256=digest, source_manifest_sha256=source_manifest_sha256, selected_realm_id=realm_id)
        return journal.effects()[effect_name]

    def _writer_boundary(self, stack: ExitStack) -> dict[str, Any]:
        if not callable(self.writer_stop):
            raise MigrationError("B12 requires an explicit writer-stop boundary")
        boundary = self.writer_stop()
        if hasattr(boundary, "__enter__") and hasattr(boundary, "__exit__"):
            value = stack.enter_context(boundary)
        else:
            value = boundary
        if not isinstance(value, Mapping) or value.get("stopped") is not True:
            raise MigrationError("writer-stop boundary must return stopped=true")
        return {str(key): item for key, item in value.items() if key not in {"token", "nonce", "authorization"}} | {"stopped": True}

    def _capacity(self, inventory: Mapping[str, Any], evidence_root: Path) -> dict[str, Any]:
        source_bytes = _tree_size(self.config.source_root)
        destination_bytes = _tree_size(self.config.destination_root) if self.config.destination_root.exists() else 0
        margin = self.config.capacity_margin_bytes if self.config.capacity_margin_bytes is not None else max(int(source_bytes * 0.2), 10 * 1024**3)
        required = source_bytes * 2 + destination_bytes * 2 + int(inventory.get("estimated_cas_bytes", 0)) + _tree_size(evidence_root) + margin
        available = int(inventory["destination_free_bytes"])
        receipt = {"packet": "B12.1", "source_bytes": source_bytes, "archive_bytes": source_bytes, "destination_bytes": destination_bytes, "margin_bytes": margin, "required_bytes": required, "available_bytes": available, "reserved": available >= required}
        if not receipt["reserved"]:
            raise MigrationError("B12.1 capacity reservation is insufficient")
        return receipt

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MigrationError(f"B12 durable artifact is unreadable: {path}") from exc
        if not isinstance(value, dict):
            raise MigrationError(f"B12 durable artifact is not an object: {path}")
        return value

    @staticmethod
    def _existing_effect(journal: MigrationJournal, name: str) -> dict[str, Any] | None:
        return journal.effects().get(name)

    @staticmethod
    def _path_exists(path: Path) -> bool:
        # Path.exists() is false for a dangling symlink.  A destination must
        # be genuinely absent, not merely absent after link resolution.
        return os.path.lexists(str(path))

    def _fresh_destination(self, destination: Path) -> None:
        if self._path_exists(destination):
            raise MigrationError("B12 destination must be a fresh, non-symlink path")
        if destination.is_symlink():
            raise MigrationError("B12 destination must not be a symlink")

    def _bind_request(self, journal: MigrationJournal, *, realm_id: str, source_manifest_sha256: str, evidence_root: Path) -> dict[str, Any]:
        binding = {
            "realm_id": realm_id,
            "source_manifest_sha256": source_manifest_sha256,
            "source_root": str(self.config.source_root.resolve()),
            "archive_root": str(self.config.archive_root.resolve()),
            "destination_root": str(self.config.destination_root.resolve()),
            "evidence_root": str(evidence_root.resolve()),
            "authorization_nonce_sha256": {
                authorization_id: self._nonce_digest(self.authorizations[authorization_id])
                for authorization_id in LIVE_AUTHORIZATION_IDS
            },
        }
        current = journal._read()
        recorded = current.get("binding")
        if recorded is not None and recorded != binding:
            raise MigrationError("B12 replay conflicts with the durable request binding")
        if recorded is None:
            journal.bind(**binding)
        return binding

    def _terminal_replay(self, journal: MigrationJournal, *, realm_id: str) -> dict[str, Any]:
        current = journal._read()
        binding = current.get("binding")
        if not isinstance(binding, Mapping):
            raise MigrationError("B12 terminal journal has no durable request binding")
        if binding.get("realm_id") != realm_id or binding.get("destination_root") != str(self.config.destination_root.resolve()):
            raise MigrationError("B12 terminal replay conflicts with realm or destination binding")
        if binding.get("source_root") != str(self.config.source_root.resolve()) or binding.get("archive_root") != str(self.config.archive_root.resolve()):
            raise MigrationError("B12 terminal replay conflicts with source or archive binding")
        try:
            source_manifest = Migrator(self.config, None).inventory()["source_manifest_sha256"]
        except Exception as exc:
            raise MigrationError("B12 terminal replay could not verify the frozen source") from exc
        if binding.get("source_manifest_sha256") != source_manifest:
            raise MigrationError("B12 terminal replay conflicts with the frozen source manifest")
        expected_nonces = binding.get("authorization_nonce_sha256")
        if not isinstance(expected_nonces, Mapping):
            raise MigrationError("B12 terminal journal has no authorization binding")
        for authorization_id in LIVE_AUTHORIZATION_IDS:
            value = self.authorizations.get(authorization_id)
            self._validate_authorization(authorization_id, source_manifest_sha256=source_manifest, realm_id=realm_id)
            if not isinstance(value, Mapping) or self._nonce_digest(value) != expected_nonces.get(authorization_id):
                raise MigrationError(f"{authorization_id} replay conflicts with the durable authorization")
        entries = current.get("entries", [])
        identity = entries[-1].get("identity") if entries else None
        if not isinstance(identity, Mapping) or identity.get("realm_id") != realm_id or identity.get("source_manifest_sha256") != source_manifest or identity.get("destination_root") != str(self.active_runtime.store.root):
            raise MigrationError("B12 terminal journal has an invalid final identity binding")
        final_effect = journal.effects().get("final-identity")
        if not final_effect or final_effect.get("payload", {}).get("identity") != dict(identity):
            raise MigrationError("B12 terminal journal final identity effect is missing or conflicting")
        if identity.get("active_database_sha256") != _sha256_file(self.active_runtime.store.db_path):
            raise MigrationError("B12 terminal replay conflicts with the active final identity")
        return {"packet": "B12", "journal": current, "identity": dict(identity), "idempotent": True}

    def _backup_or_reuse(self, runtime: RuntimeService, destination: Path, *, binding: Mapping[str, Any], journal: MigrationJournal, effect_name: str, seam: str) -> dict[str, Any]:
        existing = self._existing_effect(journal, effect_name)
        if existing:
            payload = existing.get("payload", {})
            if payload.get("path") != str(destination) or payload.get("realm_id") != binding.get("selected_realm_id"):
                raise MigrationError(f"B12 {effect_name} conflicts with the durable effect")
            try:
                verified = verify_backup(destination)
            except Exception as exc:
                raise MigrationError(f"B12 durable backup effect is not reusable: {destination}") from exc
            if dict(verified["manifest"].get("destination_binding") or {}) != dict(binding):
                raise MigrationError(f"B12 durable backup binding changed on disk: {destination}")
            if payload.get("manifest_sha256") != _sha256_file(destination / "manifest.json"):
                raise MigrationError(f"B12 durable backup effect changed on disk: {destination}")
            return verified
        if self._path_exists(destination):
            try:
                verified = verify_backup(destination)
            except Exception as exc:
                raise MigrationError(f"B12 existing backup is not a verified reusable artifact: {destination}") from exc
            actual = verified["manifest"].get("destination_binding") or {}
            if dict(actual) != dict(binding):
                raise MigrationError(f"B12 existing backup has a conflicting binding: {destination}")
        else:
            journal._inject(f"before_{seam}")
            verified = runtime.backup(destination, binding=dict(binding))
            journal._inject(f"after_{seam}")
        journal.effect(effect_name, path=str(destination), manifest_sha256=_sha256_file(destination / "manifest.json"), realm_id=binding.get("selected_realm_id"))
        return verified

    def _restore_or_reuse(self, backup: Path, destination: Path, *, journal: MigrationJournal, effect_name: str, realm_id: str, seam: str) -> dict[str, Any]:
        existing = self._existing_effect(journal, effect_name)
        if existing:
            payload = existing.get("payload", {})
            if payload.get("destination") != str(destination) or payload.get("realm_id") != realm_id:
                raise MigrationError(f"B12 {effect_name} conflicts with the durable effect")
            try:
                verification = verify_restore_candidate(destination)
            except Exception as exc:
                raise MigrationError(f"B12 durable restore effect is not reusable: {destination}") from exc
            if payload.get("source_manifest_sha256") != verification["handoff"].get("source_manifest_sha256"):
                raise MigrationError(f"B12 durable restore effect changed source binding: {destination}")
            return {"destination": str(destination), "realm_id": realm_id, "verification": verification}
        if self._path_exists(destination):
            try:
                verification = verify_restore_candidate(destination)
            except Exception as exc:
                raise MigrationError(f"B12 existing restore candidate is not reusable: {destination}") from exc
        else:
            journal._inject(f"before_{seam}")
            restored = restore_backup(backup, destination)
            journal._inject(f"after_{seam}")
            verification = verify_restore_candidate(destination)
        if verification["manifest"].get("realm_id") != realm_id:
            raise MigrationError(f"B12 restore candidate has the wrong realm: {destination}")
        journal.effect(effect_name, destination=str(destination), realm_id=realm_id, source_manifest_sha256=verification["handoff"].get("source_manifest_sha256"), database_sha256=verification.get("database_sha256"))
        return {"destination": str(destination), "realm_id": realm_id, "verification": verification}

    def run(self) -> dict[str, Any]:
        active = self.active_runtime
        realm_id = str(active.realm["id"])
        evidence_root = (self.config.evidence_root or self.config.destination_root.parent / "migration-evidence-b12").resolve()
        journal = MigrationJournal(evidence_root / "migration-journal-b12.json", fault_injector=self.fault_injector, crash_at=self.crash_at)
        current = journal._read()
        if current["state"] == "reactivated":
            return self._terminal_replay(journal, realm_id=realm_id)
        if current["state"] not in {"prepared", "active", "rolled_back"}:
            raise MigrationError("B12 live migration journal is interrupted; inspect it before resuming")
        evidence_root.mkdir(parents=True, exist_ok=True)
        if current["state"] == "prepared" and current.get("binding") is None:
            self._fresh_destination(self.config.destination_root)
        archive_root = self.config.archive_root
        active_backup_root = archive_root.parent / f"{archive_root.name}-live-pre-migration-backup"
        destination_backup_root = archive_root.parent / f"{archive_root.name}-live-destination-backup"
        candidate_root = archive_root.parent / f"{archive_root.name}-live-candidate"
        rollback_root = archive_root.parent / f"{archive_root.name}-live-rollback"
        reactivation_root = archive_root.parent / f"{archive_root.name}-live-reactivated"
        with ExitStack() as stack:
            self._validate_authorization("AUTH-LIVE-INPUT-B12", source_manifest_sha256=None, realm_id=realm_id)
            writer_receipt = self._writer_boundary(stack)
            self._validate_authorization("AUTH-WRITER-STOP-B12", source_manifest_sha256=None, realm_id=realm_id)

            probe = Migrator(self.config, None)
            inventory = probe.inventory()
            source_manifest_sha256 = inventory["source_manifest_sha256"]
            binding = self._bind_request(journal, realm_id=realm_id, source_manifest_sha256=source_manifest_sha256, evidence_root=evidence_root)
            for authorization_id in LIVE_AUTHORIZATION_IDS:
                self._validate_authorization(authorization_id, source_manifest_sha256=source_manifest_sha256, realm_id=realm_id)
            self._consume_authorization("AUTH-LIVE-INPUT-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            self._consume_authorization("AUTH-WRITER-STOP-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            if current["state"] == "prepared":
                freeze_path = evidence_root / "source-freeze-b12.json"
                freeze_effect = self._existing_effect(journal, "source-freeze")
                freeze = self._read_json(freeze_path) if freeze_effect else {"packet": "B12.1", "state": "frozen", "source_manifest_sha256": source_manifest_sha256, "source_tree_sha256": _tree_digest(self.config.source_root), "source_facts_sha256": inventory["source_facts_sha256"], "writer": writer_receipt, "created_at": time.time()}
                if not freeze_effect:
                    _write_json(freeze_path, freeze)
                    byte_manifest = {"packet": "B12.1", "source_manifest_sha256": source_manifest_sha256, "source_facts_sha256": inventory["source_facts_sha256"], "database_sha256": inventory["database_sha256"], "files": inventory["files"], "files_sha256": inventory["files_sha256"], "created_at": time.time()}
                    _write_json(evidence_root / "source-byte-manifest-b12.json", byte_manifest)
                    journal.effect("source-freeze", path=str(freeze_path), source_manifest_sha256=source_manifest_sha256, source_byte_manifest_sha256=inventory["files_sha256"])
                capacity_path = evidence_root / "capacity-receipt-b12.json"
                capacity_effect = self._existing_effect(journal, "capacity-receipt")
                capacity = self._read_json(capacity_path) if capacity_effect else self._capacity(inventory, evidence_root)
                if not capacity_effect:
                    _write_json(capacity_path, capacity)
                    journal.effect("capacity-receipt", path=str(capacity_path), required_bytes=capacity["required_bytes"], available_bytes=capacity["available_bytes"])
                writer_path = evidence_root / "writer-freeze-receipt-b12.json"
                if not self._existing_effect(journal, "writer-freeze-receipt"):
                    _write_json(writer_path, freeze | {"authorization_id": "AUTH-WRITER-STOP-B12"})
                    journal.effect("writer-freeze-receipt", path=str(writer_path), source_manifest_sha256=source_manifest_sha256)
                dry_path = evidence_root / "dry-run-receipt-b12.json"
                dry_effect = self._existing_effect(journal, "dry-run-receipt")
                if dry_effect:
                    dry_run = self._read_json(dry_path)["report"]
                else:
                    dry_config = replace(self.config, dry_run=True, expected_source_manifest_sha256=source_manifest_sha256, expected_source_facts_sha256=inventory["source_facts_sha256"])
                    dry_run = Migrator(dry_config, None).migrate()
                    _write_json(dry_path, {"packet": "B12.1", "source_manifest_sha256": source_manifest_sha256, "report": dry_run})
                    journal.effect("dry-run-receipt", path=str(dry_path), source_manifest_sha256=source_manifest_sha256)
                active_binding = {"packet": "B12.1", "kind": "rollback-archive", "selected_realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256}
                active_backup = self._backup_or_reuse(active, active_backup_root, binding=active_binding, journal=journal, effect_name="pre-migration-backup", seam="active_backup")
                self._consume_authorization("AUTH-LIVE-MIGRATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)

                destination = RuntimeService(self.config.destination_root, display_name=active.realm["display_name"], realm_id=realm_id)
                destination_adapter = RuntimeServiceAdapter(destination)
                try:
                    migration_effect = self._existing_effect(journal, "migration-receipt")
                    if migration_effect:
                        migration = self._read_json(evidence_root / "migration-receipt-b12.json")["report"]
                    else:
                        live_config = replace(self.config, require_destination_verification=True, expected_source_manifest_sha256=source_manifest_sha256, expected_source_facts_sha256=inventory["source_facts_sha256"])
                        journal._inject("before_migration")
                        migration = Migrator(live_config, destination_adapter).migrate()
                        journal._inject("after_migration")
                        _write_json(evidence_root / "migration-receipt-b12.json", {"packet": "B12.2", "migration_epoch": 1, "report": migration})
                        journal.effect("migration-receipt", path=str(evidence_root / "migration-receipt-b12.json"), source_manifest_sha256=source_manifest_sha256)
                    reconciliation = migration["reconciliation"]
                    if not reconciliation.get("ok"):
                        raise MigrationError("B12.2 reconciliation failed")
                    destination_binding = {"packet": "B12.2", "kind": "destination", "selected_realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "reconciliation": reconciliation}
                    destination_backup = self._backup_or_reuse(destination, destination_backup_root, binding=destination_binding, journal=journal, effect_name="destination-backup", seam="destination_backup")
                finally:
                    destination.close()

                candidate_result = self._restore_or_reuse(destination_backup_root, candidate_root, journal=journal, effect_name="candidate-restore", realm_id=realm_id, seam="candidate_restore")
                destination_activation_manifest = self.config.destination_root / "activation-manifest.json"
                if destination_activation_manifest.is_file() and not (candidate_root / "activation-manifest.json").is_file():
                    shutil.copy2(destination_activation_manifest, candidate_root / "activation-manifest.json")
                # The activation manifest is a control-plane handoff, not
                # part of the realm backup. Re-verify after attaching it.
                candidate_verification = verify_restore_candidate(candidate_root)
                candidate_result = candidate_result | {"verification": candidate_verification}
                destination_binding = candidate_verification["manifest"].get("destination_binding") or {}
                if (destination_binding.get("packet") != "B12.2" or destination_binding.get("selected_realm_id") != realm_id or destination_binding.get("source_manifest_sha256") != source_manifest_sha256):
                    raise MigrationError("B12.3 destination backup is not bound to the selected live migration")
                self._consume_authorization("AUTH-ACTIVATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
                activation_effect = self._existing_effect(journal, "active-activation")
                candidate_db = candidate_verification["database_sha256"]
                if activation_effect:
                    activated = activation_effect["payload"]["activation"]
                elif _sha256_file(active.store.db_path) == candidate_db:
                    activated = {"state": "active", "reused": True, "candidate": str(candidate_root)}
                    journal.effect("active-activation", candidate=str(candidate_root), state="active", activation=activated, database_sha256=candidate_db)
                else:
                    journal._inject("before_active_activation")
                    activated = RuntimeServiceAdapter(active).activate_destination(candidate_root, state="active")
                    journal._inject("after_active_activation")
                    journal.effect("active-activation", candidate=str(candidate_root), state="active", activation=activated, database_sha256=candidate_db)
                active_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
                active_entry = journal.transition("active", source_manifest_sha256=source_manifest_sha256, destination=str(self.config.destination_root), destination_backup=str(destination_backup_root), activation=activated, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=1)
                _write_json(evidence_root / "activated-destination-b12-active.json", {"packet": "B12.3", "state": "active", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "activation_epoch": 1, "runtime_epoch": active.health()["runtime_epoch"], "database_sha256": _sha256_file(active.store.db_path)})
            else:
                active_entry = current
                source_manifest_sha256 = str(current["binding"]["source_manifest_sha256"])
                active_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
                freeze = capacity = dry_run = migration = reconciliation = active_backup = destination_backup = None
                activated = None

            if journal._read()["state"] == "active":
                self._consume_authorization("AUTH-ROLLBACK-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
                rollback_result = self._restore_or_reuse(active_backup_root, rollback_root, journal=journal, effect_name="rollback-restore", realm_id=realm_id, seam="rollback_restore")
                rollback_verification = rollback_result["verification"]
                rollback_effect = self._existing_effect(journal, "rollback-activation")
                if rollback_effect:
                    rolled_back = rollback_effect["payload"]["activation"]
                elif _sha256_file(active.store.db_path) == rollback_verification["database_sha256"]:
                    rolled_back = {"state": "rolled_back", "reused": True, "candidate": str(rollback_root)}
                    journal.effect("rollback-activation", candidate=str(rollback_root), state="rolled_back", activation=rolled_back, database_sha256=rollback_verification["database_sha256"])
                else:
                    journal._inject("before_rollback_activation")
                    rolled_back = RuntimeServiceAdapter(active).activate_destination(rollback_root, state="rolled_back")
                    journal._inject("after_rollback_activation")
                    journal.effect("rollback-activation", candidate=str(rollback_root), state="rolled_back", activation=rolled_back, database_sha256=rollback_verification["database_sha256"])
                rollback_entry = journal.transition("rolled_back", predecessor=active_entry["entries"][-1], activation=rolled_back, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=2)
                _write_json(evidence_root / "activated-destination-b12-rollback.json", {"packet": "B12.3", "state": "rolled_back", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "activation_epoch": 2, "runtime_epoch": active.health()["runtime_epoch"], "database_sha256": _sha256_file(active.store.db_path)})
            else:
                rollback_entry = current
                rolled_back = None

            if journal._read()["state"] == "rolled_back":
                self._consume_authorization("AUTH-REACTIVATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
                reactivation_result = self._restore_or_reuse(destination_backup_root, reactivation_root, journal=journal, effect_name="reactivation-restore", realm_id=realm_id, seam="reactivation_restore")
                reactivation_verification = reactivation_result["verification"]
                reactivation_effect = self._existing_effect(journal, "reactivation-activation")
                if reactivation_effect:
                    reactivated = reactivation_effect["payload"]["activation"]
                elif _sha256_file(active.store.db_path) == reactivation_verification["database_sha256"]:
                    reactivated = {"state": "reactivated", "reused": True, "candidate": str(reactivation_root)}
                    journal.effect("reactivation-activation", candidate=str(reactivation_root), state="reactivated", activation=reactivated, database_sha256=reactivation_verification["database_sha256"])
                else:
                    journal._inject("before_reactivation_activation")
                    reactivated = RuntimeServiceAdapter(active).activate_destination(reactivation_root, state="reactivated")
                    journal._inject("after_reactivation_activation")
                    journal.effect("reactivation-activation", candidate=str(reactivation_root), state="reactivated", activation=reactivated, database_sha256=reactivation_verification["database_sha256"])
                final_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
                identity = {"packet": "B12.4", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "destination_root": str(active.store.root), "runtime_epoch": active.health()["runtime_epoch"], "activation_epoch": 3, "source_backup_manifest_sha256": _sha256_file(active_backup_root / "manifest.json"), "destination_backup_manifest_sha256": _sha256_file(destination_backup_root / "manifest.json"), "active_database_sha256": _sha256_file(active.store.db_path), "active_snapshot_counts": {key: len(value) for key, value in final_snapshot.items() if isinstance(value, list)}}
                _write_json(evidence_root / "activated-destination-b12-reactivated.json", {"packet": "B12.3", "state": "reactivated", **{key: identity[key] for key in ("realm_id", "source_manifest_sha256", "activation_epoch", "runtime_epoch", "active_database_sha256")}})
                journal.effect("final-identity", identity=identity)
                final = journal.transition("reactivated", predecessor=rollback_entry["entries"][-1], activation=reactivated, identity=identity, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=3)
                _write_json(evidence_root / "activated-destination-b12.json", identity)
                return {"packet": "B12", "source_freeze": freeze, "capacity": capacity, "dry_run": dry_run, "migration": migration, "reconciliation": reconciliation, "active_backup": active_backup, "destination_backup": destination_backup, "journal": final, "activation": activated, "rollback": rolled_back, "reactivation": reactivated, "identity": identity, "active_snapshot": active_snapshot, "final_snapshot": final_snapshot}
            raise MigrationError("B12 live migration did not reach a resumable terminal state")


def run_live_migration(config: MigrationConfig, active_runtime: RuntimeService, authorizations: Mapping[str, Mapping[str, Any]], *, writer_stop: Callable[[], Any], fault_injector: Callable[[str], None] | None = None, crash_at: str | None = None) -> dict[str, Any]:
    """Run the serialized B12 flow against a selected disposable runtime."""
    return LiveMigration(config, active_runtime, authorizations, writer_stop, fault_injector=fault_injector, crash_at=crash_at).run()


__all__ = ["LIVE_AUTHORIZATION_IDS", "LiveMigration", "issue_live_authorizations", "run_live_migration"]
