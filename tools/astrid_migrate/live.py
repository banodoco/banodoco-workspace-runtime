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
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from runtime_protocol.backup import restore_backup, verify_restore_candidate
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

    def run(self) -> dict[str, Any]:
        active = self.active_runtime
        realm_id = str(active.realm["id"])
        evidence_root = (self.config.evidence_root or self.config.destination_root.parent / "migration-evidence-b12").resolve()
        evidence_root.mkdir(parents=True, exist_ok=True)
        journal = MigrationJournal(evidence_root / "migration-journal-b12.json")
        current = journal._read()
        if current["state"] == "reactivated":
            return {"packet": "B12", "journal": current, "idempotent": True}
        if current["state"] != "prepared":
            raise MigrationError("B12 live migration journal is interrupted; inspect it before resuming")
        if self.config.destination_root.exists() and any(self.config.destination_root.iterdir()):
            raise MigrationError("B12 destination must be a newly created empty directory")
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
            for authorization_id in LIVE_AUTHORIZATION_IDS:
                self._validate_authorization(authorization_id, source_manifest_sha256=source_manifest_sha256, realm_id=realm_id)
            self._consume_authorization("AUTH-LIVE-INPUT-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            self._consume_authorization("AUTH-WRITER-STOP-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            freeze = {"packet": "B12.1", "state": "frozen", "source_manifest_sha256": source_manifest_sha256, "source_tree_sha256": _tree_digest(self.config.source_root), "source_facts_sha256": inventory["source_facts_sha256"], "writer": writer_receipt, "created_at": time.time()}
            _write_json(evidence_root / "source-freeze-b12.json", freeze)
            byte_manifest = {"packet": "B12.1", "source_manifest_sha256": source_manifest_sha256, "source_facts_sha256": inventory["source_facts_sha256"], "database_sha256": inventory["database_sha256"], "files": inventory["files"], "files_sha256": inventory["files_sha256"], "created_at": time.time()}
            _write_json(evidence_root / "source-byte-manifest-b12.json", byte_manifest)
            capacity = self._capacity(inventory, evidence_root)
            _write_json(evidence_root / "capacity-receipt-b12.json", capacity)
            _write_json(evidence_root / "writer-freeze-receipt-b12.json", freeze | {"authorization_id": "AUTH-WRITER-STOP-B12"})
            journal.effect("source-freeze", path=str(evidence_root / "source-freeze-b12.json"), source_manifest_sha256=source_manifest_sha256, source_byte_manifest_sha256=inventory["files_sha256"])
            journal.effect("capacity-receipt", path=str(evidence_root / "capacity-receipt-b12.json"), required_bytes=capacity["required_bytes"], available_bytes=capacity["available_bytes"])
            journal.effect("writer-freeze-receipt", path=str(evidence_root / "writer-freeze-receipt-b12.json"), source_manifest_sha256=source_manifest_sha256)

            dry_config = replace(self.config, dry_run=True, expected_source_manifest_sha256=source_manifest_sha256, expected_source_facts_sha256=inventory["source_facts_sha256"])
            dry_run = Migrator(dry_config, None).migrate()
            _write_json(evidence_root / "dry-run-receipt-b12.json", {"packet": "B12.1", "source_manifest_sha256": source_manifest_sha256, "report": dry_run})
            journal.effect("dry-run-receipt", path=str(evidence_root / "dry-run-receipt-b12.json"), source_manifest_sha256=source_manifest_sha256)
            active_backup = active.backup(active_backup_root, binding={"packet": "B12.1", "kind": "rollback-archive", "selected_realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256})
            journal.effect("pre-migration-backup", path=str(active_backup_root), manifest_sha256=_sha256_file(active_backup_root / "manifest.json"), realm_id=realm_id)
            self._consume_authorization("AUTH-LIVE-MIGRATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)

            destination = RuntimeService(self.config.destination_root, display_name=active.realm["display_name"], realm_id=realm_id)
            destination_adapter = RuntimeServiceAdapter(destination)
            try:
                live_config = replace(self.config, require_destination_verification=True, expected_source_manifest_sha256=source_manifest_sha256, expected_source_facts_sha256=inventory["source_facts_sha256"])
                migration = Migrator(live_config, destination_adapter).migrate()
                _write_json(evidence_root / "migration-receipt-b12.json", {"packet": "B12.2", "migration_epoch": 1, "report": migration})
                journal.effect("migration-receipt", path=str(evidence_root / "migration-receipt-b12.json"), source_manifest_sha256=source_manifest_sha256)
                reconciliation = migration["reconciliation"]
                if not reconciliation.get("ok"):
                    raise MigrationError("B12.2 reconciliation failed")
                destination_backup = destination.backup(destination_backup_root, binding={"packet": "B12.2", "kind": "destination", "selected_realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "reconciliation": reconciliation})
                journal.effect("destination-backup", path=str(destination_backup_root), manifest_sha256=_sha256_file(destination_backup_root / "manifest.json"), realm_id=realm_id)
            finally:
                destination.close()

            candidate = restore_backup(destination_backup_root, candidate_root)
            destination_activation_manifest = self.config.destination_root / "activation-manifest.json"
            if destination_activation_manifest.is_file():
                import shutil
                shutil.copy2(destination_activation_manifest, candidate_root / "activation-manifest.json")
            # The manifest carries the destination key path.  Verify again
            # immediately before the authority swap, not merely after copy.
            candidate_verification = verify_restore_candidate(candidate_root)
            destination_binding = candidate_verification["manifest"].get("destination_binding") or {}
            if (destination_binding.get("packet") != "B12.2" or
                    destination_binding.get("selected_realm_id") != realm_id or
                    destination_binding.get("source_manifest_sha256") != source_manifest_sha256 or
                    candidate_verification["manifest"].get("realm_id") != realm_id):
                raise MigrationError("B12.3 destination backup is not bound to the selected live migration")
            self._consume_authorization("AUTH-ACTIVATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            activated = RuntimeServiceAdapter(active).activate_destination(candidate_root, state="active")
            active_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
            active_entry = journal.transition("active", source_manifest_sha256=source_manifest_sha256, destination=str(self.config.destination_root), destination_backup=str(destination_backup_root), activation=activated, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=1)
            _write_json(evidence_root / "activated-destination-b12-active.json", {"packet": "B12.3", "state": "active", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "activation_epoch": 1, "runtime_epoch": active.health()["runtime_epoch"], "database_sha256": _sha256_file(active.store.db_path)})

            self._consume_authorization("AUTH-ROLLBACK-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            restore_backup(active_backup_root, rollback_root)
            rollback_verification = verify_restore_candidate(rollback_root)
            if rollback_verification["manifest"].get("realm_id") != realm_id:
                raise MigrationError("B12.3 rollback backup does not match the selected realm")
            rolled_back = RuntimeServiceAdapter(active).activate_destination(rollback_root, state="rolled_back")
            rollback_entry = journal.transition("rolled_back", predecessor=active_entry["entries"][-1], activation=rolled_back, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=2)
            _write_json(evidence_root / "activated-destination-b12-rollback.json", {"packet": "B12.3", "state": "rolled_back", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "activation_epoch": 2, "runtime_epoch": active.health()["runtime_epoch"], "database_sha256": _sha256_file(active.store.db_path)})

            self._consume_authorization("AUTH-REACTIVATION-B12", source_manifest_sha256=source_manifest_sha256, realm_id=realm_id, journal=journal)
            restore_backup(destination_backup_root, reactivation_root)
            reactivation_verification = verify_restore_candidate(reactivation_root)
            if reactivation_verification["manifest"].get("realm_id") != realm_id:
                raise MigrationError("B12.3 reactivation backup does not match the selected realm")
            reactivated = RuntimeServiceAdapter(active).activate_destination(reactivation_root, state="reactivated")
            final = journal.transition("reactivated", predecessor=rollback_entry["entries"][-1], activation=reactivated, runtime_epoch=active.health()["runtime_epoch"], activation_epoch=3)
            _write_json(evidence_root / "activated-destination-b12-reactivated.json", {"packet": "B12.3", "state": "reactivated", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "activation_epoch": 3, "runtime_epoch": active.health()["runtime_epoch"], "database_sha256": _sha256_file(active.store.db_path)})
            final_snapshot = RuntimeServiceAdapter(active).destination_snapshot()
            identity = {"packet": "B12.4", "realm_id": realm_id, "source_manifest_sha256": source_manifest_sha256, "destination_root": str(active.store.root), "runtime_epoch": active.health()["runtime_epoch"], "activation_epoch": 3, "journal_sha256": _sha256_file(evidence_root / "migration-journal-b12.json"), "source_backup_manifest_sha256": _sha256_file(active_backup_root / "manifest.json"), "destination_backup_manifest_sha256": _sha256_file(destination_backup_root / "manifest.json"), "active_database_sha256": _sha256_file(active.store.db_path), "active_snapshot_counts": {key: len(value) for key, value in final_snapshot.items() if isinstance(value, list)}}
            _write_json(evidence_root / "activated-destination-b12.json", identity)
            return {"packet": "B12", "source_freeze": freeze, "capacity": capacity, "dry_run": dry_run, "migration": migration, "reconciliation": reconciliation, "active_backup": active_backup, "destination_backup": destination_backup, "journal": final, "activation": activated, "rollback": rolled_back, "reactivation": reactivated, "identity": identity, "active_snapshot": active_snapshot, "final_snapshot": final_snapshot}


def run_live_migration(config: MigrationConfig, active_runtime: RuntimeService, authorizations: Mapping[str, Mapping[str, Any]], *, writer_stop: Callable[[], Any]) -> dict[str, Any]:
    """Run the serialized B12 flow against a selected disposable runtime."""
    return LiveMigration(config, active_runtime, authorizations, writer_stop).run()


__all__ = ["LIVE_AUTHORIZATION_IDS", "LiveMigration", "issue_live_authorizations", "run_live_migration"]
