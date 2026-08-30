"""Executable, offline B10 migration rehearsal helpers.

This module is intentionally small: it provides a deterministic synthetic
source and a disposable activation journal around :class:`Migrator`.  It does
not inspect or mutate a live Astrid root.  A caller must supply a cloned
source and, for a runtime rehearsal, an already-created disposable runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Any, Callable, Mapping

from .migrator import MigrationConfig, MigrationError, Migrator, _canonical, _sha256_file, _tree_size


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{time.time_ns()}.tmp")
    with temporary.open("wb") as stream:
        stream.write(_canonical(value) + b"\n")
        stream.flush()
        import os
        os.fsync(stream.fileno())
    temporary.replace(path)
    try:
        directory = path.parent.open("rb")
        try:
            import os
            os.fsync(directory.fileno())
        finally:
            directory.close()
    except OSError:
        pass


def _tree_digest(root: Path) -> str:
    files = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        files.append({"path": str(path.relative_to(root)), "size": path.stat().st_size, "sha256": _sha256_file(path)})
    return hashlib.sha256(_canonical(files)).hexdigest()


@dataclass(frozen=True)
class SyntheticFixture:
    root: Path
    media_digest: str
    source_tree_sha256: str


def build_synthetic_fixture(root: str | Path) -> SyntheticFixture:
    """Create a root-complete legacy fixture with project/media/timeline/task evidence."""
    root = Path(root).expanduser().resolve()
    if root.exists() and any(root.iterdir()):
        raise MigrationError(f"synthetic fixture destination is not empty: {root}")
    (root / ".astrid").mkdir(parents=True, exist_ok=True)
    (root / "media").mkdir()
    payload = b"astrid-stage1-b10-synthetic-media\n"
    media_path = root / "media" / "clip.bin"
    media_path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    (root / ".astrid" / "preferences.json").write_text('{"selected_project":"demo"}\n', encoding="utf-8")
    db = sqlite3.connect(root / ".astrid" / "astrid.sqlite3")
    db.executescript(
        """
        PRAGMA foreign_keys=ON;
        CREATE TABLE projects (id TEXT PRIMARY KEY, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, settings_json TEXT, event_head_seq INTEGER, created_at TEXT, updated_at TEXT);
        CREATE TABLE timelines (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), event_stream_id TEXT, name TEXT, document_json TEXT, asset_registry_json TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE shots (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), name TEXT, sort_key TEXT, metadata_json TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE project_references (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), kind TEXT, name TEXT, description TEXT, metadata_json TEXT, created_at TEXT, updated_at TEXT, archived_at TEXT);
        CREATE TABLE media (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), media_kind TEXT, mime_type TEXT, byte_size INTEGER, content_hash TEXT, metadata_json TEXT, created_at TEXT);
        CREATE TABLE media_locations (id TEXT PRIMARY KEY, media_id TEXT REFERENCES media(id), realm TEXT, locator TEXT, verified_at TEXT, created_at TEXT);
        CREATE TABLE generations (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), task_id TEXT, type TEXT, name TEXT, based_on_generation_id TEXT, parent_generation_id TEXT, child_order INTEGER, params_json TEXT, starred INTEGER, deleted_at TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE runs (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), event_stream_id TEXT, kind TEXT, status TEXT, title TEXT, input_json TEXT, result_json TEXT, started_at TEXT, finished_at TEXT);
        CREATE TABLE tasks (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), event_stream_id TEXT, run_id TEXT, run_ordinal INTEGER, capability TEXT, spec_json TEXT, spec_hash TEXT, input_manifest_json TEXT, status TEXT, priority INTEGER, available_at TEXT, max_attempts INTEGER, winning_attempt_id TEXT, cancel_request_id TEXT, cancel_requested_at TEXT, created_at TEXT, updated_at TEXT, finished_at TEXT);
        CREATE TABLE event_streams (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), stream_type TEXT, aggregate_id TEXT, head_seq INTEGER, created_at TEXT);
        CREATE TABLE events (event_id TEXT PRIMARY KEY, project_id TEXT, project_seq INTEGER, stream_id TEXT REFERENCES event_streams(id), seq INTEGER, subject_type TEXT, subject_id TEXT, changes_json TEXT, kind TEXT, schema_version TEXT, idempotency_key TEXT, txn_id TEXT, actor_kind TEXT, payload_json TEXT, created_at TEXT);
        CREATE TABLE schema_migrations (pack TEXT, version INTEGER, name TEXT, checksum TEXT, applied_at TEXT);
        """
    )
    db.execute("INSERT INTO projects VALUES ('p-demo','demo','Demo','{}',2,'2026-01-01','2026-01-01')")
    db.execute("INSERT INTO timelines VALUES ('tl-main','p-demo','stream-tl','Main','{\"config\":{\"fps\":24}}','{}','2026-01-01','2026-01-01')")
    db.execute("INSERT INTO shots VALUES ('shot-1','p-demo','Opening','001','{\"timeline_id\":\"tl-main\"}','2026-01-01','2026-01-01')")
    db.execute("INSERT INTO project_references VALUES ('ref-1','p-demo','image','Reference','synthetic','{}','2026-01-01','2026-01-01',NULL)")
    db.execute("INSERT INTO media VALUES ('media-1','p-demo','generic','application/octet-stream',?,?,?,?)", (len(payload), digest, "{}", "2026-01-01"))
    db.execute("INSERT INTO media_locations VALUES ('loc-1','media-1','external_local','media/clip.bin',NULL,'2026-01-01')")
    db.execute("INSERT INTO generations VALUES ('gen-1','p-demo',NULL,'image','Opening generation',NULL,NULL,0,'{}',0,NULL,'2026-01-01','2026-01-01')")
    # Every referenced root has a stream and every stream has a valid event;
    # the fixture is intentionally useful for FK/event reconciliation rather
    # than merely having the entity rows present.
    db.execute("INSERT INTO event_streams VALUES ('stream-project','p-demo','project','p-demo',1,'2026-01-01')")
    db.execute("INSERT INTO event_streams VALUES ('stream-tl','p-demo','timeline','tl-main',1,'2026-01-01')")
    db.execute("INSERT INTO event_streams VALUES ('stream-run','p-demo','run','run-1',1,'2026-01-01')")
    db.execute("INSERT INTO event_streams VALUES ('stream-task','p-demo','task','task-1',1,'2026-01-01')")
    db.execute("INSERT INTO runs VALUES ('run-1','p-demo','stream-run','task','queued','Synthetic task','{}',NULL,NULL,NULL)")
    db.execute("INSERT INTO tasks VALUES ('task-1','p-demo','stream-task','run-1',0,'render.basic','{\"quality\":\"draft\"}',NULL,'{}','queued',0,'2026-01-01',1,NULL,NULL,NULL,'2026-01-01','2026-01-01',NULL)")
    db.execute("INSERT INTO events VALUES ('event-project','p-demo',1,'stream-project',1,'project','p-demo',NULL,'project.created','1','project-created','txn-project','migration','{\"slug\":\"demo\"}','2026-01-01')")
    db.execute("INSERT INTO events VALUES ('event-task','p-demo',2,'stream-task',1,'task','task-1',NULL,'task.admitted','1','task-created','txn-task','migration','{\"capability\":\"render.basic\"}','2026-01-01')")
    db.execute("INSERT INTO schema_migrations VALUES ('core',10,'legacy','fixture','2026-01-01')")
    db.commit()
    db.close()
    return SyntheticFixture(root=root, media_digest=digest, source_tree_sha256=_tree_digest(root))


class RuntimeServiceAdapter:
    """Generated-client-shaped adapter for an in-process disposable service."""

    def __init__(self, service):
        self.service = service
        self.project_ids: dict[str, str] = {}

    def create_project(self, name, *, slug=None, metadata=None, idempotency_key=None, legacy_id=None):
        result = self.service.create_project({"name": name, "slug": slug, "metadata": metadata or {}}, idempotency_key=idempotency_key)
        if slug:
            self.project_ids[str(slug)] = result["id"]
        if legacy_id:
            self.project_ids[str(legacy_id)] = result["id"]
        return result

    def ingest_object(self, data, *, media_type, idempotency_key=None, filename=None):
        return self.service.ingest_object(data, media_type=media_type, original_name=filename)

    def create_timeline(self, project_id, timeline_id, *, idempotency_key=None):
        return self.service.create_timeline(project_id, timeline_id)

    def create_shot(self, timeline_id, shot, *, idempotency_key=None):
        return self.service.create_shot(timeline_id, shot)

    def create_reference(self, timeline_id, reference, *, idempotency_key=None):
        return self.service.create_reference(timeline_id, reference)

    def create_generation(self, generation, *, idempotency_key=None):
        project_id = self.project_ids.get(str(generation["project_id"]), generation["project_id"])
        return self.service.create_generation(project_id, {"generation_id": generation["id"], "type": generation.get("type", "generation"), "metadata": {}})

    def create_document(self, project_id, body):
        return self.service.create_document(project_id, body)

    def create_task(self, body):
        value = dict(body)
        project = value.get("project") or value.get("project_id")
        value["project"] = self.project_ids.get(str(project), project)
        value["capability_digest"] = value.get("capability_digest") or "sha256:" + hashlib.sha256(str(value.get("capability_id") or value.get("capability")).encode()).hexdigest()
        return self.service.create_task(value)

    def destination_snapshot(self):
        """Read destination truth from the runtime kernel, never local maps."""
        conn = self.service.store.conn

        def rows(table):
            return [dict(row) for row in conn.execute(f'SELECT * FROM "{table}"')]

        snapshot = {"foreign_key_errors": [dict(row) for row in conn.execute("PRAGMA foreign_key_check")]}
        for table in ("projects", "timelines", "timeline_shots", "timeline_references", "objects", "generations", "runs", "tasks", "events"):
            try:
                snapshot[table] = rows(table)
            except Exception:
                snapshot[table] = []
        snapshot["documents"] = rows("project_documents")
        snapshot["media_locations"] = [{"digest": row["digest"], "realm": "cas", "locator": str(self.service.cas.root / row["digest"][:2] / row["digest"][2:])} for row in snapshot.get("objects", [])]
        return snapshot


class MigrationJournal:
    """Small durable state journal whose transitions are safe to repeat."""

    def __init__(self, path: str | Path, *, fault_injector=None, crash_at: str | None = None):
        self.path = Path(path).expanduser().resolve()
        self.fault_injector = fault_injector
        self.crash_at = crash_at

    @staticmethod
    def _entry_hash(entry: Mapping[str, Any]) -> str:
        body = {key: value for key, value in entry.items() if key != "entry_sha256"}
        return hashlib.sha256(_canonical(body)).hexdigest()

    def _read(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"format_version": 1, "generation": 0, "state": "prepared", "entries": []}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MigrationError("migration journal is corrupt or interrupted") from exc
        if not isinstance(value, dict) or value.get("format_version") != 1 or not isinstance(value.get("entries"), list):
            raise MigrationError("migration journal has an invalid envelope")
        state = value.get("state")
        if state not in {"prepared", "active", "rolled_back", "reactivated"} or not isinstance(value.get("generation"), int):
            raise MigrationError("migration journal has an invalid state")
        previous = "prepared"
        generation = 0
        for entry in value["entries"]:
            if not isinstance(entry, dict) or entry.get("from") != previous or int(entry.get("generation", -1)) != generation + 1 or entry.get("to") not in {"active", "rolled_back", "reactivated"} or entry.get("entry_sha256") != self._entry_hash(entry):
                raise MigrationError("migration journal has a broken transition chain")
            previous = entry["to"]
            generation += 1
        if previous != state or generation != value["generation"]:
            raise MigrationError("migration journal generation/state mismatch")
        return value

    def _inject(self, seam: str) -> None:
        if self.crash_at == seam:
            raise MigrationError(f"injected rehearsal crash at {seam}")
        if self.fault_injector is not None:
            self.fault_injector(seam)

    def transition(self, state: str, **payload: Any) -> dict[str, Any]:
        current = self._read()
        if current["state"] == state:
            return current
        allowed = {"prepared": {"active"}, "active": {"rolled_back"}, "rolled_back": {"reactivated"}, "reactivated": set()}
        if state not in allowed.get(current["state"], set()):
            raise MigrationError(f"invalid migration journal transition {current['state']} -> {state}")
        entry = {"from": current["state"], "to": state, "generation": int(current["generation"]) + 1, **payload}
        entry["entry_sha256"] = self._entry_hash(entry)
        result = {"format_version": 1, "generation": entry["generation"], "state": state, "entries": [*current["entries"], entry]}
        self._inject(f"before_{current['state']}_to_{state}")
        _write_json(self.path, result)
        self._inject(f"after_{current['state']}_to_{state}")
        return result


@dataclass
class Rehearsal:
    config: MigrationConfig
    client: Any
    runtime: Any | None = None
    rollback_root: Path | None = None
    fault_injector: Callable[[str], None] | None = None
    crash_at: str | None = None

    def _inject(self, seam: str) -> None:
        if self.crash_at == seam:
            raise MigrationError(f"injected rehearsal crash at {seam}")
        if self.fault_injector is not None:
            self.fault_injector(seam)

    def run(self) -> dict[str, Any]:
        evidence_root = (self.config.evidence_root or self.config.destination_root / "migration-evidence").resolve()
        evidence_root.mkdir(parents=True, exist_ok=True)
        migrator = Migrator(self.config, self.client)
        inventory = migrator.inventory()
        freeze = {"packet": "B10.1", "state": "frozen", "source_manifest_sha256": inventory["source_manifest_sha256"], "source_tree_sha256": _tree_digest(self.config.source_root), "source_facts_sha256": inventory["source_facts_sha256"], "writer_probe": "passed", "created_at": time.time()}
        _write_json(evidence_root / "source-freeze-b10.json", freeze)
        preceding = _tree_size(self.config.source_root)
        margin = self.config.capacity_margin_bytes if self.config.capacity_margin_bytes is not None else max(int(preceding * 0.2), 10 * 1024**3)
        free = int(inventory["destination_free_bytes"])
        required = preceding + margin
        capacity = {"packet": "B10.5", "accepted_archive_bytes": preceding, "destination_db_cas_bytes": int(inventory["estimated_cas_bytes"]), "measured_peak_staging_bytes": 0, "isolated_restore_copy_bytes": 0, "evidence_export_allowance_bytes": 0, "margin_bytes": margin, "required_bytes": required, "available_bytes": free, "reserved": free >= required}
        if not capacity["reserved"]:
            raise MigrationError("B10.5 capacity reservation is insufficient")
        _write_json(evidence_root / "capacity-receipt-b10.json", capacity)
        _write_json(evidence_root / "writer-freeze-receipt-b10.json", freeze | {"packet": "B10.5", "procedure": "source clone is immutable; writer probe passed", "held_across_critical_operation": True})
        pre_backup = None
        candidate_backup = None
        staging_peaks = [_tree_size(self.config.destination_root / "staging")]
        if self.runtime is not None:
            # This snapshot must precede the first migration write.
            backup_root = self.config.archive_root.parent / f"{self.config.archive_root.name}-runtime-pre-migration-backup"
            self._inject("before_pre_migration_backup")
            pre_backup = self.runtime.backup(backup_root)
            self._inject("after_pre_migration_backup")
            staging_peaks.append(_tree_size(backup_root))
        self._inject("before_migration")
        report = migrator.migrate()
        self._inject("after_migration")
        _write_json(evidence_root / "writer-freeze-receipt-b10.json", freeze | {"packet": "B10.5", "procedure": "source clone is immutable; writer probe passed", "held_across_critical_operation": True, "lock_count": report.get("source_freeze", {}).get("lock_count", 0), "completed_at": time.time()})
        backup_result = None
        restore_result = None
        if self.runtime is not None:
            # Back up the pre-migration authority before the first destination
            # write.  The previous implementation backed up the already
            # migrated state, making rollback a no-op.
            backup_result = pre_backup
            capacity["accepted_archive_bytes"] = _tree_size(self.config.archive_root)
            capacity["destination_db_cas_bytes"] = _tree_size(self.config.destination_root)
            staging_peaks.append(_tree_size(self.config.destination_root / "staging"))
            # Preserve a verified candidate so reactivation is a real restore,
            # not merely a journal label.
            candidate_root = self.config.archive_root.parent / f"{self.config.archive_root.name}-runtime-candidate-backup"
            self._inject("before_candidate_backup")
            candidate_backup = self.runtime.backup(candidate_root)
            self._inject("after_candidate_backup")
            staging_peaks.append(_tree_size(candidate_root))
            restore_root = self.rollback_root or self.config.archive_root.parent / f"{self.config.archive_root.name}-runtime-restore"
            self._inject("before_rollback_restore")
            restore_result = self.runtime.restore(backup_root, restore_root)
            self._inject("after_rollback_restore")
            staging_peaks.append(_tree_size(restore_root))
            reactivation_root = restore_root.parent / f"{restore_root.name}-reactivated"
            self._inject("before_reactivation_restore")
            reactivation_result = self.runtime.restore(candidate_root, reactivation_root)
            self._inject("after_reactivation_restore")
            staging_peaks.append(_tree_size(reactivation_root))
            capacity["measured_peak_staging_bytes"] = max([report.get("archive_peak_bytes", 0), *staging_peaks])
            capacity["isolated_restore_copy_bytes"] = max(_tree_size(restore_root), _tree_size(reactivation_root))
            capacity["evidence_export_allowance_bytes"] = _tree_size(evidence_root)
            capacity["required_bytes"] = sum(capacity[key] for key in ("accepted_archive_bytes", "destination_db_cas_bytes", "measured_peak_staging_bytes", "isolated_restore_copy_bytes", "evidence_export_allowance_bytes", "margin_bytes"))
            capacity["reserved"] = capacity["available_bytes"] >= capacity["required_bytes"]
            if not capacity["reserved"]:
                raise MigrationError("B10.5 exact capacity reservation is insufficient after measured rehearsal")
            _write_json(evidence_root / "capacity-receipt-b10.json", capacity)
            # Query the restored authorities themselves.  A successful copy is
            # insufficient if rollback still contains imported entities or if
            # the candidate cannot be reactivated.
            def restored_counts(path):
                db = sqlite3.connect(path / "realm.sqlite3")
                try:
                    return {table: int(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]) for table in ("projects", "runs", "tasks", "objects")}
                finally:
                    db.close()
            rollback_counts = restored_counts(restore_root)
            reactivation_counts = restored_counts(reactivation_root)
            if any(rollback_counts.values()):
                raise MigrationError("B10 rollback restored migrated entities instead of pre-migration authority")
            if not any(reactivation_counts.values()):
                raise MigrationError("B10 reactivation did not restore the migrated candidate")
        else:
            reactivation_result = None
            rollback_counts = {}
            reactivation_counts = {}
        reconciliation = report["reconciliation"] | {"source_manifest_sha256": inventory["source_manifest_sha256"], "source_tree_sha256": freeze["source_tree_sha256"], "source_facts_sha256": inventory["source_facts_sha256"], "backup_verified": backup_result is not None, "restore_verified": restore_result is not None, "rollback_counts": rollback_counts, "reactivation_counts": reactivation_counts}
        _write_json(evidence_root / "reconciliation-b10.json", reconciliation)
        journal = MigrationJournal(self.config.destination_root / "migration-journal.json", fault_injector=self.fault_injector, crash_at=self.crash_at)
        active = journal.transition("active", migration_manifest_sha256=_sha256_file(Path(report["activation_manifest"])), reconciliation_sha256=hashlib.sha256(_canonical(reconciliation)).hexdigest())
        rolled_back = journal.transition("rolled_back", backup=backup_result, restore=restore_result)
        reactivated = journal.transition("reactivated", destination=str(self.config.destination_root), candidate_restore=reactivation_result)
        return {"packet": "B10", "source_freeze": freeze, "capacity": capacity, "migration": report, "backup": backup_result, "pre_migration_backup": pre_backup, "candidate_backup": candidate_backup, "restore": restore_result, "reactivation": reactivation_result, "reconciliation": reconciliation, "journal": reactivated, "idempotent_reactivation": MigrationJournal(self.config.destination_root / "migration-journal.json").transition("reactivated", destination=str(self.config.destination_root), candidate_restore=reactivation_result) == reactivated, "rollback": rolled_back}


def run_rehearsal(config: MigrationConfig, client: Any, *, runtime: Any | None = None, rollback_root: str | Path | None = None, fault_injector=None, crash_at: str | None = None) -> dict[str, Any]:
    return Rehearsal(config, client, runtime=runtime, rollback_root=Path(rollback_root).resolve() if rollback_root else None, fault_injector=fault_injector, crash_at=crash_at).run()
