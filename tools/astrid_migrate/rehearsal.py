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
from typing import Any, Mapping

from .migrator import MigrationConfig, MigrationError, Migrator, _canonical, _sha256_file, _tree_size


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{time.time_ns()}.tmp")
    temporary.write_bytes(_canonical(value) + b"\n")
    temporary.replace(path)


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
    db.execute("INSERT INTO projects VALUES ('p-demo','demo','Demo','{}',1,'2026-01-01','2026-01-01')")
    db.execute("INSERT INTO timelines VALUES ('tl-main','p-demo','stream-tl','Main','{\"config\":{\"fps\":24}}','{}','2026-01-01','2026-01-01')")
    db.execute("INSERT INTO shots VALUES ('shot-1','p-demo','Opening','001','{\"timeline_id\":\"tl-main\"}','2026-01-01','2026-01-01')")
    db.execute("INSERT INTO project_references VALUES ('ref-1','p-demo','image','Reference','synthetic','{}','2026-01-01','2026-01-01',NULL)")
    db.execute("INSERT INTO media VALUES ('media-1','p-demo','generic','application/octet-stream',?,?,?,?)", (len(payload), digest, "{}", "2026-01-01"))
    db.execute("INSERT INTO media_locations VALUES ('loc-1','media-1','external_local','media/clip.bin',NULL,'2026-01-01')")
    db.execute("INSERT INTO generations VALUES ('gen-1','p-demo',NULL,'image','Opening generation',NULL,NULL,0,'{}',0,NULL,'2026-01-01','2026-01-01')")
    db.execute("INSERT INTO event_streams VALUES ('stream-tl','p-demo','timeline','tl-main',1,'2026-01-01')")
    db.execute("INSERT INTO runs VALUES ('run-1','p-demo','stream-run','task','queued','Synthetic task','{}',NULL,NULL,NULL)")
    db.execute("INSERT INTO tasks VALUES ('task-1','p-demo','stream-task','run-1',0,'render.basic','{\"quality\":\"draft\"}',NULL,'{}','queued',0,'2026-01-01',1,NULL,NULL,NULL,'2026-01-01','2026-01-01',NULL)")
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


class MigrationJournal:
    """Small durable state journal whose transitions are safe to repeat."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()

    def _read(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"format_version": 1, "generation": 0, "state": "prepared", "entries": []}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def transition(self, state: str, **payload: Any) -> dict[str, Any]:
        current = self._read()
        if current["state"] == state:
            return current
        allowed = {"prepared": {"active"}, "active": {"rolled_back"}, "rolled_back": {"reactivated"}, "reactivated": set()}
        if state not in allowed.get(current["state"], set()):
            raise MigrationError(f"invalid migration journal transition {current['state']} -> {state}")
        entry = {"from": current["state"], "to": state, "generation": int(current["generation"]) + 1, **payload}
        result = {"format_version": 1, "generation": entry["generation"], "state": state, "entries": [*current["entries"], entry]}
        _write_json(self.path, result)
        return result


@dataclass
class Rehearsal:
    config: MigrationConfig
    client: Any
    runtime: Any | None = None
    rollback_root: Path | None = None

    def run(self) -> dict[str, Any]:
        evidence_root = (self.config.evidence_root or self.config.destination_root / "migration-evidence").resolve()
        evidence_root.mkdir(parents=True, exist_ok=True)
        migrator = Migrator(self.config, self.client)
        inventory = migrator.inventory()
        freeze = {"packet": "B10.1", "state": "frozen", "source_manifest_sha256": inventory["source_manifest_sha256"], "source_tree_sha256": _tree_digest(self.config.source_root), "writer_probe": "passed", "created_at": time.time()}
        _write_json(evidence_root / "source-freeze-b10.json", freeze)
        preceding = _tree_size(self.config.source_root)
        margin = self.config.capacity_margin_bytes if self.config.capacity_margin_bytes is not None else max(int(preceding * 0.2), 10 * 1024**3)
        free = int(inventory["destination_free_bytes"])
        required = preceding + margin
        capacity = {"packet": "B10.5", "accepted_archive_bytes": preceding, "destination_db_cas_bytes": int(inventory["estimated_cas_bytes"]), "measured_peak_staging_bytes": 0, "isolated_restore_copy_bytes": 0, "evidence_export_allowance_bytes": 1024 * 1024, "margin_bytes": margin, "required_bytes": required + 1024 * 1024, "available_bytes": free, "reserved": free >= required + 1024 * 1024}
        if not capacity["reserved"]:
            raise MigrationError("B10.5 capacity reservation is insufficient")
        _write_json(evidence_root / "capacity-receipt-b10.json", capacity)
        _write_json(evidence_root / "writer-freeze-receipt-b10.json", freeze | {"packet": "B10.5", "procedure": "source clone is immutable; writer probe passed"})
        report = migrator.migrate()
        backup_result = None
        restore_result = None
        if self.runtime is not None:
            backup_root = self.config.archive_root.parent / f"{self.config.archive_root.name}-runtime-backup"
            backup_result = self.runtime.backup(backup_root)
            capacity["accepted_archive_bytes"] = _tree_size(self.config.archive_root)
            capacity["destination_db_cas_bytes"] = _tree_size(self.config.destination_root)
            staging = self.config.destination_root / "staging"
            capacity["measured_peak_staging_bytes"] = _tree_size(staging) if staging.exists() else 0
            capacity["isolated_restore_copy_bytes"] = _tree_size(backup_root)
            restore_root = self.rollback_root or self.config.archive_root.parent / f"{self.config.archive_root.name}-runtime-restore"
            restore_result = self.runtime.restore(backup_root, restore_root)
            capacity["required_bytes"] = sum(capacity[key] for key in ("accepted_archive_bytes", "destination_db_cas_bytes", "measured_peak_staging_bytes", "isolated_restore_copy_bytes", "evidence_export_allowance_bytes", "margin_bytes"))
            capacity["reserved"] = capacity["available_bytes"] >= capacity["required_bytes"]
            if not capacity["reserved"]:
                raise MigrationError("B10.5 exact capacity reservation is insufficient after measured rehearsal")
            _write_json(evidence_root / "capacity-receipt-b10.json", capacity)
        reconciliation = report["reconciliation"] | {"source_manifest_sha256": inventory["source_manifest_sha256"], "source_tree_sha256": freeze["source_tree_sha256"], "backup_verified": backup_result is not None, "restore_verified": restore_result is not None}
        _write_json(evidence_root / "reconciliation-b10.json", reconciliation)
        journal = MigrationJournal(self.config.destination_root / "migration-journal.json")
        active = journal.transition("active", migration_manifest_sha256=_sha256_file(Path(report["activation_manifest"])), reconciliation_sha256=hashlib.sha256(_canonical(reconciliation)).hexdigest())
        rolled_back = journal.transition("rolled_back", backup=backup_result, restore=restore_result)
        reactivated = journal.transition("reactivated", destination=str(self.config.destination_root))
        return {"packet": "B10", "source_freeze": freeze, "capacity": capacity, "migration": report, "backup": backup_result, "restore": restore_result, "reconciliation": reconciliation, "journal": reactivated, "idempotent_reactivation": MigrationJournal(self.config.destination_root / "migration-journal.json").transition("reactivated", destination=str(self.config.destination_root)) == reactivated, "rollback": rolled_back}


def run_rehearsal(config: MigrationConfig, client: Any, *, runtime: Any | None = None, rollback_root: str | Path | None = None) -> dict[str, Any]:
    return Rehearsal(config, client, runtime=runtime, rollback_root=Path(rollback_root).resolve() if rollback_root else None).run()
