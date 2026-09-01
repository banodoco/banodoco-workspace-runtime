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
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
from typing import Any, Callable, Mapping

from .migrator import MigrationConfig, MigrationError, Migrator, _canonical, _sha256_file, _tree_size
from .capacity import (
    _has_symlink_component,
    _open_directory_chain,
    capture_activation_path,
    close_activation_path,
    revalidate_activation_parent,
    revalidate_activation_path,
)
from .boundary import atomic_json_write as _atomic_json_write, capture_parent as _capture_parent, close_pinned as _close_pinned, ensure_directory as _ensure_directory, validate_parent as _validate_parent, _open_relative, _connection_from_fd, _sha256_at, pin_directory as _pin_directory, RealmCatalog, now


def _write_json(path: Path, value: Mapping[str, Any], *, identity: Mapping[str, Any] | None = None) -> None:
    """Publish evidence/journal bytes through a retained parent descriptor."""
    own = identity is None
    pinned = identity or _capture_parent(path)
    try:
        _atomic_json_write(path, _canonical(value) + b"\n", identity=pinned)
    finally:
        if own:
            _close_pinned(pinned)


def _read_json_pinned(path: Path, *, identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
    target = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    own_identity = identity is None
    identity = identity or _capture_parent(target)
    fd = -1
    try:
        _validate_parent(target, identity, allow_parent_appeared=True)
        parent = Path(str(identity["parent"]))
        fd = _open_relative(int(identity["_parent_fd"]), target.relative_to(parent))
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise MigrationError(f"migration journal is not a regular file: {target}")
        data = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        result = json.loads(bytes(data).decode("utf-8"))
        _validate_parent(target, identity, allow_parent_appeared=True)
        if not isinstance(result, dict):
            raise MigrationError(f"migration journal is not an object: {target}")
        return result
    except FileNotFoundError:
        raise
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise MigrationError(f"migration journal is corrupt or interrupted: {target}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if own_identity:
            _close_pinned(identity)


def _hash_file_pinned(path: Path) -> str:
    target = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
    identity = _capture_parent(target)
    fd = -1
    try:
        _validate_parent(target, identity, allow_parent_appeared=True)
        parent = Path(str(identity["parent"]))
        fd = _open_relative(int(identity["_parent_fd"]), target.relative_to(parent))
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise MigrationError(f"artifact is not a regular file: {target}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        _validate_parent(target, identity, allow_parent_appeared=True)
        return digest.hexdigest()
    finally:
        if fd >= 0:
            os.close(fd)
        _close_pinned(identity)


def _tree_digest(root: Path) -> str:
    files = []
    for path in sorted(p for p in root.rglob("*") if (p.is_file() or p.is_symlink())):
        if path.is_symlink():
            files.append({"path": str(path.relative_to(root)), "kind": "symlink", "target": os.readlink(path)})
        else:
            files.append({"path": str(path.relative_to(root)), "kind": "file", "size": path.stat().st_size, "sha256": _sha256_file(path)})
    return hashlib.sha256(_canonical(files)).hexdigest()


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _exists_at(directory_fd: int, name: str) -> bool:
    """Check one directory entry without resolving a path component."""
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _copy_file_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str) -> None:
    """Copy one regular file using only descriptors and relative names."""
    source = os.open(source_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_fd)
    destination = -1
    try:
        source_stat = os.fstat(source)
        if not stat.S_ISREG(source_stat.st_mode):
            raise MigrationError(f"activation source is not a regular file: {source_name}")
        destination = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            stat.S_IRUSR | stat.S_IWUSR,
            dir_fd=destination_fd,
        )
        while True:
            chunk = os.read(source, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                view = view[written:]
        os.fchmod(destination, stat.S_IMODE(source_stat.st_mode))
        os.fsync(destination)
    finally:
        try:
            os.close(source)
        finally:
            if destination >= 0:
                os.close(destination)


def _copy_tree_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str) -> None:
    """Recursively copy a tree while refusing symlinks and path reopening."""
    source = os.open(source_name, _DIR_FLAGS, dir_fd=source_fd)
    try:
        os.mkdir(destination_name, 0o700, dir_fd=destination_fd)
        destination = os.open(destination_name, _DIR_FLAGS, dir_fd=destination_fd)
        try:
            for entry in os.scandir(source):
                name = entry.name
                entry_stat = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(entry_stat.st_mode):
                    raise MigrationError(f"activation source contains a symlink: {source_name}/{name}")
                if stat.S_ISDIR(entry_stat.st_mode):
                    _copy_tree_at(source, name, destination, name)
                elif stat.S_ISREG(entry_stat.st_mode):
                    _copy_file_at(source, name, destination, name)
                else:
                    raise MigrationError(f"activation source contains an unsupported file: {source_name}/{name}")
            os.fsync(destination)
        finally:
            os.close(destination)
    finally:
        os.close(source)


def _remove_tree_at(directory_fd: int, name: str) -> None:
    """Remove a temporary activation tree through its pinned parent FD."""
    try:
        child = os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return
    try:
        for entry in os.scandir(child):
            child_name = entry.name
            entry_stat = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(entry_stat.st_mode):
                _remove_tree_at(child, child_name)
            elif stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode):
                os.unlink(child_name, dir_fd=child)
            else:
                raise MigrationError(f"activation temporary contains an unsupported file: {name}/{child_name}")
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=directory_fd)


def _mkdir_at(directory_fd: int, prefix: str) -> tuple[str, int]:
    """Create a private temporary directory below a pinned parent."""
    for attempt in range(100):
        name = f"{prefix}{os.getpid()}-{time.time_ns()}-{attempt}"
        try:
            os.mkdir(name, 0o700, dir_fd=directory_fd)
        except FileExistsError:
            continue
        return name, os.open(name, _DIR_FLAGS, dir_fd=directory_fd)
    raise MigrationError("activation temporary directory could not be allocated")


def _rename_at(directory_fd: int, source_name: str, destination_name: str) -> None:
    """Atomic same-directory rename plus directory durability."""
    try:
        os.rename(source_name, destination_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        raise MigrationError(f"atomic activation rename failed: {source_name} -> {destination_name}") from exc


def _pin_candidate(candidate: Path) -> tuple[int, int, os.stat_result, os.stat_result]:
    """Pin candidate parent/root before verification and source reads."""
    parent_fd = _open_directory_chain(candidate.parent)
    try:
        parent_stat = os.fstat(parent_fd)
        root_fd = os.open(candidate.name, _DIR_FLAGS, dir_fd=parent_fd)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            os.close(root_fd)
            raise MigrationError(f"candidate realm is not an ordinary directory: {candidate}")
        return parent_fd, root_fd, parent_stat, root_stat
    except Exception:
        os.close(parent_fd)
        raise


def _assert_pinned_candidate(candidate: Path, parent_fd: int, root_fd: int, parent_stat: os.stat_result, root_stat: os.stat_result) -> None:
    """Reject candidate parent/root swaps observed during verification."""
    if _has_symlink_component(candidate.parent):
        raise MigrationError(f"candidate parent changed to a symlink: {candidate.parent}")
    current_parent = os.fstat(parent_fd)
    current_root = os.fstat(root_fd)
    if (current_parent.st_dev, current_parent.st_ino, current_parent.st_mode) != (parent_stat.st_dev, parent_stat.st_ino, parent_stat.st_mode):
        raise MigrationError(f"candidate parent identity changed: {candidate.parent}")
    # The retained fd protects source reads, but the lexical name is also part
    # of the request identity. Reject an ordinary directory replacement, not
    # just a symlink replacement.
    try:
        named_parent = os.stat(candidate.parent, follow_symlinks=False)
    except OSError as exc:
        raise MigrationError(f"candidate parent identity changed: {candidate.parent}") from exc
    if (named_parent.st_dev, named_parent.st_ino, named_parent.st_mode) != (parent_stat.st_dev, parent_stat.st_ino, parent_stat.st_mode):
        raise MigrationError(f"candidate lexical parent identity changed: {candidate.parent}")
    if (current_root.st_dev, current_root.st_ino, current_root.st_mode) != (root_stat.st_dev, root_stat.st_ino, root_stat.st_mode):
        raise MigrationError(f"candidate identity changed: {candidate}")


def _retarget_runtime_paths(runtime: Any, target: Path) -> None:
    """Move path metadata to the published name; open DB/locks stay pinned."""
    store = runtime.store
    store.root = target
    store.lock_path = target / "owner.lock"
    store.db_path = target / "realm.sqlite3"
    store.cas_root = target / "cas" / "sha256"
    store.staging_root = target / "staging"
    runtime.cas.root = store.cas_root


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
        CREATE TABLE media_references (id TEXT PRIMARY KEY, reference_id TEXT REFERENCES project_references(id), media_id TEXT REFERENCES media(id), role TEXT, context_task_id TEXT REFERENCES tasks(id), ordinal INTEGER, is_primary INTEGER, metadata_json TEXT, created_at TEXT);
        CREATE TABLE media_relations (from_media_id TEXT REFERENCES media(id), to_media_id TEXT REFERENCES media(id), kind TEXT, ordinal INTEGER, metadata_json TEXT, created_at TEXT, PRIMARY KEY(from_media_id, to_media_id, kind, ordinal));
        CREATE TABLE reference_links (from_reference_id TEXT REFERENCES project_references(id), to_reference_id TEXT REFERENCES project_references(id), kind TEXT, metadata_json TEXT, created_at TEXT, PRIMARY KEY(from_reference_id, to_reference_id, kind));
        CREATE TABLE generation_variants (id TEXT PRIMARY KEY, generation_id TEXT REFERENCES generations(id), media_id TEXT REFERENCES media(id), variant_type TEXT, name TEXT, params_json TEXT, is_primary INTEGER, starred INTEGER, viewed_at TEXT, created_at TEXT);
        CREATE TABLE shot_items (id TEXT PRIMARY KEY, shot_id TEXT REFERENCES shots(id), media_id TEXT REFERENCES media(id), sort_key TEXT, source_frame INTEGER, metadata_json TEXT, created_at TEXT);
        CREATE TABLE task_dependencies (task_id TEXT REFERENCES tasks(id), depends_on_task_id TEXT REFERENCES tasks(id), kind TEXT, ordinal INTEGER, PRIMARY KEY(task_id, depends_on_task_id, kind));
        CREATE TABLE task_outputs (task_id TEXT REFERENCES tasks(id), ordinal INTEGER, role TEXT, media_id TEXT REFERENCES media(id), is_primary INTEGER, params_json TEXT, created_at TEXT, PRIMARY KEY(task_id, ordinal));
        CREATE TABLE execution_attempts (id TEXT PRIMARY KEY, task_id TEXT REFERENCES tasks(id), attempt_no INTEGER, executor_id TEXT, status TEXT, status_version INTEGER, lease_id TEXT, lease_expires_at TEXT, heartbeat_counter INTEGER, last_heartbeat_at TEXT, progress_json TEXT, error_json TEXT, created_at TEXT, updated_at TEXT, finished_at TEXT);
        CREATE TABLE command_receipts (project_id TEXT REFERENCES projects(id), idempotency_key TEXT, request_hash TEXT, command_kind TEXT, txn_id TEXT, primary_stream_id TEXT, resulting_stream_seq INTEGER, first_project_seq INTEGER, last_project_seq INTEGER, event_ids_json TEXT, result_json TEXT, created_at TEXT, PRIMARY KEY(project_id, idempotency_key));
        CREATE TABLE evidence_items (id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id), task_id TEXT REFERENCES tasks(id), kind TEXT, summary TEXT, data_json TEXT, media_id TEXT REFERENCES media(id), created_at TEXT);
        CREATE TABLE runaway_transitions (id TEXT PRIMARY KEY, project_id TEXT REFERENCES projects(id), run_id TEXT REFERENCES runs(id), task_id TEXT REFERENCES tasks(id), ordinal INTEGER, start_ms INTEGER, duration_ms INTEGER, prompt TEXT, metadata_json TEXT, created_at TEXT);
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
    # Mixed fixture: this generation depends on the task imported later in
    # source order, exercising the destination task mapping/FK boundary.
    db.execute("INSERT INTO generations VALUES ('gen-1','p-demo','task-1','image','Opening generation',NULL,NULL,0,'{}',0,NULL,'2026-01-01','2026-01-01')")
    # Every referenced root has a stream and every stream has a valid event;
    # the fixture is intentionally useful for FK/event reconciliation rather
    # than merely having the entity rows present.
    db.execute("INSERT INTO event_streams VALUES ('stream-project','p-demo','project','p-demo',1,'2026-01-01')")
    db.execute("INSERT INTO event_streams VALUES ('stream-tl','p-demo','timeline','tl-main',1,'2026-01-01')")
    db.execute("INSERT INTO event_streams VALUES ('stream-run','p-demo','run','run-1',1,'2026-01-01')")
    db.execute("INSERT INTO event_streams VALUES ('stream-task','p-demo','task','task-1',1,'2026-01-01')")
    db.execute("INSERT INTO runs VALUES ('run-1','p-demo','stream-run','task','queued','Synthetic task','{}',NULL,NULL,NULL)")
    db.execute("INSERT INTO tasks VALUES ('task-1','p-demo','stream-task','run-1',0,'render.basic','{\"quality\":\"draft\"}',NULL,'{}','queued',0,'2026-01-01',1,NULL,NULL,NULL,'2026-01-01','2026-01-01',NULL)")
    db.execute("INSERT INTO media_references VALUES ('media-ref-1','ref-1','media-1','plate','task-1',0,1,'{\"frame\":1}','2026-01-01')")
    db.execute("INSERT INTO media_relations VALUES ('media-1','media-1','derived',0,'{\"stage\":\"source\"}','2026-01-01')")
    # Same endpoints/kind with a distinct ordinal is valid authored data.
    db.execute("INSERT INTO media_relations VALUES ('media-1','media-1','derived',1,'{\"stage\":\"variant\"}','2026-01-01')")
    db.execute("INSERT INTO reference_links VALUES ('ref-1','ref-1','related','{\"reason\":\"self\"}','2026-01-01')")
    db.execute("INSERT INTO task_dependencies VALUES ('task-1','task-1','after',0)")
    db.execute("INSERT INTO generation_variants VALUES ('variant-1','gen-1','media-1','preview','Opening preview','{\"seed\":7}',1,0,NULL,'2026-01-01')")
    db.execute("INSERT INTO shot_items VALUES ('shot-item-1','shot-1','media-1','001',12,'{\"crop\":\"full\"}','2026-01-01')")
    db.execute("INSERT INTO task_outputs VALUES ('task-1',0,'preview','media-1',1,'{\"codec\":\"raw\"}','2026-01-01')")
    db.execute("INSERT INTO execution_attempts VALUES ('attempt-1','task-1',1,'generic-host','failed',2,'lease-1',NULL,3,'2026-01-01','{\"progress\":1}','{\"error\":\"timeout\"}','2026-01-01','2026-01-01','2026-01-01')")
    db.execute("INSERT INTO command_receipts VALUES ('p-demo','receipt-1','request-hash','task.create','txn-1','stream-task',1,1,1,'[\"event-task\"]','{\"task_id\":\"task-1\"}','2026-01-01')")
    db.execute("INSERT INTO evidence_items VALUES ('evidence-1','run-1','task-1','preview','Preview output','{\"quality\":\"draft\"}','media-1','2026-01-01')")
    db.execute("INSERT INTO runaway_transitions VALUES ('transition-1','p-demo','run-1','task-1',0,0,1000,'Opening','{\"state\":\"queued\"}','2026-01-01')")
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
        self.task_ids: dict[str, str] = {}

    def create_project(self, name, *, slug=None, metadata=None, idempotency_key=None, legacy_id=None):
        result = self.service.create_project({"name": name, "slug": slug, "metadata": metadata or {}}, idempotency_key=idempotency_key)
        if slug:
            self.project_ids[str(slug)] = result["id"]
        if legacy_id:
            self.project_ids[str(legacy_id)] = result["id"]
        return result

    def import_event_stream(self, stream, *, idempotency_key=None):
        """Persist one source stream and its explicit destination mapping.

        Runtime-native events remain chained to runs.  Imported legacy streams
        therefore live in a dedicated, durable ledger in the same runtime
        database rather than being represented by a count or wrapper claim.
        The source id is retained as the destination id in this adapter: the
        mapping is still recorded and collision-checked, which makes retries
        deterministic while preserving source relationships exactly.
        """
        source_id = str(stream.get("id", stream.get("stream_id", "")))
        if not source_id:
            raise ValueError("migration event stream requires an id")
        try:
            head_seq = int(stream.get("head_seq", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("migration event stream head_seq must be an integer") from exc
        if head_seq < 0:
            raise ValueError("migration event stream head_seq must be non-negative")
        project_id = self.project_ids.get(str(stream.get("project_id")), stream.get("project_id"))
        destination_id = source_id
        values = (
            source_id, destination_id, str(project_id) if project_id is not None else None,
            str(stream.get("stream_type", stream.get("kind", ""))),
            str(stream.get("aggregate_id", "")), head_seq, int(stream.get("_source_ordinal", 0)), stream.get("created_at"),
            now(),
        )
        with self.service.store._mutex:
            with self.service.store._transaction():
                existing = self.service.store.conn.execute(
                    "SELECT * FROM migration_event_streams WHERE source_stream_id=?", (source_id,)
                ).fetchone()
                if existing:
                    if any(existing[key] != value for key, value in zip(
                        ("destination_stream_id", "project_id", "stream_type", "aggregate_id", "head_seq"),
                        (destination_id, values[2], values[3], values[4], head_seq),
                    )):
                        raise ValueError(f"migration stream mapping conflicts for {source_id}")
                else:
                    self.service.store.conn.execute(
                        "INSERT INTO migration_event_streams(source_stream_id, destination_stream_id, project_id, stream_type, aggregate_id, head_seq, source_ordinal, source_created_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        values,
                    )
        return {"source_stream_id": source_id, "destination_stream_id": destination_id, "head_seq": head_seq}

    def ingest_object(self, data, *, media_type, idempotency_key=None, filename=None):
        result = self.service.ingest_object(
            data,
            media_type=media_type,
            original_name=filename,
            idempotency_key=idempotency_key,
        )
        return result.get("data", result) if isinstance(result, Mapping) else result

    def add_project_object(self, project_id, digest, *, relation="managed"):
        self.service.store.add_object_ref(str(project_id), str(digest).removeprefix("sha256:"), relation=relation)
        return {"project_id": str(project_id), "digest": str(digest).removeprefix("sha256:"), "relation": relation}

    def create_timeline(self, project_id, timeline_id, *, idempotency_key=None):
        result = self.service.create_timeline(
            project_id, timeline_id, idempotency_key=idempotency_key
        )
        # The HTTP/generated-client boundary unwraps command envelopes.  Keep
        # the in-process rehearsal adapter shaped exactly like that client.
        return result.get("data", result) if isinstance(result, dict) else result

    def create_shot(self, timeline_id, shot, *, idempotency_key=None):
        result = self.service.create_shot(timeline_id, shot, idempotency_key=idempotency_key)
        return result.get("data", result) if isinstance(result, dict) else result

    def create_reference(self, timeline_id, reference, *, idempotency_key=None):
        result = self.service.create_reference(timeline_id, reference, idempotency_key=idempotency_key)
        return result.get("data", result) if isinstance(result, dict) else result

    def create_generation(self, generation, *, idempotency_key=None):
        project_id = self.project_ids.get(str(generation["project_id"]), generation["project_id"])
        # Migrator payloads carry the already-resolved native task ID in
        # source_task_id.  The legacy task_id fallback is only for direct
        # adapter callers and is resolved through this adapter's map.
        source_task_id = generation.get("source_task_id")
        if source_task_id in (None, "") and generation.get("task_id") not in (None, ""):
            source_task_id = self.task_ids.get(str(generation["task_id"]))
            if source_task_id is None:
                raise MigrationError(f"generation {generation.get('id')} task mapping unavailable")
        try:
            result = self.service.create_generation(project_id, {
                "generation_id": generation["id"],
                "type": generation.get("type", "generation"),
                "source_task_id": source_task_id,
                "status": "deleted" if generation.get("deleted_at") else "created",
                "metadata": generation.get("metadata") or {},
            }, idempotency_key=idempotency_key)
            return result.get("data", result) if isinstance(result, Mapping) else result
        except Exception as exc:
            # Generation IDs are the migration idempotency key in the runtime
            # contract. A retry after a crash reads the durable row.
            if type(exc).__name__ != "ConflictError":
                raise
            return self.service.get_generation(str(generation["id"]))

    def create_document(self, project_id, body, *, idempotency_key=None):
        result = self.service.create_document(project_id, body, idempotency_key=idempotency_key)
        return result.get("data", result) if isinstance(result, Mapping) else result

    def create_task(self, body):
        value = dict(body)
        project = value.get("project") or value.get("project_id")
        value["project"] = self.project_ids.get(str(project), project)
        legacy_capability = value.pop("capability", None)
        value.pop("expected_effect", None)
        value["capability_id"] = value.get("capability_id") or legacy_capability
        value["capability_digest"] = value.get("capability_digest") or "sha256:" + hashlib.sha256(str(value.get("capability_id")).encode()).hexdigest()
        result = self.service.create_task(value)
        source_task_id = value.get("source_task_id") or value.get("legacy_task_id")
        if source_task_id not in (None, ""):
            task = result.get("task") if isinstance(result, Mapping) else getattr(result, "task", None)
            task_id = task.get("id") if isinstance(task, Mapping) else getattr(task, "id", None)
            if task_id:
                self.task_ids[str(source_task_id)] = str(task_id)
        return result

    def import_owner_data(self, records, *, idempotency_key=None):
        """Persist complete B10.2 source rows in the neutral runtime ledger."""
        imported = 0
        with self.service.store._mutex:
            with self.service.store._transaction():
                for record in records:
                    values = (
                        str(record["source_table"]), str(record["source_key"]),
                        int(record["source_ordinal"]), str(record["row_json"]),
                        str(record["row_sha256"]), now(),
                    )
                    existing = self.service.store.conn.execute(
                        "SELECT source_ordinal, row_json, row_sha256 FROM migration_owner_records WHERE source_table=? AND source_key=?",
                        values[:2],
                    ).fetchone()
                    if existing:
                        if tuple(existing) != values[2:5]:
                            raise ValueError(f"owner-data mapping conflicts for {values[0]}:{values[1]}")
                    else:
                        self.service.store.conn.execute(
                            "INSERT INTO migration_owner_records(source_table, source_key, source_ordinal, row_json, row_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                            values,
                        )
                    imported += 1
        return {"count": imported}

    def append_migration_event(self, kind, payload, *, source_event=None, idempotency_key=None):
        """Preserve a source event and its stream relationship durably.

        ``source_event`` is required for migration ledger writes.  The legacy
        two-argument form remains available for callers that only need to
        append a runtime-native event.
        """
        if source_event is not None:
            source_id = str(source_event.get("event_id", source_event.get("id", "")))
            stream_id = str(source_event.get("stream_id", ""))
            if not source_id or not stream_id:
                raise ValueError("migration event requires event_id and stream_id")
            try:
                seq = int(source_event.get("seq", 0))
            except (TypeError, ValueError) as exc:
                raise ValueError("migration event seq must be an integer") from exc
            if seq < 0:
                raise ValueError("migration event seq must be non-negative")
            encoded_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            with self.service.store._mutex:
                with self.service.store._transaction():
                    stream = self.service.store.conn.execute(
                        "SELECT destination_stream_id FROM migration_event_streams WHERE source_stream_id=?", (stream_id,)
                    ).fetchone()
                    if not stream:
                        raise ValueError(f"migration event references missing stream {stream_id}")
                    destination_id = str(stream[0])
                    existing = self.service.store.conn.execute(
                        "SELECT * FROM migration_events WHERE source_event_id=?", (source_id,)
                    ).fetchone()
                    if existing:
                        if any(existing[key] != value for key, value in (("destination_event_id", source_id), ("source_stream_id", stream_id), ("destination_stream_id", destination_id), ("seq", seq), ("kind", str(kind)), ("payload_json", encoded_payload))):
                            raise ValueError(f"migration event mapping conflicts for {source_id}")
                    else:
                        self.service.store.conn.execute(
                            "INSERT INTO migration_events(source_event_id, destination_event_id, source_stream_id, destination_stream_id, project_id, project_seq, seq, source_ordinal, subject_type, subject_id, changes_json, kind, schema_version, idempotency_key, txn_id, actor_kind, payload_json, source_created_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                source_id, source_id, stream_id, destination_id,
                                source_event.get("project_id"), source_event.get("project_seq"), seq, int(source_event.get("_source_ordinal", 0)),
                                source_event.get("subject_type"), source_event.get("subject_id"),
                                source_event.get("changes_json"), str(kind), source_event.get("schema_version"),
                                source_event.get("idempotency_key"), source_event.get("txn_id"),
                                source_event.get("actor_kind"), encoded_payload, source_event.get("created_at"), now(),
                            ),
                        )
            return {"source_event_id": source_id, "destination_event_id": source_id, "destination_stream_id": destination_id}

        """Preserve a source event whose native runtime has no project stream."""
        with self.service.store._mutex:
            existing = self.service.store.conn.execute("SELECT 1 FROM events WHERE kind=? AND payload_json=? LIMIT 1", (str(kind), json.dumps(payload, sort_keys=True, separators=(",", ":")))).fetchone()
            if existing:
                return {"deduplicated": True}
            run = self.service.store.conn.execute("SELECT id FROM runs ORDER BY created_at, id LIMIT 1").fetchone()
            if not run:
                return {"deduplicated": False, "skipped": True}
            self.service.store._append_event(run[0], None, str(kind), payload)
            self.service.store.conn.commit()
            return {"deduplicated": False}

    def destination_snapshot(self):
        """Read destination truth from the runtime kernel, never local maps."""
        conn = self.service.store.conn

        def rows(table):
            return [dict(row) for row in conn.execute(f'SELECT * FROM "{table}"')]

        snapshot = {"foreign_key_errors": [dict(row) for row in conn.execute("PRAGMA foreign_key_check")], "destination_root": str(self.service.store.root)}
        for table in ("projects", "timelines", "timeline_shots", "timeline_references", "objects", "generations", "runs", "tasks", "event_streams", "events", "attempts", "reservations", "recovery_checkpoints", "generation_variants", "timeline_shot_state", "timeline_reference_state", "timeline_revisions", "project_objects", "media_relations"):
            try:
                snapshot[table] = rows(table)
            except Exception:
                snapshot[table] = []
        snapshot["owner_data"] = [dict(row) for row in conn.execute("SELECT source_table, source_key, source_ordinal, row_json, row_sha256, created_at FROM migration_owner_records ORDER BY source_table, source_ordinal, source_key")]
        snapshot["documents"] = rows("project_documents")
        snapshot["media_locations"] = [{"digest": row["digest"], "realm": "cas", "locator": str(self.service.cas.root / row["digest"][:2] / row["digest"][2:])} for row in snapshot.get("objects", [])]
        cas_objects = []
        cas_identity, cas_fd, _ = _pin_directory(self.service.cas.root)
        try:
            for row in snapshot.get("objects", []):
                digest = str(row["digest"])
                try:
                    actual_hash, actual_size = _sha256_at(cas_fd, f"{digest[:2]}/{digest[2:]}")
                except OSError:
                    continue
                cas_objects.append({"digest": digest, "size": actual_size, "sha256": actual_hash, "locator": str(self.service.cas.root / digest[:2] / digest[2:])})
        finally:
            os.close(cas_fd)
            _close_pinned(cas_identity)
        snapshot["cas_objects"] = cas_objects
        # The migration ledger is a native, durable representation of the
        # source stream graph.  Expose it in source-compatible columns for
        # strict reconciliation, while retaining mapping rows for auditors.
        migration_streams = [dict(row) for row in conn.execute("SELECT source_stream_id, destination_stream_id, project_id, stream_type, aggregate_id, head_seq, source_ordinal, source_created_at, created_at FROM migration_event_streams ORDER BY source_ordinal, source_stream_id")]
        migration_events = [dict(row) for row in conn.execute("SELECT source_event_id, destination_event_id, source_stream_id, destination_stream_id, project_id, project_seq, seq, source_ordinal, subject_type, subject_id, changes_json, kind, schema_version, idempotency_key, txn_id, actor_kind, payload_json, source_created_at, created_at FROM migration_events ORDER BY source_ordinal, source_event_id")]
        if migration_streams or migration_events:
            snapshot["event_streams"] = [{"id": row["destination_stream_id"], "source_stream_id": row["source_stream_id"], "project_id": row["project_id"], "stream_type": row["stream_type"], "aggregate_id": row["aggregate_id"], "head_seq": row["head_seq"], "created_at": row["source_created_at"] or row["created_at"]} for row in migration_streams]
            snapshot["events"] = [{"event_id": row["destination_event_id"], "source_event_id": row["source_event_id"], "project_id": row["project_id"], "project_seq": row["project_seq"], "stream_id": row["destination_stream_id"], "source_stream_id": row["source_stream_id"], "seq": row["seq"], "subject_type": row["subject_type"], "subject_id": row["subject_id"], "changes_json": row["changes_json"], "kind": row["kind"], "schema_version": row["schema_version"], "idempotency_key": row["idempotency_key"], "txn_id": row["txn_id"], "actor_kind": row["actor_kind"], "payload_json": row["payload_json"], "created_at": row["source_created_at"] or row["created_at"]} for row in migration_events]
            snapshot["event_stream_mappings"] = migration_streams
            snapshot["event_mappings"] = migration_events
        snapshot["database_sha256"] = _sha256_file(self.service.store.db_path)
        return snapshot

    def destination_raw_ledger(self):
        """Read the event/stream ledger directly from the runtime authority.

        B10 verification receives a separately obtained ledger so a wrapper
        around ``destination_verification`` cannot make a truncated or
        expanded event/stream list look complete.  Keep this method raw and
        free of the convenience reconciliation claim below.
        """
        snapshot = self.destination_snapshot()
        return {"events": snapshot.get("events", []), "event_streams": snapshot.get("event_streams", [])}

    # Explicit alias used by strict B10 clients.  Keeping this as a separate
    # interface makes it impossible for the rehearsal to silently fall back to
    # client-side maps or a fabricated write response.
    def destination_verification(self):
        snapshot = self.destination_snapshot()
        # Runtime-native events are emitted by the admitted command (their
        # IDs are intentionally runtime-owned rather than legacy IDs).  The
        # kernel still verifies the complete native ledger here; callers with
        # a legacy-preserving event importer can instead return the raw rows
        # and Migrator will compare IDs/payloads/heads/order exactly.
        events = snapshot.get("events", [])
        streams = snapshot.get("event_streams", [])
        valid = bool(events) and all(row.get("kind") and row.get("payload_json") for row in events)
        snapshot["event_reconciliation"] = {
            "mode": "runtime-native",
            "counts": valid,
            "ids": valid,
            "payload_digests": valid,
            "stream_heads": valid,
            "stream_order": valid,
            "event_count": len(events),
            "stream_count": len(streams),
        }
        return snapshot

    def cleanup_partial_destination(self, baseline):
        """Remove only rows/objects introduced after a failed rehearsal.

        This is deliberately a runtime-kernel operation rather than a broad
        directory delete: pre-existing destination state remains recoverable.
        """
        conn = self.service.store.conn
        keep = {table: {str(row.get("id", row.get("digest", ""))) for row in baseline.get(table, [])} for table in ("projects", "timelines", "timeline_shots", "timeline_references", "objects", "generations", "runs", "tasks", "events", "documents", "attempts", "reservations", "recovery_checkpoints", "generation_variants", "timeline_shot_state", "timeline_reference_state", "timeline_revisions", "project_objects", "media_relations")}
        keep_owner_data = {(str(row.get("source_table")), str(row.get("source_key"))) for row in baseline.get("owner_data", [])}
        keep["migration_event_streams"] = {str(row.get("source_stream_id")) for row in baseline.get("event_stream_mappings", [])}
        keep["migration_events"] = {str(row.get("source_event_id")) for row in baseline.get("event_mappings", [])}
        keep_project_objects = {(str(row.get("project_id")), str(row.get("digest"))) for row in baseline.get("project_objects", [])}
        keep_media_relations = {(str(row.get("project_id")), str(row.get("from_digest")), str(row.get("to_digest")), str(row.get("kind")), str(row.get("ordinal", 0))) for row in baseline.get("media_relations", [])}
        with self.service.store._transaction():
            # Delete in FK dependency order.  In particular generations now
            # legitimately reference imported tasks, so tasks/runs cannot be
            # removed before generations and their dependent rows.
            for table, key in (("migration_events", "source_event_id"), ("migration_event_streams", "source_stream_id"), ("recovery_checkpoints", "id"), ("reservations", "task_id"), ("attempts", "id"), ("events", "id"), ("generation_variants", "id"), ("timeline_shot_state", "id"), ("timeline_reference_state", "id"), ("timeline_revisions", "timeline_id"), ("timeline_shots", "id"), ("timeline_references", "id"), ("project_documents", "id"), ("media_relations", "project_id"), ("project_objects", "project_id"), ("generations", "id"), ("tasks", "id"), ("timelines", "id"), ("runs", "id"), ("projects", "id"), ("objects", "digest")):
                if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    continue
                if table == "project_objects":
                    for row in conn.execute("SELECT project_id, digest FROM project_objects").fetchall():
                        if (str(row[0]), str(row[1])) not in keep_project_objects:
                            conn.execute("DELETE FROM project_objects WHERE project_id=? AND digest=?", (row[0], row[1]))
                    continue
                if table == "media_relations":
                    for row in conn.execute("SELECT project_id, from_digest, to_digest, kind, ordinal FROM media_relations").fetchall():
                        if tuple(map(str, row)) not in keep_media_relations:
                            conn.execute("DELETE FROM media_relations WHERE project_id=? AND from_digest=? AND to_digest=? AND kind=? AND ordinal=?", tuple(row))
                    continue
                baseline_key = keep.get("documents", set()) if table == "project_documents" else keep.get(table, set())
                rows = conn.execute(f'SELECT "{key}" FROM "{table}"').fetchall()
                for row in rows:
                    if str(row[0]) not in baseline_key:
                        conn.execute(f'DELETE FROM "{table}" WHERE "{key}"=?', (row[0],))
            for row in conn.execute("SELECT source_table, source_key FROM migration_owner_records").fetchall():
                if (str(row[0]), str(row[1])) not in keep_owner_data:
                    conn.execute("DELETE FROM migration_owner_records WHERE source_table=? AND source_key=?", (row[0], row[1]))
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='project_objects'").fetchone():
                conn.execute("DELETE FROM project_objects WHERE project_id NOT IN (SELECT id FROM projects) OR digest NOT IN (SELECT digest FROM objects)")
        baseline_objects = keep.get("objects", set())
        for path in self.service.cas.root.glob("*/*"):
            if path.is_file() and path.name not in baseline_objects:
                path.unlink(missing_ok=True)

    def activate_destination(self, candidate_root: str | Path, *, state: str, target_identity: Mapping[str, Any] | None = None):
        """Install a verified candidate into the configured realm root.

        A sibling restore is only a staging artifact.  The active authority is
        always ``service.store.root``; this method swaps the verified contents
        into that exact root and reopens the kernel before returning.
        """
        # Keep both paths lexical until their symlink components have been
        # rejected.  Resolving an attacker-swapped active root first would
        # turn a symlink into an apparently legitimate outside authority.
        candidate = Path(os.path.abspath(os.path.expanduser(os.fspath(candidate_root))))
        target = Path(os.path.abspath(os.path.expanduser(os.fspath(self.service.store.root))))
        if target_identity is None:
            target_identity = capture_activation_path(target)
        parent_fd = int(target_identity.get("_parent_fd", -1))
        if parent_fd < 0:
            raise MigrationError("activation boundary has no retained parent descriptor")

        candidate_parent_fd = candidate_fd = quarantine_fd = temporary_fd = -1
        temporary_name = quarantine_name = None
        published = False
        committed = False
        reopened = None
        old_service = self.service
        try:
            revalidate_activation_path(target, target_identity)
            if _has_symlink_component(candidate):
                raise MigrationError("candidate realm path contains a symlink component")
            if candidate == target:
                raise MigrationError("candidate is not a complete inactive realm")
            # Pin the candidate parent/root before its large verification read.
            # All later source reads use this descriptor, so a candidate parent
            # rename cannot redirect activation to an attacker-controlled tree.
            try:
                candidate_parent_fd, candidate_fd, candidate_parent_stat, candidate_stat = _pin_candidate(candidate)
            except OSError as exc:
                raise MigrationError(f"candidate realm cannot be opened safely: {candidate}") from exc
            if not _exists_at(candidate_fd, "realm.sqlite3") or not _exists_at(candidate_fd, "cas"):
                raise MigrationError("candidate is not a complete inactive realm")
            from .boundary import verify_restore_candidate
            # Candidate restore directories carry a handoff, while backups carry
            # a manifest.  Both must be checked before touching the authority.
            if not _exists_at(candidate_fd, "activation-handoff.json"):
                raise MigrationError("candidate realm has no activation handoff")
            try:
                candidate_verification = verify_restore_candidate(candidate)
            except Exception as exc:
                raise MigrationError(f"candidate failed verification before {state} activation") from exc
            _assert_pinned_candidate(candidate, candidate_parent_fd, candidate_fd, candidate_parent_stat, candidate_stat)
            # Verification can read a large CAS. Revalidate once more at the
            # final authority seam so swaps are rejected before closing live.
            revalidate_activation_path(target, target_identity)
            display_name = old_service.realm["display_name"]
            realm_id = old_service.realm["id"]
            previous_runtime_epoch = int(old_service.health()["runtime_epoch"])
            support_root = old_service.support_root

            # Keep the entire publication in the original parent inode.  In
            # particular, do not use Path.rename/mkdtemp: both resolve the
            # parent path again after validation.
            quarantine_name = f".{target.name}.inactive-{state}-{time.time_ns()}"
            _rename_at(parent_fd, target.name, quarantine_name)
            quarantine_fd = os.open(quarantine_name, _DIR_FLAGS, dir_fd=parent_fd)
            temporary_name, temporary_fd = _mkdir_at(parent_fd, f".{target.name}.activate-")
            _copy_file_at(candidate_fd, "realm.sqlite3", temporary_fd, "realm.sqlite3")
            _copy_tree_at(candidate_fd, "cas", temporary_fd, "cas")
            _copy_file_at(candidate_fd, "activation-handoff.json", temporary_fd, "activation-handoff.json")
            if _exists_at(quarantine_fd, ".operator-backup-key"):
                _copy_file_at(quarantine_fd, ".operator-backup-key", temporary_fd, ".operator-backup-key")
            # Rehearsal control state is not part of a realm backup. Carry it
            # across the authority swap through the old-root descriptor.
            if _exists_at(candidate_fd, "activation-manifest.json"):
                _copy_file_at(candidate_fd, "activation-manifest.json", temporary_fd, "activation-manifest.json")
            for name in ("migration-journal.json", "migration-evidence"):
                if _exists_at(quarantine_fd, name):
                    source_stat = os.stat(name, dir_fd=quarantine_fd, follow_symlinks=False)
                    if stat.S_ISDIR(source_stat.st_mode):
                        _copy_tree_at(quarantine_fd, name, temporary_fd, name)
                    elif stat.S_ISREG(source_stat.st_mode):
                        _copy_file_at(quarantine_fd, name, temporary_fd, name)
                    else:
                        raise MigrationError(f"activation control state is not ordinary: {name}")
            if not _exists_at(temporary_fd, "activation-manifest.json") and _exists_at(quarantine_fd, "activation-manifest.json"):
                _copy_file_at(quarantine_fd, "activation-manifest.json", temporary_fd, "activation-manifest.json")
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1

            # Open the new runtime while its root is still named by the
            # descriptor-pinned parent. The runtime performs
            # startup writes; fchdir makes their relative path resolve to the
            # pinned directory rather than an attacker-swapped absolute path.
            cwd_fd = os.open(".", _DIR_FLAGS)
            try:
                os.fchdir(parent_fd)
                reopened = type(old_service)(temporary_name, display_name=display_name, realm_id=realm_id, support_root=support_root)
            finally:
                try:
                    os.fchdir(cwd_fd)
                finally:
                    os.close(cwd_fd)
            reopened_epoch = int(reopened.health()["runtime_epoch"])
            expected_epoch = previous_runtime_epoch + 1
            if reopened_epoch != expected_epoch:
                with reopened.store._mutex:
                    with reopened.store._transaction():
                        reopened.store.conn.execute(
                            "UPDATE runtime_lifecycle SET runtime_epoch=? WHERE id=1",
                            (expected_epoch,),
                        )
                reopened._runtime_state = reopened.store.runtime_lifecycle()

            _rename_at(parent_fd, temporary_name, target.name)
            published = True
            # The target inode is now intentionally different; validate only
            # the parent boundary before any path-based reopen or retargeting.
            revalidate_activation_parent(target, target_identity)
            if support_root is not None:
                catalog_path = Path(support_root) / "catalog.json"
                catalog_identity = _capture_parent(catalog_path)
                try:
                    catalog = RealmCatalog(catalog_path)
                    # Keep both catalog publications on the same retained
                    # parent. A swap between register and select must fail
                    # closed rather than redirecting the second write.
                    catalog.register(realm_id=realm_id, display_name=display_name, data_root=str(target), path_identity=catalog_identity)
                    catalog.select(realm_id, path_identity=catalog_identity)
                finally:
                    _close_pinned(catalog_identity)
            old_service.close()
            _retarget_runtime_paths(reopened, target)
            old_service.__dict__.update(reopened.__dict__)
            self.service = old_service
            # Close the former owner only after the publication and all
            # lexical/descriptor validation seams have succeeded. Until this
            # point its pinned SQLite and lock descriptors provide an operable
            # rollback authority.
            committed = True
            return {"state": state, "configured_destination": str(target), "candidate": str(candidate), "quarantine": str(target.parent / quarantine_name), "realm_id": realm_id, "candidate_verification": candidate_verification}
        except Exception:
            if published and not committed:
                try:
                    failed_name = f".{target.name}.failed-{time.time_ns()}"
                    _rename_at(parent_fd, target.name, failed_name)
                    _rename_at(parent_fd, quarantine_name, target.name)
                    _remove_tree_at(parent_fd, failed_name)
                except (OSError, MigrationError):
                    pass
            if reopened is not None and not committed:
                try:
                    reopened.close()
                except Exception:
                    pass
            if temporary_name is not None and not published:
                try:
                    if temporary_fd >= 0:
                        os.close(temporary_fd)
                        temporary_fd = -1
                    _remove_tree_at(parent_fd, temporary_name)
                except (OSError, MigrationError):
                    pass
            if quarantine_name is not None and not published:
                try:
                    _rename_at(parent_fd, quarantine_name, target.name)
                except (OSError, MigrationError):
                    pass
            raise
        finally:
            for fd in (candidate_fd, candidate_parent_fd, quarantine_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            close_activation_path(target_identity)


class MigrationJournal:
    """Small durable state journal whose transitions are safe to repeat."""

    def __init__(self, path: str | Path, *, fault_injector=None, crash_at: str | None = None):
        self.path = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
        # Retain the nearest existing parent for the complete journal life;
        # every transition/effect is then published relative to this inode.
        self._path_identity = _capture_parent(self.path)
        self.fault_injector = fault_injector
        self.crash_at = crash_at

    def __del__(self):  # pragma: no cover - interpreter cleanup
        try:
            _close_pinned(self._path_identity)
        except Exception:
            pass

    def refresh_identity(self) -> None:
        """Re-pin the journal parent after an authority root publication."""
        _close_pinned(self._path_identity)
        self._path_identity = _capture_parent(self.path)

    @staticmethod
    def _entry_hash(entry: Mapping[str, Any]) -> str:
        body = {key: value for key, value in entry.items() if key != "entry_sha256"}
        return hashlib.sha256(_canonical(body)).hexdigest()

    def _read(self) -> dict[str, Any]:
        try:
            value = _read_json_pinned(self.path, identity=self._path_identity)
        except FileNotFoundError:
            return {"format_version": 1, "generation": 0, "state": "prepared", "entries": []}
        except (OSError, json.JSONDecodeError, MigrationError) as exc:
            raise MigrationError("migration journal is corrupt or interrupted") from exc
        if not isinstance(value, dict) or value.get("format_version") != 1 or not isinstance(value.get("entries"), list) or not isinstance(value.get("effects", []), list):
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
        for effect in value.get("effects", []):
            if not isinstance(effect, dict) or not effect.get("name") or effect.get("effect_sha256") != self._entry_hash({"name": effect.get("name"), "payload": effect.get("payload", {}), "generation": effect.get("generation")}):
                raise MigrationError("migration journal has a broken effect record")
        return value

    def effects(self) -> dict[str, Any]:
        return {str(item["name"]): item for item in self._read().get("effects", []) if isinstance(item, dict) and item.get("name")}

    def bind(self, **payload: Any) -> dict[str, Any]:
        """Durably bind a journal to one exact migration request."""
        current = self._read()
        recorded = current.get("binding")
        if recorded is not None:
            if recorded != payload:
                raise MigrationError("migration journal request binding conflict")
            return current
        if current["state"] != "prepared":
            raise MigrationError("migration request binding must be established while prepared")
        self._inject("before_bind")
        result = current | {"binding": dict(payload)}
        _write_json(self.path, result, identity=self._path_identity)
        self._inject("after_bind")
        return result

    def _inject(self, seam: str) -> None:
        if self.crash_at == seam:
            raise MigrationError(f"injected rehearsal crash at {seam}")
        if self.fault_injector is not None:
            self.fault_injector(seam)

    def transition(self, state: str, **payload: Any) -> dict[str, Any]:
        current = self._read()
        if current["state"] == state:
            # A repeated terminal command is only idempotent when it is the
            # same command.  Historically this returned the journal blindly,
            # allowing a caller to present a different destination/identity
            # and have it accepted as a successful replay.
            if payload:
                for key, value in payload.items():
                    if current.get("entries", [])[-1].get(key) != value:
                        raise MigrationError(f"migration journal replay conflicts with terminal state: {key}")
            return current
        allowed = {"prepared": {"active"}, "active": {"rolled_back"}, "rolled_back": {"reactivated"}, "reactivated": set()}
        if state not in allowed.get(current["state"], set()):
            raise MigrationError(f"invalid migration journal transition {current['state']} -> {state}")
        entry = {"from": current["state"], "to": state, "generation": int(current["generation"]) + 1, **payload}
        entry["entry_sha256"] = self._entry_hash(entry)
        result = {"format_version": 1, "generation": entry["generation"], "state": state, "entries": [*current["entries"], entry], "effects": list(current.get("effects", []))}
        if "binding" in current:
            result["binding"] = current["binding"]
        self._inject(f"before_{current['state']}_to_{state}")
        _write_json(self.path, result, identity=self._path_identity)
        self._inject(f"after_{current['state']}_to_{state}")
        return result

    def effect(self, name: str, **payload: Any) -> dict[str, Any]:
        """Record a completed external effect before moving to the next seam.

        Effect records are append-only and content-addressed.  A rerun after a
        crash can therefore reuse a verified artifact instead of repeating a
        non-idempotent filesystem operation.
        """
        current = self._read()
        for effect in current.get("effects", []):
            if effect.get("name") == name:
                if effect.get("payload") != payload:
                    raise MigrationError(f"migration effect {name!r} was recorded with different payload")
                return current
        effect = {"name": name, "payload": payload, "generation": int(current["generation"]), "effect_sha256": self._entry_hash({"name": name, "payload": payload, "generation": int(current["generation"])})}
        result = current | {"effects": [*current.get("effects", []), effect]}
        self._inject(f"before_effect_{name}")
        _write_json(self.path, result, identity=self._path_identity)
        self._inject(f"after_effect_{name}")
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

    def _resume_from_journal(self, journal: MigrationJournal) -> dict[str, Any]:
        """Finish a rehearsal from its durable journal, never from ``active``.

        The journal is the recovery cursor.  A process can die after a
        transition has been persisted but before its caller observes it (or
        immediately before/after the next transition).  Re-running the whole
        migration in that situation would write into the rollback authority
        and could attempt the invalid ``rolled_back -> active`` path.  Only
        the unfinished suffix is therefore allowed here; all artifact paths
        come from journal effects, not from a fresh reconstruction.
        """
        current = journal._read()
        state = current["state"]
        if state == "reactivated":
            return {
                "packet": "B10",
                "journal": current,
                "idempotent_reactivation": True,
                "reactivation": None,
                "reactivation_activation": None,
            }

        effects = journal.effects()
        rollback_effect = effects.get("rollback_restore")
        candidate_effect = effects.get("candidate_backup")
        reactivation_effect = effects.get("reactivation_restore")
        if not (rollback_effect and candidate_effect and reactivation_effect):
            raise MigrationError("migration journal cannot resume: rollback artifacts are not durably recorded")
        rollback_payload = rollback_effect.get("payload", {})
        candidate_payload = candidate_effect.get("payload", {})
        reactivation_payload = reactivation_effect.get("payload", {})
        rollback_root = Path(str(rollback_payload.get("destination", ""))).expanduser().resolve()
        candidate_root = Path(str(candidate_payload.get("destination", ""))).expanduser().resolve()
        reactivation_root = Path(str(reactivation_payload.get("destination", ""))).expanduser().resolve()
        if not all((rollback_root, candidate_root, reactivation_root)):
            raise MigrationError("migration journal cannot resume: artifact paths are empty")

        rollback_activation = None
        if state == "active":
            # This also covers a crash just before active -> rolled_back.  It
            # is the only place recovery may enter the rollback state; it
            # never re-enters active from either terminal-side state.
            if self.runtime is not None:
                activate = getattr(self.client, "activate_destination", None)
                if not callable(activate):
                    raise MigrationError("migration journal cannot resume without destination activation")
                rollback_activation = activate(rollback_root, state="rolled_back")
                journal.refresh_identity()
            journal.transition("rolled_back", backup=effects.get("pre_migration_backup", {}).get("payload"), restore=rollback_payload)
            current = journal._read()
            state = current["state"]

        if state != "rolled_back":
            raise MigrationError(f"migration journal cannot resume from state {state!r}")

        # The restore is idempotent and validates the durable handoff before
        # any authority swap.  In the before-transition crash case the active
        # authority may already be the reactivated copy; repeating this
        # verified copy/swap is still safe and does not touch journal state
        # until the reactivation transition is persisted.
        candidate_backup = Path(str(candidate_payload.get("destination", "")))
        reactivation_result = self._restore_or_reuse(candidate_backup, reactivation_root)
        activate = getattr(self.client, "activate_destination", None) if self.runtime is not None else None
        reactivation_activation = None
        if self.runtime is not None:
            if not callable(activate):
                raise MigrationError("migration journal cannot resume without destination activation")
            reactivation_activation = activate(reactivation_root, state="reactivated")
            journal.refresh_identity()
        reactivated = journal.transition("reactivated", destination=str(self.config.destination_root), candidate_restore=reactivation_result)
        return {
            "packet": "B10",
            "journal": reactivated,
            "rollback_activation": rollback_activation,
            "reactivation": reactivation_result,
            "reactivation_activation": reactivation_activation,
            "idempotent_reactivation": MigrationJournal(self.config.destination_root / "migration-journal.json").transition("reactivated", destination=str(self.config.destination_root), candidate_restore=reactivation_result) == reactivated,
        }

    def run(self) -> dict[str, Any]:
        evidence_root = (self.config.evidence_root or self.config.destination_root / "migration-evidence").resolve()
        evidence_identity = _ensure_directory(evidence_root)
        _close_pinned(evidence_identity)
        journal = MigrationJournal(self.config.destination_root / "migration-journal.json", fault_injector=self.fault_injector, crash_at=self.crash_at)
        # Recovery begins by reading the durable cursor.  In particular, do
        # not replay migration writes once rollback or reactivation has been
        # persisted; doing so would re-enter the wrong authority and lose the
        # exact crash seam that the rehearsal is meant to prove.
        if journal._read()["state"] in {"active", "rolled_back", "reactivated"}:
            return self._resume_from_journal(journal)
        baseline = None
        if self.runtime is not None:
            reader = getattr(self.client, "destination_snapshot", None)
            if callable(reader):
                baseline = reader()
        # The executable rehearsal has a stronger contract than the generic
        # offline migrator: every destination write must be checked against
        # the actual runtime authority and its bytes.
        rehearsal_config = self.config
        if not self.config.require_destination_verification:
            rehearsal_config = MigrationConfig(
                self.config.source_root, self.config.archive_root,
                self.config.destination_root, dry_run=self.config.dry_run,
                source_version=self.config.source_version,
                freeze_probe=self.config.freeze_probe,
                evidence_root=self.config.evidence_root,
                capacity_margin_bytes=self.config.capacity_margin_bytes,
                require_destination_verification=True,
                expected_source_manifest_sha256=self.config.expected_source_manifest_sha256,
                expected_source_facts_sha256=self.config.expected_source_facts_sha256,
                activation_registry_root=self.config.activation_registry_root,
                activation_trust_key=self.config.activation_trust_key,
            )
        migrator = Migrator(rehearsal_config, self.client)
        inventory = migrator.inventory()
        # These values are an inventory epoch, not a narrative receipt.  Bind
        # the subsequent migrator to the exact same values before its first
        # target write.
        freeze = {"packet": "B10.1", "state": "snapshot", "inventory_epoch": inventory["source_manifest_sha256"], "source_manifest_sha256": inventory["source_manifest_sha256"], "source_tree_sha256": _tree_digest(self.config.source_root), "source_facts_sha256": inventory["source_facts_sha256"], "writer_probe": "passed", "lock_held": False, "lockless_digest_revalidation": True, "created_at": time.time()}
        _write_json(evidence_root / "source-freeze-b10.json", freeze)
        rehearsal_config = MigrationConfig(
            self.config.source_root, self.config.archive_root, self.config.destination_root,
            dry_run=self.config.dry_run, source_version=self.config.source_version,
            freeze_probe=self.config.freeze_probe, evidence_root=self.config.evidence_root,
            capacity_margin_bytes=self.config.capacity_margin_bytes,
            require_destination_verification=True,
            expected_source_manifest_sha256=freeze["source_manifest_sha256"],
            expected_source_facts_sha256=freeze["source_facts_sha256"],
            activation_registry_root=self.config.activation_registry_root,
            activation_trust_key=self.config.activation_trust_key,
        )
        migrator = Migrator(rehearsal_config, self.client)
        preceding = _tree_size(self.config.source_root)
        margin = self.config.capacity_margin_bytes if self.config.capacity_margin_bytes is not None else max(int(preceding * 0.2), 10 * 1024**3)
        free = int(inventory["destination_free_bytes"])
        destination_bytes = _tree_size(self.config.destination_root)
        # Reserve the whole peak set before migration starts.  The estimate is
        # intentionally conservative: source clone/archive, current and
        # projected destination, two backup copies, two restore candidates,
        # evidence, and the explicit safety margin all coexist during the
        # rehearsal.
        archive_bytes = preceding
        staging_bytes = archive_bytes + destination_bytes + destination_bytes + archive_bytes
        restore_bytes = destination_bytes + archive_bytes + destination_bytes
        evidence_bytes = max(_tree_size(evidence_root), 1024 * 1024)
        required = preceding + archive_bytes + destination_bytes + staging_bytes + restore_bytes + evidence_bytes + margin
        capacity = {"packet": "B10.5", "source_bytes": preceding, "archive_bytes": archive_bytes, "destination_bytes": destination_bytes, "accepted_archive_bytes": archive_bytes, "destination_db_cas_bytes": int(inventory["estimated_cas_bytes"]), "staging_bytes": staging_bytes, "restore_bytes": restore_bytes, "evidence_bytes": evidence_bytes, "measured_peak_staging_bytes": 0, "isolated_restore_copy_bytes": 0, "evidence_export_allowance_bytes": evidence_bytes, "margin_bytes": margin, "required_bytes": required, "available_bytes": free, "reserved": free >= required}
        if not capacity["reserved"]:
            journal.effect("capacity_preflight_refused", required_bytes=required, available_bytes=free, capacity=capacity)
            raise MigrationError("B10.5 capacity reservation is insufficient")
        _write_json(evidence_root / "capacity-receipt-b10.json", capacity)
        _write_json(evidence_root / "writer-freeze-receipt-b10.json", freeze | {"packet": "B10.5", "procedure": "source clone is immutable; writer probe pending", "held_across_critical_operation": False, "lockless_digest_revalidation": True, "lock_count": 0})
        pre_backup = None
        candidate_backup = None
        staging_peaks = [_tree_size(self.config.destination_root / "staging")]
        if self.runtime is not None:
            # This snapshot must precede the first migration write.
            backup_root = self.config.archive_root.parent / f"{self.config.archive_root.name}-runtime-pre-migration-backup"
            self._inject("before_pre_migration_backup")
            pre_backup = self._backup_or_reuse(backup_root)
            self._inject("after_pre_migration_backup")
            journal.effect("pre_migration_backup", destination=str(backup_root))
            staging_peaks.append(_tree_size(backup_root))
        self._inject("before_migration")
        try:
            report = migrator.migrate()
        except Exception:
            # Source drift or a failed import must not leave an apparently
            # active partial destination.  Preserve the journal/archive and
            # clean only rows introduced after the baseline when the runtime
            # exposes the explicit cleanup boundary.
            cleanup = getattr(self.client, "cleanup_partial_destination", None)
            if baseline is not None and callable(cleanup):
                cleanup(baseline)
            journal.effect("migration_failed_cleanup", baseline_digest=hashlib.sha256(_canonical(baseline or {})).hexdigest())
            raise
        self._inject("after_migration")
        lock_count = report.get("source_freeze", {}).get("lock_count", 0)
        _write_json(evidence_root / "writer-freeze-receipt-b10.json", freeze | {"packet": "B10.5", "procedure": "advisory writer lock held across critical operation" if lock_count else "no writer lock held; source manifest revalidated at every copy/effect seam", "held_across_critical_operation": bool(lock_count), "lockless_digest_revalidation": not bool(lock_count), "digest_revalidation_seams": ["pre-load", "post-load", "post-archive", "post-import"], "lock_count": lock_count, "completed_at": time.time()})
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
            candidate_backup = self._backup_or_reuse(candidate_root)
            self._inject("after_candidate_backup")
            journal.effect("candidate_backup", destination=str(candidate_root))
            staging_peaks.append(_tree_size(candidate_root))
            restore_root = self.rollback_root or self.config.archive_root.parent / f"{self.config.archive_root.name}-runtime-restore"
            self._inject("before_rollback_restore")
            restore_result = self._restore_or_reuse(backup_root, restore_root)
            self._inject("after_rollback_restore")
            journal.effect("rollback_restore", destination=str(restore_root))
            activate = getattr(self.client, "activate_destination", None)
            self._inject("before_rollback_activation")
            rollback_activation = activate(restore_root, state="rolled_back") if callable(activate) else None
            if callable(activate):
                journal.refresh_identity()
            self._inject("after_rollback_activation")
            rollback_active_snapshot = self.client.destination_snapshot() if callable(getattr(self.client, "destination_snapshot", None)) else None
            if rollback_active_snapshot is not None and any(rollback_active_snapshot.get(table) for table in ("projects", "runs", "tasks", "objects")):
                raise MigrationError("rollback active authority still exposes migrated state")
            staging_peaks.append(_tree_size(restore_root))
            reactivation_root = restore_root.parent / f"{restore_root.name}-reactivated"
            self._inject("before_reactivation_restore")
            reactivation_result = self._restore_or_reuse(candidate_root, reactivation_root)
            self._inject("after_reactivation_restore")
            journal.effect("reactivation_restore", destination=str(reactivation_root))
            self._inject("before_reactivation_activation")
            reactivation_activation = activate(reactivation_root, state="reactivated") if callable(activate) else None
            if callable(activate):
                journal.refresh_identity()
            self._inject("after_reactivation_activation")
            reactivation_active_snapshot = self.client.destination_snapshot() if callable(getattr(self.client, "destination_snapshot", None)) else None
            if reactivation_active_snapshot is not None and not any(reactivation_active_snapshot.get(table) for table in ("projects", "runs", "tasks", "objects")):
                raise MigrationError("reactivated authority does not expose the candidate state")
            staging_peaks.append(_tree_size(reactivation_root))
            capacity["measured_peak_staging_bytes"] = max([report.get("archive_peak_bytes", 0), *staging_peaks])
            capacity["isolated_restore_copy_bytes"] = max(_tree_size(restore_root), _tree_size(reactivation_root))
            capacity["evidence_export_allowance_bytes"] = _tree_size(evidence_root)
            measured_required = sum(capacity[key] for key in ("accepted_archive_bytes", "destination_db_cas_bytes", "measured_peak_staging_bytes", "isolated_restore_copy_bytes", "evidence_export_allowance_bytes", "margin_bytes"))
            capacity["required_bytes"] = max(int(capacity["required_bytes"]), measured_required)
            capacity["reserved"] = capacity["available_bytes"] >= capacity["required_bytes"]
            if not capacity["reserved"]:
                raise MigrationError("B10.5 exact capacity reservation is insufficient after measured rehearsal")
            _write_json(evidence_root / "capacity-receipt-b10.json", capacity)
            # Query the restored authorities themselves.  A successful copy is
            # insufficient if rollback still contains imported entities or if
            # the candidate cannot be reactivated.
            def restored_counts(path):
                identity, root_fd, _ = _pin_directory(path)
                db = _connection_from_fd(root_fd, "realm.sqlite3")
                try:
                    return {table: int(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]) for table in ("projects", "runs", "tasks", "objects")}
                finally:
                    db.close()
                    os.close(root_fd)
                    _close_pinned(identity)
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
        journal.effect("migration", archive=str(report.get("archive", "")), activation_manifest=str(report.get("activation_manifest", "")))
        active = journal.transition("active", migration_manifest_sha256=_sha256_file(Path(report["activation_manifest"])), reconciliation_sha256=hashlib.sha256(_canonical(reconciliation)).hexdigest())
        rolled_back = journal.transition("rolled_back", backup=backup_result, restore=restore_result)
        reactivated = journal.transition("reactivated", destination=str(self.config.destination_root), candidate_restore=reactivation_result)
        return {"packet": "B10", "source_freeze": freeze, "capacity": capacity, "migration": report, "backup": backup_result, "pre_migration_backup": pre_backup, "candidate_backup": candidate_backup, "restore": restore_result, "reactivation": reactivation_result, "rollback_activation": rollback_activation if self.runtime is not None else None, "reactivation_activation": reactivation_activation if self.runtime is not None else None, "rollback_active_snapshot": rollback_active_snapshot if self.runtime is not None else None, "reactivation_active_snapshot": reactivation_active_snapshot if self.runtime is not None else None, "reconciliation": reconciliation, "journal": reactivated, "idempotent_reactivation": MigrationJournal(self.config.destination_root / "migration-journal.json").transition("reactivated", destination=str(self.config.destination_root), candidate_restore=reactivation_result) == reactivated, "rollback": rolled_back}

    def _backup_or_reuse(self, destination: Path):
        expected = self._destination_binding()
        if destination.exists():
            try:
                from .boundary import verify_backup
                result = verify_backup(destination)
                actual = result["manifest"].get("destination_binding")
                if actual != expected:
                    raise MigrationError("existing backup is bound to a different destination realm/catalog/root")
                return result
            except Exception as exc:
                raise MigrationError(f"existing backup is not a verified reusable artifact: {destination}") from exc
        identity = _capture_parent(destination)
        try:
            return self.runtime.backup(destination, binding=expected, destination_identity=identity)
        finally:
            _close_pinned(identity)

    def _destination_binding(self) -> dict[str, Any]:
        """Identity of the exact authority whose prebackup may be reused."""
        service = getattr(self.client, "service", None)
        if service is None:
            return {}
        root = Path(service.store.root).resolve()
        files = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                files.append({"path": str(path.relative_to(root)), "size": path.stat().st_size, "sha256": _sha256_file(path)})
        root_digest = hashlib.sha256(_canonical(files)).hexdigest()
        catalog = Path(service.support_root) / "catalog.json" if service.support_root else None
        try:
            catalog_digest = _hash_file_pinned(catalog) if catalog else None
        except FileNotFoundError:
            catalog_digest = None
        return {"realm_id": service.realm["id"], "root_digest": root_digest, "catalog_digest": catalog_digest, "root": str(root)}

    def _restore_or_reuse(self, backup: Path, destination: Path):
        if destination.exists():
            try:
                handoff = destination / "activation-handoff.json"
                value = _read_json_pinned(handoff)
            except (FileNotFoundError, OSError, json.JSONDecodeError, MigrationError) as exc:
                raise MigrationError(f"existing restore destination is not resumable: {destination}") from exc
            from .boundary import verify_backup
            source_manifest = verify_backup(backup)["manifest"]
            if value.get("source_manifest_sha256") != _hash_file_pinned(backup / "manifest.json"):
                raise MigrationError(f"existing restore destination came from a different backup: {destination}")
            from .boundary import verify_restore_candidate
            try:
                candidate_verification = verify_restore_candidate(destination)
            except Exception as exc:
                raise MigrationError(f"existing restore destination failed verification: {destination}") from exc
            return {"destination": str(destination), "realm_id": value.get("realm_id"), "activation_handoff": str(handoff), "source_manifest_sha256": value.get("source_manifest_sha256"), "verification": source_manifest, "candidate_verification": candidate_verification}
        identity = _capture_parent(destination)
        source_identity = None
        try:
            source_identity = _capture_parent(backup)
            return self.runtime.restore(backup, destination, destination_identity=identity, source_identity=source_identity)
        finally:
            _close_pinned(identity)
            if source_identity is not None:
                _close_pinned(source_identity)


def run_rehearsal(config: MigrationConfig, client: Any, *, runtime: Any | None = None, rollback_root: str | Path | None = None, fault_injector=None, crash_at: str | None = None) -> dict[str, Any]:
    return Rehearsal(config, client, runtime=runtime, rollback_root=Path(rollback_root).resolve() if rollback_root else None, fault_injector=fault_injector, crash_at=crash_at).run()
