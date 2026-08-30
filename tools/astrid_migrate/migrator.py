"""Small, fail-closed current-Mac Astrid offline migrator (T5)."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from typing import Any, Callable, Mapping


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class MigrationConfig:
    source_root: Path
    archive_root: Path
    destination_root: Path
    dry_run: bool = False
    source_version: str = "astrid-v10"
    freeze_probe: Callable[[], bool] | None = None
    evidence_root: Path | None = None
    capacity_margin_bytes: int | None = None
    # B10 rehearsals must prove writes against the destination authority.  The
    # ordinary offline migrator keeps the older response-only fixture mode for
    # callers that do not have a read API.
    require_destination_verification: bool = False
    # Rehearsals bind the migrator to the inventory captured by the freeze
    # receipt.  Without this, a mutation at the ``before_migration`` seam
    # becomes the new baseline and can go unnoticed.
    expected_source_manifest_sha256: str | None = None
    expected_source_facts_sha256: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "source_root", Path(self.source_root).expanduser().resolve())
        object.__setattr__(self, "archive_root", Path(self.archive_root).expanduser().resolve())
        object.__setattr__(self, "destination_root", Path(self.destination_root).expanduser().resolve())
        if self.evidence_root is not None:
            object.__setattr__(self, "evidence_root", Path(self.evidence_root).expanduser().resolve())


def _json(value: Any, default: Any):
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        raise MigrationError("invalid JSON in Astrid source")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _tree_size(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file() and not path.is_symlink())


def _file_map(root: Path) -> dict[str, dict[str, Any]]:
    """Return a root-complete description, including symlink identity.

    Symlinks are never dereferenced for the archive manifest.  Recording the
    literal target and whether its resolved target stays inside the source
    root makes retarget/add/remove changes observable while allowing archive
    creation to reject an escaping link before it can become an authority.
    """
    result: dict[str, dict[str, Any]] = {}
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            target = os.readlink(path)
            resolved = path.resolve(strict=False)
            try:
                resolved.relative_to(root)
                inside = True
            except ValueError:
                inside = False
            result[relative] = {"kind": "symlink", "target": target, "resolved_inside_root": inside}
        elif path.is_file():
            result[relative] = {"kind": "file", "size": path.stat().st_size, "sha256": _sha256_file(path)}
    return result


def _files_digest(files: Mapping[str, Mapping[str, Any]]) -> str:
    return _sha256_bytes(_canonical([{"path": name, **dict(files[name])} for name in sorted(files)]))


def _table_names(conn: sqlite3.Connection) -> list[str]:
    return [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def _rows(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in conn.execute(f' SELECT * FROM "{table}"')]
    except sqlite3.OperationalError:
        return []


def _source_database(root: Path) -> Path:
    candidates = [root / ".astrid" / "astrid.sqlite3", root / "astrid.sqlite3"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise MigrationError("Astrid source database was not found")


def _assert_writer_free(source_root: Path, database: Path, probe: Callable[[], bool] | None) -> None:
    if probe is not None and not probe():
        raise MigrationError("Astrid writer freeze preflight failed; stop Astrid and retry")
    # The legacy app's lock is advisory but is enough to refuse an active
    # writer without creating or mutating source files.
    lock_paths = [database.with_suffix(database.suffix + ".lock"), database.with_suffix(".lock"), source_root / ".astrid" / "writer.lock"]
    try:
        import fcntl
    except ImportError:  # pragma: no cover
        fcntl = None
    for lock_path in lock_paths:
        if not lock_path.exists() or fcntl is None:
            continue
        handle = lock_path.open("rb")
        try:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise MigrationError("Astrid writer is active; freeze writers before migrating") from exc
            finally:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            handle.close()


class Migrator:
    def __init__(self, config: MigrationConfig, client: Any = None):
        self.config = config
        self.client = client
        self.database = _source_database(config.source_root)
        self._project_ids: dict[str, Any] = {}
        self._timeline_ids: dict[str, Any] = {}
        self._media_ids: dict[str, Any] = {}
        self._reference_ids: dict[str, Any] = {}
        self._task_ids: dict[str, Any] = {}
        self._run_ids: dict[str, Any] = {}
        self._document_ids: dict[str, Any] = {}
        self._import_counts: dict[str, int] = {}
        self._report: dict[str, Any] = {}
        self._freeze_handles: list[Any] = []

    @contextmanager
    def source_freeze(self):
        """Hold any legacy writer lock for the complete migration critical path.

        Old roots did not all have a lock file, so the lock is supplemented by
        manifest revalidation at every copy seam.  This keeps the operation
        fail-closed without creating a new authority or mutating the source.
        """
        try:
            import fcntl
        except ImportError:  # pragma: no cover
            fcntl = None
        handles = []
        if fcntl is not None:
            lock_paths = [self.database.with_suffix(self.database.suffix + ".lock"), self.database.with_suffix(".lock"), self.config.source_root / ".astrid" / "writer.lock"]
            for lock_path in lock_paths:
                if not lock_path.exists():
                    continue
                handle = lock_path.open("rb")
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    handle.close()
                    raise MigrationError("Astrid writer is active; freeze writers before migrating") from exc
                handles.append((handle, fcntl))
        self._freeze_handles = handles
        started = time.time()
        try:
            _assert_writer_free(self.config.source_root, self.database, self.config.freeze_probe)
            yield {"started_at": started, "lock_count": len(handles)}
        finally:
            for handle, module in reversed(handles):
                try:
                    module.flock(handle.fileno(), module.LOCK_UN)
                finally:
                    handle.close()
            self._freeze_handles = []

    def _source_manifest(self, inventory: Mapping[str, Any]) -> dict[str, Any]:
        """Build the immutable, root-complete identity for this source."""
        payload = {
            "format_version": 1,
            "source_root": str(self.config.source_root),
            "source_version": self.config.source_version,
            "database_sha256": inventory["database_sha256"],
            "files": inventory["files"],
            "files_sha256": inventory["files_sha256"],
            "source_facts_sha256": inventory["source_facts_sha256"],
            "row_counts": inventory["row_counts"],
            "schema_migrations": inventory["schema_migrations"],
        }
        return payload | {"source_manifest_sha256": _sha256_bytes(_canonical(payload))}

    def inventory(self) -> dict[str, Any]:
        if not self._freeze_handles:
            _assert_writer_free(self.config.source_root, self.database, self.config.freeze_probe)
        conn = sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = [dict(row) for row in conn.execute("PRAGMA foreign_key_check")]
            tables = _table_names(conn)
            counts = {table: conn.execute(f' SELECT count(*) FROM "{table}"').fetchone()[0] for table in tables}
            column_map = {table: {row[1] for row in conn.execute(f'pragma table_info("{table}")')} for table in tables}
            migrations = _rows(conn, "schema_migrations")
            media_rows = _rows(conn, "media")
            location_rows = _rows(conn, "media_locations")
        finally:
            conn.close()
        if integrity != "ok" or foreign_keys:
            raise MigrationError("Astrid source failed SQLite integrity/foreign-key preflight")
        files = _file_map(self.config.source_root)
        facts_conn = sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)
        facts_conn.row_factory = sqlite3.Row
        try:
            source_facts = {table: _rows(facts_conn, table) for table in _table_names(facts_conn)}
        finally:
            facts_conn.close()
        # Include every table and every row, not only entities currently
        # imported by the neutral client.  This is the root-complete fact
        # identity used to detect drift and to reconcile the destination.
        source_facts_sha256 = _sha256_bytes(_canonical(source_facts))
        media_dispositions = []
        estimated_cas_bytes = 0
        for media in media_rows:
            estimated_cas_bytes += int(media.get("byte_size") or 0)
            locs = [x for x in location_rows if str(x.get("media_id")) == str(media.get("id"))]
            disposition = []
            for location in locs:
                realm = str(location.get("realm") or "").lower()
                locator = str(location.get("locator") or "")
                if realm in {"remote", "http", "https"}:
                    disposition.append({"realm": realm, "disposition": "blocked_remote"})
                    continue
                path = Path(locator).expanduser()
                if not path.is_absolute():
                    path = self.config.source_root / path
                try:
                    path.resolve().relative_to(self.config.source_root)
                    inside = True
                except ValueError:
                    inside = False
                disposition.append({"realm": realm, "disposition": "readable_local" if path.is_file() and inside else "missing_or_outside_source", "relative_locator": str(path.resolve().relative_to(self.config.source_root)) if inside else "<outside-source>"})
            media_dispositions.append({"media_id": media.get("id"), "content_hash": media.get("content_hash"), "byte_size": media.get("byte_size"), "locations": disposition})
        known_columns = {"projects": {"id", "slug", "name", "settings_json", "event_head_seq", "created_at", "updated_at"}, "timelines": {"id", "project_id", "event_stream_id", "name", "document_json", "asset_registry_json", "created_at", "updated_at", "project_data_json"}, "shots": {"id", "project_id", "name", "sort_key", "metadata_json", "created_at", "updated_at"}, "project_references": {"id", "project_id", "kind", "name", "description", "metadata_json", "created_at", "updated_at", "archived_at"}, "media": {"id", "project_id", "media_kind", "mime_type", "byte_size", "content_hash", "metadata_json", "created_at"}, "media_locations": {"id", "media_id", "realm", "locator", "verified_at", "created_at"}, "media_references": {"id", "reference_id", "media_id", "role", "context_task_id", "ordinal", "is_primary", "metadata_json", "created_at"}, "media_relations": {"from_media_id", "to_media_id", "kind", "ordinal", "metadata_json", "created_at"}, "reference_links": {"from_reference_id", "to_reference_id", "kind", "metadata_json", "created_at"}, "generation_variants": {"id", "generation_id", "media_id", "variant_type", "name", "params_json", "is_primary", "starred", "viewed_at", "created_at"}, "generations": {"id", "project_id", "task_id", "type", "name", "based_on_generation_id", "parent_generation_id", "child_order", "params_json", "starred", "deleted_at", "created_at", "updated_at"}, "runs": {"id", "project_id", "event_stream_id", "kind", "status", "title", "input_json", "result_json", "started_at", "finished_at"}, "tasks": {"id", "project_id", "event_stream_id", "run_id", "run_ordinal", "capability", "spec_json", "spec_hash", "input_manifest_json", "status", "priority", "available_at", "max_attempts", "winning_attempt_id", "cancel_request_id", "cancel_requested_at", "created_at", "updated_at", "finished_at"}, "events": {"event_id", "project_id", "project_seq", "stream_id", "seq", "subject_type", "subject_id", "changes_json", "kind", "schema_version", "idempotency_key", "txn_id", "actor_kind", "payload_json", "created_at"}, "event_streams": {"id", "project_id", "stream_type", "aggregate_id", "head_seq", "created_at"}, "schema_migrations": {"pack", "version", "name", "checksum", "applied_at"}, "shot_items": {"id", "shot_id", "media_id", "sort_key", "source_frame", "metadata_json", "created_at"}, "task_dependencies": {"task_id", "depends_on_task_id", "kind", "ordinal"}, "task_outputs": {"task_id", "ordinal", "role", "media_id", "is_primary", "params_json", "created_at"}, "execution_attempts": {"id", "task_id", "attempt_no", "executor_id", "status", "status_version", "lease_id", "lease_expires_at", "heartbeat_counter", "last_heartbeat_at", "progress_json", "error_json", "created_at", "updated_at", "finished_at"}, "command_receipts": {"project_id", "idempotency_key", "request_hash", "command_kind", "txn_id", "primary_stream_id", "resulting_stream_seq", "first_project_seq", "last_project_seq", "event_ids_json", "result_json", "created_at"}, "evidence_items": {"id", "run_id", "task_id", "kind", "summary", "data_json", "media_id", "created_at"}, "runaway_transitions": {"id", "project_id", "run_id", "task_id", "ordinal", "start_ms", "duration_ms", "prompt", "metadata_json", "created_at"}}
        supported_tables = {"projects", "timelines", "shots", "project_references", "media", "media_locations", "generations", "runs", "tasks", "event_streams", "events"}
        metadata_only_tables = {"schema_migrations"}
        unmapped = {}
        unsupported = {}
        for table in tables:
            columns = column_map[table]
            if table in known_columns:
                extra = sorted(columns - known_columns[table])
                if extra:
                    unmapped[table] = extra
            else:
                unmapped[table] = sorted(columns)
            if table not in supported_tables and table not in metadata_only_tables and counts.get(table, 0):
                unsupported[table] = {"rows": counts[table], "columns": sorted(columns)}
        free_bytes = shutil.disk_usage(self.config.destination_root.parent if self.config.destination_root.parent.exists() else self.config.source_root).free
        inventory = {
            "source_root": str(self.config.source_root),
            "database": str(self.database),
            "source_version": self.config.source_version,
            "database_sha256": _sha256_file(self.database),
            "schema_migrations": migrations,
            "tables": tables,
            "row_counts": counts,
            "files": files,
            "files_sha256": _files_digest(files),
            "source_facts_sha256": source_facts_sha256,
            "integrity": {"quick_check": integrity, "foreign_key_errors": foreign_keys},
            "media_locator_dispositions": media_dispositions,
            "estimated_cas_bytes": estimated_cas_bytes,
            "destination_free_bytes": free_bytes,
            "unmapped_fields": unmapped,
            "unsupported_nonempty_tables": unsupported,
            "blockers": [],
        }
        inventory["source_manifest"] = self._source_manifest(inventory)
        inventory["source_manifest_sha256"] = inventory["source_manifest"]["source_manifest_sha256"]
        self._report["inventory"] = inventory
        return inventory

    def _load(self) -> dict[str, list[dict[str, Any]]]:
        conn = sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            return {table: _rows(conn, table) for table in _table_names(conn)}
        finally:
            conn.close()

    def validate(self, data: Mapping[str, list[dict[str, Any]]]) -> None:
        projects = data.get("projects", [])
        ids = [str(row.get("id", "")) for row in projects]
        if not all(ids) or len(ids) != len(set(ids)):
            raise MigrationError("projects contain missing or duplicate IDs")
        slugs = [str(row.get("slug", "")) for row in projects]
        if any(not slug for slug in slugs) or len(slugs) != len(set(slugs)):
            raise MigrationError("projects contain missing or duplicate slugs")
        project_set = set(ids)
        for row in data.get("timelines", []):
            if not row.get("id") or str(row.get("project_id")) not in project_set:
                raise MigrationError("timeline has an invalid project reference")
        for row in data.get("shots", []):
            if not row.get("id") or str(row.get("project_id")) not in project_set:
                raise MigrationError("shot has an invalid project reference")
        for row in data.get("project_references", []):
            if not row.get("id") or str(row.get("project_id")) not in project_set:
                raise MigrationError("reference has an invalid project reference")
        media_set = {str(row.get("id")) for row in data.get("media", [])}
        for row in data.get("media_locations", []):
            if str(row.get("media_id")) not in media_set:
                raise MigrationError("media location has an invalid media reference")
        for row in data.get("media", []):
            digest = str(row.get("content_hash") or "")
            if digest and len(digest.removeprefix("sha256:")) != 64:
                raise MigrationError(f"media {row.get('id')} has an invalid content hash")
        blockers = []
        inventory = self._report.get("inventory", {})
        for table, detail in inventory.get("unsupported_nonempty_tables", {}).items():
            blockers.append({"kind": "unmapped_table", "table": table, "rows": detail.get("rows"), "reason": "no neutral client operation in this slice"})
        for media in inventory.get("media_locator_dispositions", []):
            for location in media.get("locations", []):
                if location.get("disposition") != "readable_local":
                    blockers.append({"kind": "media_locator", "media_id": media.get("media_id"), "disposition": location.get("disposition")})
        inventory["blockers"] = blockers
        self._report["validation"] = {"ok": not blockers, "foreign_keys": "ok", "invariants": ["unique project IDs/slugs", "project-owned timelines/shots/references", "media-location foreign keys", "content hash shape"], "blockers": blockers}

    def _invoke(self, name: str, *args, **kwargs):
        if self.client is None or not hasattr(self.client, name):
            raise MigrationError(f"generated client does not expose required operation {name}")
        method = getattr(self.client, name)
        try:
            return method(*args, **kwargs)
        except TypeError:
            # Fixtures commonly use a single resource argument; accepting that
            # shape keeps the migration kernel independent of a client language.
            if args or kwargs:
                payload = dict(kwargs)
                if args and isinstance(args[-1], Mapping):
                    payload = {**payload, **dict(args[-1])}
                return method(payload)
            raise

    @staticmethod
    def _result_id(value: Any, *keys: str) -> Any:
        if isinstance(value, Mapping):
            for key in keys:
                if value.get(key) is not None:
                    return value[key]
            nested = value.get("task") or value.get("run") or value.get("project")
            if isinstance(nested, Mapping):
                return Migrator._result_id(nested, *keys)
            return None
        for key in keys:
            result = getattr(value, key, None)
            if result is not None:
                return result
        return value if value is not None else None

    def _media_bytes(self, media: Mapping[str, Any], locations: list[Mapping[str, Any]]) -> tuple[bytes, str]:
        candidates = [x for x in locations if str(x.get("media_id")) == str(media.get("id"))]
        if not candidates:
            raise MigrationError(f"media {media.get('id')} has no readable location; external_local must be ingested")
        for location in candidates:
            realm = str(location.get("realm") or "").lower()
            locator = str(location.get("locator") or "")
            if realm in {"remote", "http", "https"}:
                continue
            path = Path(locator).expanduser()
            if not path.is_absolute():
                path = self.config.source_root / path
            try:
                path = path.resolve()
                path.relative_to(self.config.source_root)
            except ValueError:
                raise MigrationError(f"media {media.get('id')} locator escapes source root")
            if path.is_file():
                raw = path.read_bytes()
                expected = str(media.get("content_hash") or "").removeprefix("sha256:")
                if expected and _sha256_bytes(raw) != expected:
                    raise MigrationError(f"media {media.get('id')} failed content hash verification")
                return raw, path.name
        raise MigrationError(f"media {media.get('id')} has no local bytes; remote media is not runnable in local-v1")

    def _assert_source_digest(self, expected: str, seam: str) -> None:
        current = self.inventory()
        if current["source_manifest_sha256"] != expected:
            raise MigrationError(f"source changed at {seam}; discard the clone and restart rehearsal")
        bound = self.config.expected_source_manifest_sha256
        if bound is not None and current["source_manifest_sha256"] != bound:
            raise MigrationError(f"source inventory no longer matches the bound freeze receipt at {seam}")
        facts = self.config.expected_source_facts_sha256
        if facts is not None and current["source_facts_sha256"] != facts:
            raise MigrationError(f"source facts no longer match the bound freeze receipt at {seam}")

    def migrate(self) -> dict[str, Any]:
        with self.source_freeze() as freeze_info:
            self._report["source_freeze"] = freeze_info
            inventory = self.inventory()
            if self.config.expected_source_manifest_sha256 is not None and inventory["source_manifest_sha256"] != self.config.expected_source_manifest_sha256:
                raise MigrationError("source inventory does not match the bound freeze receipt before migration")
            if self.config.expected_source_facts_sha256 is not None and inventory["source_facts_sha256"] != self.config.expected_source_facts_sha256:
                raise MigrationError("source facts do not match the bound freeze receipt before migration")
            frozen_source_digest = inventory["source_manifest_sha256"]
            # Re-read before and after loading so rows and bytes can never be
            # combined from two source epochs.
            self._assert_source_digest(frozen_source_digest, "pre-load")
            data = self._load()
            self._assert_source_digest(frozen_source_digest, "post-load")
            self.validate(data)
            if self.config.dry_run:
                for row in data.get("media", []):
                    self._media_bytes(row, data.get("media_locations", []))
                self._report["dry_run"] = True
                self._report["mapping"] = self._mapping_preview(data)
                self._report["reconciliation"] = self._reconcile(data, preview=True)
                return self._report
            if self._report.get("validation", {}).get("blockers"):
                raise MigrationError("migration has unresolved source facts; resolve blockers before archive/import/activation")
            archive = self._archive(inventory)
            self._assert_source_digest(frozen_source_digest, "post-archive")
            self._import(data)
            self._assert_source_digest(frozen_source_digest, "post-import")
            reconciliation = self._reconcile(data, preview=False)
            self._report["reconciliation"] = reconciliation
            if not reconciliation["ok"]:
                raise MigrationError("migration reconciliation failed; source remains untouched; see verified archive rollback")
            activation = self._activation(archive, reconciliation)
            self._report["archive"] = str(archive)
            self._report["activation_manifest"] = str(activation)
            self._report["rollback"] = str(archive / "ROLLBACK.md")
            return self._report

    def _mapping_preview(self, data):
        return {"projects": len(data.get("projects", [])), "timelines": len(data.get("timelines", [])), "shots": len(data.get("shots", [])), "references": len(data.get("project_references", [])), "generations": len(data.get("generations", [])), "media": len(data.get("media", [])), "runs": len(data.get("runs", [])), "tasks": len(data.get("tasks", []))}

    def _archive(self, inventory: Mapping[str, Any]) -> Path:
        escaping_source = [name for name, detail in inventory.get("files", {}).items() if detail.get("kind") == "symlink" and not detail.get("resolved_inside_root", False)]
        if escaping_source:
            raise MigrationError(f"source contains symlinks escaping source root: {escaping_source}")
        if self.config.archive_root.exists():
            manifest_path = self.config.archive_root / "manifest.json"
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                archived = _file_map(self.config.archive_root / "source")
            except (OSError, json.JSONDecodeError, MigrationError):
                archived = None
                manifest = {}
            archived_escaping = [name for name, detail in (archived or {}).items() if detail.get("kind") == "symlink" and not detail.get("resolved_inside_root", False)]
            if archived_escaping:
                raise MigrationError(f"archive contains symlinks escaping source root: {archived_escaping}")
            if archived == inventory.get("files") and manifest.get("source_manifest_sha256") == inventory.get("source_manifest_sha256") and manifest.get("files_sha256") == _files_digest(archived or {}):
                self._report["archive_reused"] = True
                self._report["archive_peak_bytes"] = _tree_size(self.config.archive_root)
                return self.config.archive_root
            raise MigrationError(f"archive destination already exists and does not match the frozen source: {self.config.archive_root}")
        try:
            self.config.archive_root.relative_to(self.config.source_root)
        except ValueError:
            pass
        else:
            raise MigrationError("archive must be outside source root")
        self.config.archive_root.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{self.config.archive_root.name}.", dir=self.config.archive_root.parent))
        try:
            shutil.copytree(self.config.source_root, temporary / "source", symlinks=True)
            archived_files = _file_map(temporary / "source")
            self._report["archive_peak_bytes"] = _tree_size(temporary)
            escaping = [name for name, detail in archived_files.items() if detail.get("kind") == "symlink" and not detail.get("resolved_inside_root", False)]
            if escaping:
                raise MigrationError(f"archive contains symlinks escaping source root: {escaping}")
            if archived_files != inventory["files"]:
                raise MigrationError("source changed while archive was being copied; discard the clone and restart rehearsal")
            archived_db = temporary / "source" / self.database.relative_to(self.config.source_root)
            manifest = {"format_version": 2, "source_version": self.config.source_version, "source_root": str(self.config.source_root), "files": archived_files, "files_sha256": _files_digest(archived_files), "database_sha256": _sha256_file(archived_db), "source_manifest_sha256": inventory["source_manifest_sha256"], "source_manifest": inventory["source_manifest"], "archive_source_tree_sha256": _files_digest(archived_files), "created_at": time.time()}
            (temporary / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            (temporary / "ROLLBACK.md").write_text("# Astrid migration rollback\n\nThe original source is untouched. Stop the runtime, remove the activated realm, restore the verified source archive under `source/`, and rerun the legacy launcher only after review.\n\nArchive manifest: `manifest.json`.\n")
            for path in temporary.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    path.chmod(0o400)
            if _file_map(temporary / "source") != archived_files or _sha256_file(archived_db) != manifest["database_sha256"]:
                raise MigrationError("archive bytes failed post-copy verification")
            temporary.rename(self.config.archive_root)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return self.config.archive_root

    def _import(self, data):
        # All validation and byte reads precede the first client mutation.
        locations = data.get("media_locations", [])
        media_payloads = [(row, *self._media_bytes(row, locations)) for row in data.get("media", [])]
        for row in data.get("projects", []):
            name = str(row.get("name") or row.get("slug"))
            try:
                value = self.client.create_project(name, slug=str(row.get("slug") or ""), metadata=_json(row.get("settings_json"), {}), idempotency_key=f"astrid-migrate-project-{row['id']}", legacy_id=str(row["id"]))
            except TypeError:
                value = self._invoke("create_project", name, idempotency_key=f"astrid-migrate-project-{row['id']}")
            self._project_ids[str(row["id"])] = value
            if self._result_id(value, "project_id", "id") is None:
                self._report.setdefault("unresolved", []).append({"kind": "project", "id": row.get("id"), "reason": "client returned no durable identity"})
        for row, raw, filename in media_payloads:
            value = self._invoke("ingest_object", raw, media_type=str(row.get("mime_type") or "application/octet-stream"), idempotency_key=f"astrid-migrate-media-{row['id']}", filename=filename)
            self._media_ids[str(row["id"])] = value
            if self._result_id(value, "object_id", "digest", "id") is None:
                self._report.setdefault("unresolved", []).append({"kind": "media", "id": row.get("id"), "reason": "client returned no durable identity"})
            project = self._project_ids.get(str(row.get("project_id")))
            digest = self._result_id(value, "digest", "object_id", "id")
            if project is not None and digest is not None and hasattr(self.client, "add_project_object"):
                project_id = self._result_id(project, "project_id", "id")
                self._invoke("add_project_object", project_id, digest, relation=str(row.get("media_kind") or "managed"))
        for row in data.get("timelines", []):
            project = self._project_ids[str(row["project_id"])]
            project_id = getattr(project, "project_id", project.get("project_id", project.get("id")) if isinstance(project, Mapping) else project)
            value = self._invoke("create_timeline", project_id, str(row["id"]), idempotency_key=f"astrid-migrate-timeline-{row['id']}")
            self._timeline_ids[str(row["id"])] = value
            if self._result_id(value, "timeline_id", "id") is None:
                self._report.setdefault("unresolved", []).append({"kind": "timeline", "id": row.get("id"), "reason": "client returned no durable identity"})
            document = _json(row.get("document_json"), None)
            if document is not None and hasattr(self.client, "create_document"):
                body = {"document_id": f"timeline:{row['id']}", "kind": "timeline", "content": document}
                try:
                    doc = self.client.create_document(project_id, body)
                except TypeError:
                    doc = self.client.create_document(project_id, body["document_id"], body["kind"], body["content"])
                self._document_ids[str(row["id"])] = self._result_id(doc, "document_id", "id")
        for row in data.get("shots", []):
            timeline_id = str(_json(row.get("metadata_json"), {}).get("timeline_id") or row.get("timeline_id") or "")
            if not timeline_id:
                continue
            shot = self._invoke("create_shot", timeline_id, {"shot_id": str(row["id"]), "start_ms": 0, "duration_ms": 1, "reference_ids": []}, idempotency_key=f"astrid-migrate-shot-{row['id']}")
            if self._result_id(shot, "shot_id", "id") is not None:
                self._import_counts["shots"] = self._import_counts.get("shots", 0) + 1
            else:
                self._report.setdefault("unresolved", []).append({"kind": "shot", "id": row.get("id"), "reason": "client returned no durable identity"})
        for row in data.get("project_references", []):
            project_id = str(row["project_id"])
            timeline = next((x for x in data.get("timelines", []) if str(x.get("project_id")) == project_id), None)
            if timeline and hasattr(self.client, "create_reference"):
                reference = self._invoke("create_reference", str(timeline["id"]), {"reference_id": str(row["id"]), "object_id": "", "role": row.get("kind")}, idempotency_key=f"astrid-migrate-reference-{row['id']}")
                if self._result_id(reference, "reference_id", "id") is not None:
                    self._reference_ids[str(row["id"])] = self._result_id(reference, "reference_id", "id")
                else:
                    self._report.setdefault("unresolved", []).append({"kind": "reference", "id": row.get("id"), "reason": "client returned no durable identity"})
            elif hasattr(self.client, "create_project_reference"):
                reference = self._invoke("create_project_reference", dict(row), idempotency_key=f"astrid-migrate-reference-{row['id']}")
                if self._result_id(reference, "reference_id", "id") is not None:
                    self._reference_ids[str(row["id"])] = self._result_id(reference, "reference_id", "id")
                else:
                    self._report.setdefault("unresolved", []).append({"kind": "reference", "id": row.get("id"), "reason": "client returned no durable identity"})
            else:
                self._report.setdefault("unresolved", []).append({"kind": "reference", "id": row.get("id"), "reason": "client_missing_reference_operation"})
        for row in data.get("generations", []):
            if hasattr(self.client, "create_generation"):
                # The neutral generation schema intentionally keeps the
                # legacy-only fields in metadata.  Preserve every authored
                # value rather than reducing a generation to type/id alone.
                payload = dict(row)
                payload["metadata"] = {
                    **(_json(row.get("metadata_json"), {}) or {}),
                    "legacy_name": row.get("name"),
                    "legacy_type": row.get("type"),
                    "based_on_generation_id": row.get("based_on_generation_id"),
                    "parent_generation_id": row.get("parent_generation_id"),
                    "child_order": row.get("child_order"),
                    "params": _json(row.get("params_json"), {}),
                    "starred": row.get("starred"),
                    "deleted_at": row.get("deleted_at"),
                }
                generation = self._invoke("create_generation", payload, idempotency_key=f"astrid-migrate-generation-{row['id']}")
                if self._result_id(generation, "generation_id", "id") is not None:
                    self._import_counts["generations"] = self._import_counts.get("generations", 0) + 1
                else:
                    self._report.setdefault("unresolved", []).append({"kind": "generation", "id": row.get("id"), "reason": "client returned no durable identity"})
            else:
                self._report.setdefault("unresolved", []).append({"kind": "generation", "id": row.get("id"), "reason": "client_missing_create_generation"})
        for row in data.get("tasks", []):
            project = self._project_ids.get(str(row.get("project_id")))
            project_id = self._result_id(project, "project_id", "id") if project is not None else None
            capability = str(row.get("capability") or "migration.legacy")
            spec = _json(row.get("spec_json"), {})
            key = f"astrid-migrate-task-{row['id']}"
            if hasattr(self.client, "create_task"):
                task = self._invoke("create_task", {"capability_id": capability, "capability": capability, "project": project_id, "project_id": project_id, "spec": spec, "idempotency_key": key})
            elif hasattr(self.client, "admit_task"):
                digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
                task = self.client.admit_task(capability_id=capability, capability_digest=digest, input_object_ids=[], idempotency_key=key, project_id=project_id, spec=spec)
            else:
                self._report.setdefault("unresolved", []).append({"kind": "task", "id": row.get("id"), "reason": "client_missing_task_operation"})
                continue
            self._task_ids[str(row["id"])] = task
            task_id = self._result_id(task, "task_id", "id")
            run_id = self._result_id(task, "run_id")
            if run_id is not None:
                self._run_ids[str(row.get("run_id") or run_id)] = run_id
        if hasattr(self.client, "append_migration_event"):
            for row in data.get("events", []):
                payload = _json(row.get("payload_json"), row.get("payload", {}))
                self._invoke("append_migration_event", str(row.get("kind") or row.get("event_type") or "migration.event"), payload)

    def _destination_reconciliation(self, data: Mapping[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
        reader = getattr(self.client, "destination_verification", None)
        if not callable(reader):
            reader = getattr(self.client, "destination_snapshot", None)
        if not callable(reader):
            if self.config.require_destination_verification:
                return {"ok": False, "errors": [{"kind": "destination_verification", "reason": "client must expose destination_verification() or destination_snapshot()"}]}
            return None
        try:
            truth = reader()
        except Exception as exc:
            return {"ok": False, "errors": [{"kind": "destination_read", "reason": str(exc)}]}
        errors = []
        if not isinstance(truth, Mapping):
            return {"ok": False, "errors": [{"kind": "destination_verification", "reason": "destination snapshot must be a mapping"}]}
        required_sections = ("projects", "timelines", "timeline_shots", "timeline_references", "objects", "generations", "runs", "tasks", "events", "event_streams", "media_locations", "project_objects", "foreign_key_errors")
        missing_sections = [section for section in required_sections if section not in truth]
        if self.config.require_destination_verification and missing_sections:
            errors.append({"kind": "destination_verification", "reason": "snapshot is not a complete authority snapshot", "missing": missing_sections})
        projects = truth.get("projects", [])
        by_slug = {str(row.get("slug")): row for row in projects}
        if self.config.require_destination_verification:
            def _ids(rows, *keys):
                return Counter(str(next((row.get(key) for key in keys if row.get(key) is not None), "")) for row in rows)
            # Exact sets/counts are required for every migrated entity.  The
            # old source-only loops accepted a destination that silently
            # dropped a kind or added an unrelated row.
            entity_specs = (
                ("projects", "projects", ("slug", "id")),
                ("timelines", "timelines", ("id",)),
                ("shots", "timeline_shots", ("id",)),
                ("project_references", "timeline_references", ("id",)),
                ("generations", "generations", ("id",)),
            )
            for source_name, destination_name, keys in entity_specs:
                expected_ids = _ids(data.get(source_name, []), *keys)
                actual_ids = _ids(truth.get(destination_name, []), *keys)
                if expected_ids != actual_ids:
                    errors.append({"kind": source_name, "reason": "destination entity count or identity set differs", "missing": sorted((expected_ids - actual_ids).elements()), "unexpected": sorted((actual_ids - expected_ids).elements())})
            for source_name, destination_name in (("runs", "runs"), ("tasks", "tasks")):
                if len(data.get(source_name, [])) != len(truth.get(destination_name, [])):
                    errors.append({"kind": source_name, "reason": "destination entity count differs", "source": len(data.get(source_name, [])), "destination": len(truth.get(destination_name, []))})
            expected_objects = Counter(str(row.get("content_hash") or "").removeprefix("sha256:") for row in data.get("media", []))
            actual_objects = Counter(str(row.get("digest") or row.get("content_hash") or "").removeprefix("sha256:") for row in truth.get("objects", []))
            if expected_objects != actual_objects:
                errors.append({"kind": "objects", "reason": "destination object count or content set differs", "missing": sorted((expected_objects - actual_objects).elements()), "unexpected": sorted((actual_objects - expected_objects).elements())})
            actual_project_ids = {str(row.get("id")): str(row.get("slug")) for row in projects}
            actual_relationships = Counter((actual_project_ids.get(str(row.get("project_id")), str(row.get("project_id"))), str(row.get("digest", "")).removeprefix("sha256:"), str(row.get("relation", "managed"))) for row in truth.get("project_objects", []))
            # A source media row denotes a managed project-object relation;
            # require its exact project ownership, not merely global CAS
            # presence.
            expected_relationships = Counter((str(next((p.get("slug") for p in data.get("projects", []) if str(p.get("id")) == str(m.get("project_id"))), m.get("project_id"))), str(m.get("content_hash", "")).removeprefix("sha256:"), str(m.get("media_kind") or "managed")) for m in data.get("media", []))
            if expected_relationships != actual_relationships:
                errors.append({"kind": "project_objects", "reason": "project-media relationships differ", "missing": [list(x) for x in (expected_relationships - actual_relationships).elements()], "unexpected": [list(x) for x in (actual_relationships - expected_relationships).elements()]})
        for source in data.get("projects", []):
            actual = by_slug.get(str(source.get("slug")))
            if not actual or str(actual.get("name")) != str(source.get("name")):
                errors.append({"kind": "project", "id": source.get("id"), "reason": "destination truth missing or differs"})
            elif self._result_id(self._project_ids.get(str(source.get("id"))), "project_id", "id") != actual.get("id"):
                errors.append({"kind": "project", "id": source.get("id"), "reason": "returned identity differs from destination truth"})
        for source in data.get("timelines", []):
            if not any(str(row.get("id")) == str(source.get("id")) for row in truth.get("timelines", [])):
                errors.append({"kind": "timeline", "id": source.get("id"), "reason": "missing from destination truth"})
        for source in data.get("shots", []):
            if not any(str(row.get("id")) == str(source.get("id")) for row in truth.get("timeline_shots", [])):
                errors.append({"kind": "shot", "id": source.get("id"), "reason": "missing from destination truth"})
        for source in data.get("project_references", []):
            if not any(str(row.get("id")) == str(source.get("id")) for row in truth.get("timeline_references", [])):
                errors.append({"kind": "reference", "id": source.get("id"), "reason": "missing from destination truth"})
        actual_media = {str(row.get("digest") or row.get("content_hash")) .removeprefix("sha256:") for row in truth.get("objects", [])}
        cas_objects = {str(row.get("digest")) .removeprefix("sha256:"): row for row in truth.get("cas_objects", []) if isinstance(row, Mapping)}
        for source in data.get("media", []):
            digest = str(source.get("content_hash") or "").removeprefix("sha256:")
            if digest and digest not in actual_media:
                errors.append({"kind": "media", "id": source.get("id"), "reason": "content digest missing from destination truth", "digest": digest})
            elif digest and not any(str(row.get("digest")) .removeprefix("sha256:") == digest and str(row.get("realm")) == "cas" for row in truth.get("media_locations", [])):
                errors.append({"kind": "media_location", "id": source.get("id"), "reason": "CAS location missing from destination truth", "digest": digest})
            if self.config.require_destination_verification:
                cas = cas_objects.get(digest)
                try:
                    cas_size = int(cas.get("size", -1)) if cas else -1
                except (TypeError, ValueError):
                    cas_size = -1
                locator = Path(str(cas.get("locator", ""))).expanduser() if cas else None
                bytes_verified = bool(locator and locator.is_file() and locator.stat().st_size == cas_size and _sha256_file(locator) == digest)
                expected_size = source.get("byte_size")
                try:
                    expected_size = int(expected_size) if expected_size is not None else -1
                except (TypeError, ValueError):
                    expected_size = -1
                if not cas or str(cas.get("sha256", "")).removeprefix("sha256:") != digest or cas_size != expected_size or not bytes_verified:
                    errors.append({"kind": "cas_bytes", "id": source.get("id"), "reason": "destination CAS bytes were not verified by content hash", "digest": digest})
        for source in data.get("timelines", []):
            document = _json(source.get("document_json"), None)
            if document is None:
                continue
            expected_id = f"timeline:{source['id']}"
            actual_document = next((row for row in truth.get("documents", []) if str(row.get("id")) == expected_id), None)
            if actual_document is None or _json(actual_document.get("content_json"), None) != document:
                errors.append({"kind": "timeline_document", "id": source.get("id"), "reason": "document content differs from destination truth"})
        for source in data.get("generations", []):
            actual_generation = next((row for row in truth.get("generations", []) if str(row.get("id")) == str(source.get("id"))), None)
            if actual_generation is None:
                errors.append({"kind": "generation", "id": source.get("id"), "reason": "missing from destination truth"})
            else:
                metadata = actual_generation.get("metadata")
                if metadata is None:
                    metadata = _json(actual_generation.get("metadata_json"), {})
                expected_fields = {"legacy_name": source.get("name"), "legacy_type": source.get("type"), "based_on_generation_id": source.get("based_on_generation_id"), "parent_generation_id": source.get("parent_generation_id"), "child_order": source.get("child_order"), "params": _json(source.get("params_json"), {}), "starred": source.get("starred"), "deleted_at": source.get("deleted_at")}
                if not isinstance(metadata, Mapping) or any(metadata.get(key) != value for key, value in expected_fields.items()):
                    errors.append({"kind": "generation", "id": source.get("id"), "reason": "generation authored fields differ", "expected": expected_fields, "actual": metadata})
        expected_tasks = len(data.get("tasks", []))
        if len(truth.get("tasks", [])) < expected_tasks:
            errors.append({"kind": "tasks", "reason": "destination task truth is incomplete"})
        if data.get("events") and not truth.get("events"):
            errors.append({"kind": "events", "reason": "destination event truth is empty"})
        if truth.get("events") and any(not row.get("kind") or not row.get("payload_json") for row in truth["events"]):
            errors.append({"kind": "events", "reason": "destination event truth contains incomplete records"})
        # A migration is accepted only when the raw destination ledger agrees
        # with the raw source ledger.  In particular, do not accept an
        # adapter-provided ``event_reconciliation``/attestation object: that
        # is a claim made by the wrapper, not independently observed truth.
        # This is deliberately performed even when the wrapper also returns
        # convenient booleans; a truncated or altered wrapper must fail.
        if self.config.require_destination_verification:
            source_events = list(data.get("events", []))
            destination_events = list(truth.get("events", []))
            source_streams = list(data.get("event_streams", []))
            destination_streams = list(truth.get("event_streams", []))

            def payload_digest(row):
                value = row.get("payload_json", row.get("payload", {}))
                if isinstance(value, str):
                    try:
                        value = json.loads(value)
                    except json.JSONDecodeError:
                        pass
                return hashlib.sha256(_canonical(value)).hexdigest()

            source_ids = [str(row.get("event_id", row.get("id", ""))) for row in source_events]
            destination_ids = [str(row.get("event_id", row.get("id", ""))) for row in destination_events]
            source_payloads = [payload_digest(row) for row in source_events]
            destination_payloads = [payload_digest(row) for row in destination_events]
            def stream_head(row):
                try:
                    return int(row.get("head_seq", 0))
                except (TypeError, ValueError):
                    return None
            def event_order(row):
                try:
                    seq = int(row.get("seq", 0))
                except (TypeError, ValueError):
                    seq = None
                return (str(row.get("stream_id", "")), seq)

            # A destination adapter may expose a convenience verification
            # snapshot whose rows are transformed, paged, or accidentally
            # truncated by a wrapper.  If it also exposes an independent raw
            # ledger reader, reconcile the returned rows against that second
            # authority read before applying source-to-destination checks.
            # This is intentionally separate from the old
            # ``event_reconciliation`` attestation: counts and identity sets
            # come from raw rows, not booleans asserted by the wrapper.
            raw_reader = getattr(self.client, "destination_raw_ledger", None)
            raw_truth = None
            if callable(raw_reader):
                try:
                    raw_truth = raw_reader()
                except Exception as exc:
                    errors.append({"kind": "events", "reason": "independent raw destination read failed", "details": str(exc)})
                if not isinstance(raw_truth, Mapping):
                    errors.append({"kind": "events", "reason": "independent raw destination ledger must be a mapping"})
                    raw_truth = None

            if raw_truth is not None:
                raw_events = list(raw_truth.get("events", []))
                raw_streams = list(raw_truth.get("event_streams", []))
                if len(destination_events) != len(raw_events):
                    errors.append({"kind": "events", "reason": "destination event rows are truncated or expanded", "raw": len(raw_events), "returned": len(destination_events)})
                raw_event_ids = [str(row.get("event_id", row.get("id", ""))) for row in raw_events]
                returned_event_ids = [str(row.get("event_id", row.get("id", ""))) for row in destination_events]
                if Counter(raw_event_ids) != Counter(returned_event_ids):
                    errors.append({"kind": "events", "reason": "destination event ID set differs from raw ledger", "missing": sorted((Counter(raw_event_ids) - Counter(returned_event_ids)).elements()), "unexpected": sorted((Counter(returned_event_ids) - Counter(raw_event_ids)).elements())})
                raw_event_kinds = Counter(str(row.get("kind", row.get("event_type", ""))) for row in raw_events)
                returned_event_kinds = Counter(str(row.get("kind", row.get("event_type", ""))) for row in destination_events)
                if raw_event_kinds != returned_event_kinds:
                    errors.append({"kind": "events", "reason": "destination event kind set differs from raw ledger", "missing": sorted((raw_event_kinds - returned_event_kinds).elements()), "unexpected": sorted((returned_event_kinds - raw_event_kinds).elements())})
                if len(destination_streams) != len(raw_streams):
                    errors.append({"kind": "events", "reason": "destination event stream rows are truncated or expanded", "raw": len(raw_streams), "returned": len(destination_streams)})
                raw_stream_ids = [str(row.get("id", row.get("stream_id", ""))) for row in raw_streams]
                returned_stream_ids = [str(row.get("id", row.get("stream_id", ""))) for row in destination_streams]
                if Counter(raw_stream_ids) != Counter(returned_stream_ids):
                    errors.append({"kind": "events", "reason": "destination event stream ID set differs from raw ledger", "missing": sorted((Counter(raw_stream_ids) - Counter(returned_stream_ids)).elements()), "unexpected": sorted((Counter(returned_stream_ids) - Counter(raw_stream_ids)).elements())})
                def stream_key(row):
                    return (str(row.get("id", row.get("stream_id", ""))), str(row.get("stream_type", row.get("kind", ""))), str(row.get("aggregate_id", "")), stream_head(row))
                raw_stream_keys = Counter(stream_key(row) for row in raw_streams)
                returned_stream_keys = Counter(stream_key(row) for row in destination_streams)
                if raw_stream_keys != returned_stream_keys:
                    errors.append({"kind": "events", "reason": "destination event stream set differs from raw ledger", "missing": sorted((raw_stream_keys - returned_stream_keys).elements()), "unexpected": sorted((returned_stream_keys - raw_stream_keys).elements())})
                raw_event_semantics = Counter((str(row.get("kind", row.get("event_type", ""))), payload_digest(row)) for row in raw_events)
                returned_event_semantics = Counter((str(row.get("kind", row.get("event_type", ""))), payload_digest(row)) for row in destination_events)
                if raw_event_semantics != returned_event_semantics:
                    errors.append({"kind": "events", "reason": "destination event payload set differs from raw ledger", "missing": sorted((raw_event_semantics - returned_event_semantics).elements()), "unexpected": sorted((returned_event_semantics - raw_event_semantics).elements())})

            # The neutral runtime currently emits a native event ledger whose
            # IDs and stream columns intentionally differ from legacy Astrid's
            # rows.  It still gets independently checked from the raw rows:
            # non-empty/truncation, unique IDs, valid payloads, and monotonic
            # native ordering/heads.  A legacy-preserving destination (the
            # migration contract used by external clients) takes the strict
            # source-to-destination identity path below.
            native_shape = bool(destination_events) and all(
                "event_id" not in row and "stream_id" not in row for row in destination_events
            )
            if native_shape:
                # Native runtime IDs are intentionally not the legacy event
                # IDs.  Source matching below therefore remains semantic,
                # while the independent raw-ledger comparison above enforces
                # exact counts and identity/kind/stream sets on the actual
                # destination authority.
                source_by_kind: dict[str, list[str]] = {}
                for source in source_events:
                    source_by_kind.setdefault(str(source.get("kind", "")), []).append(payload_digest(source))
                for destination in destination_events:
                    kind = str(destination.get("kind", ""))
                    digest = payload_digest(destination)
                    candidates = source_by_kind.get(kind, [])
                    if digest not in candidates:
                        errors.append({"kind": "events", "reason": "destination event is not represented by source truth", "event_kind": kind, "payload_digest": digest})
                    else:
                        candidates.remove(digest)
                destination_kinds = {str(row.get("kind", "")) for row in destination_events}
                missing_represented = {kind: len(values) for kind, values in source_by_kind.items() if values}
                if missing_represented:
                    errors.append({"kind": "events", "reason": "destination event ledger is truncated", "remaining_source_events": missing_represented})
                native_ids = [row.get("id") for row in destination_events]
                if any(value in (None, "") for value in native_ids) or len(native_ids) != len(set(map(str, native_ids))):
                    errors.append({"kind": "events", "reason": "destination event IDs are missing or duplicated", "ids": native_ids})
                if any(not row.get("kind") or not row.get("payload_json") for row in destination_events):
                    errors.append({"kind": "events", "reason": "destination event payload is missing"})
                try:
                    if native_ids != sorted(native_ids, key=lambda value: int(value)):
                        errors.append({"kind": "events", "reason": "destination event ordering differs"})
                except (TypeError, ValueError):
                    errors.append({"kind": "events", "reason": "destination event IDs are not ordered integers"})
                # Stream IDs may also be runtime-owned.  Still require the
                # complete raw stream set and reject an omitted, duplicated,
                # or unexpected stream.  When native rows expose a stream
                # reference, verify every reference resolves and every head
                # is derived from the raw event rows.
                native_stream_ids = [row.get("id", row.get("stream_id")) for row in destination_streams]
                if any(value in (None, "") for value in native_stream_ids) or len(native_stream_ids) != len(set(map(str, native_stream_ids))):
                    errors.append({"kind": "events", "reason": "destination event stream IDs are missing or duplicated", "ids": native_stream_ids})
                for stream in destination_streams:
                    stream_id = str(stream.get("id", stream.get("stream_id", "")))
                    expected_head = max((int(row.get("seq", 0)) for row in destination_events if str(row.get("stream_id")) == stream_id), default=0)
                    if stream_head(stream) != expected_head:
                        errors.append({"kind": "events", "reason": "destination stream head does not match raw events", "stream": stream_id})
            else:
                if len(source_events) != len(destination_events):
                    errors.append({"kind": "events", "reason": "event counts differ", "source": len(source_events), "destination": len(destination_events)})
                if source_ids != destination_ids:
                    errors.append({"kind": "events", "reason": "event IDs or ordering differ", "source": source_ids, "destination": destination_ids})
                if source_payloads != destination_payloads:
                    errors.append({"kind": "events", "reason": "event payload digests or ordering differ", "source": source_payloads, "destination": destination_payloads})
                source_kinds = Counter(str(row.get("kind", "")) for row in source_events)
                destination_kinds = Counter(str(row.get("kind", "")) for row in destination_events)
                if source_kinds != destination_kinds:
                    errors.append({"kind": "events", "reason": "event kind set differs", "missing": sorted((source_kinds - destination_kinds).elements()), "unexpected": sorted((destination_kinds - source_kinds).elements())})
                source_heads = [(str(row.get("id", row.get("stream_id", ""))), stream_head(row)) for row in source_streams]
                destination_heads = [(str(row.get("id", row.get("stream_id", ""))), stream_head(row)) for row in destination_streams]
                source_stream_ids = [str(row.get("id", row.get("stream_id", ""))) for row in source_streams]
                destination_stream_ids = [str(row.get("id", row.get("stream_id", ""))) for row in destination_streams]
                if len(source_streams) != len(destination_streams):
                    errors.append({"kind": "events", "reason": "event stream counts differ", "source": len(source_streams), "destination": len(destination_streams)})
                if Counter(source_stream_ids) != Counter(destination_stream_ids):
                    errors.append({"kind": "events", "reason": "event stream ID set differs", "missing": sorted((Counter(source_stream_ids) - Counter(destination_stream_ids)).elements()), "unexpected": sorted((Counter(destination_stream_ids) - Counter(source_stream_ids)).elements())})
                source_stream_kinds = Counter((str(row.get("stream_type", row.get("kind", ""))), str(row.get("aggregate_id", ""))) for row in source_streams)
                destination_stream_kinds = Counter((str(row.get("stream_type", row.get("kind", ""))), str(row.get("aggregate_id", ""))) for row in destination_streams)
                if source_stream_kinds != destination_stream_kinds:
                    errors.append({"kind": "events", "reason": "event stream kind/aggregate set differs", "missing": sorted((source_stream_kinds - destination_stream_kinds).elements()), "unexpected": sorted((destination_stream_kinds - source_stream_kinds).elements())})
                if source_heads != destination_heads:
                    errors.append({"kind": "events", "reason": "event stream heads differ", "source": source_heads, "destination": destination_heads})
                source_order = [event_order(row) for row in source_events]
                destination_order = [event_order(row) for row in destination_events]
                if source_order != destination_order:
                    errors.append({"kind": "events", "reason": "event stream order differs", "source": source_order, "destination": destination_order})
        if truth.get("foreign_key_errors"):
            errors.append({"kind": "foreign_keys", "reason": "destination foreign-key check failed", "details": truth["foreign_key_errors"]})
        return {"ok": not errors, "errors": errors, "counts": {key: len(value) for key, value in truth.items() if isinstance(value, list)}, "truth": truth}

    def _reconcile(self, data, *, preview: bool) -> dict[str, Any]:
        expected = self._mapping_preview(data)
        actual = {"projects": len(self._project_ids), "timelines": len(self._timeline_ids), "shots": self._import_counts.get("shots", 0), "references": len(self._reference_ids), "generations": self._import_counts.get("generations", 0), "media": len(self._media_ids), "runs": len(self._run_ids), "tasks": len(self._task_ids), "documents": len(self._document_ids)} if not preview else {}
        unresolved = self._report.get("unresolved", [])
        blockers = list(self._report.get("inventory", {}).get("blockers", [])) + unresolved
        source_facts_sha256 = self._report.get("inventory", {}).get("source_facts_sha256") or _sha256_bytes(_canonical({table: data.get(table, []) for table in sorted(data)}))
        destination = None if preview else self._destination_reconciliation(data)
        if destination is not None and not destination["ok"]:
            blockers.extend(destination["errors"])
        if not preview and destination is None:
            # A language client without a read surface is supported for the
            # legacy unit fixtures, but a write response must carry an actual
            # identity.  A no-op client therefore fails closed.
            missing = [kind for kind, values in (("project", self._project_ids), ("timeline", self._timeline_ids), ("media", self._media_ids), ("reference", self._reference_ids), ("task", self._task_ids)) if any(value is None for value in values.values())]
            if missing:
                blockers.append({"kind": "destination_truth", "reason": "client returned no durable identities", "entities": missing})
        return {"ok": not blockers, "expected": expected, "mapped": actual, "unresolved": unresolved, "blockers": blockers, "event_heads": {"source_events": len(data.get("events", [])), "source_streams": len(data.get("event_streams", []))}, "foreign_keys": "ok", "sqlite_integrity": "ok", "source_facts_sha256": source_facts_sha256, "source_counts": expected, "mapped_counts": actual, "destination_truth": destination}

    def _activation(self, archive: Path, reconciliation: Mapping[str, Any]) -> Path:
        self.config.destination_root.mkdir(parents=True, exist_ok=True)
        payload = {"format_version": 1, "state": "activated", "source_archive": str(archive), "source_archive_sha256": _sha256_file(archive / "manifest.json"), "source_version": self.config.source_version, "destination_root": str(self.config.destination_root), "reconciliation": reconciliation, "rollback_archive": str(archive), "created_at": time.time()}
        target = self.config.destination_root / "activation-manifest.json"
        fd, temporary = tempfile.mkstemp(prefix=".activation-", dir=self.config.destination_root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            target.chmod(0o600)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return target


def migrate(config: MigrationConfig, client: Any = None) -> dict[str, Any]:
    return Migrator(config, client).migrate()
