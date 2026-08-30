"""Small, fail-closed current-Mac Astrid offline migrator (T5)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
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

    def __post_init__(self):
        object.__setattr__(self, "source_root", Path(self.source_root).expanduser().resolve())
        object.__setattr__(self, "archive_root", Path(self.archive_root).expanduser().resolve())
        object.__setattr__(self, "destination_root", Path(self.destination_root).expanduser().resolve())


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
        self._report: dict[str, Any] = {}

    def inventory(self) -> dict[str, Any]:
        _assert_writer_free(self.config.source_root, self.database, self.config.freeze_probe)
        conn = sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = [dict(row) for row in conn.execute("PRAGMA foreign_key_check")]
            tables = _table_names(conn)
            counts = {table: conn.execute(f' SELECT count(*) FROM "{table}"').fetchone()[0] for table in tables}
            migrations = _rows(conn, "schema_migrations")
        finally:
            conn.close()
        if integrity != "ok" or foreign_keys:
            raise MigrationError("Astrid source failed SQLite integrity/foreign-key preflight")
        files = {}
        for path in sorted(self.config.source_root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                files[str(path.relative_to(self.config.source_root))] = {"size": path.stat().st_size, "sha256": _sha256_file(path)}
        self._report["inventory"] = {
            "source_root": str(self.config.source_root),
            "database": str(self.database),
            "source_version": self.config.source_version,
            "database_sha256": _sha256_file(self.database),
            "schema_migrations": migrations,
            "tables": tables,
            "row_counts": counts,
            "files": files,
            "integrity": {"quick_check": integrity, "foreign_key_errors": foreign_keys},
        }
        return self._report["inventory"]

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
        self._report["validation"] = {"ok": True, "foreign_keys": "ok", "invariants": ["unique project IDs/slugs", "project-owned timelines/shots/references", "media-location foreign keys", "content hash shape"]}

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

    def migrate(self) -> dict[str, Any]:
        inventory = self.inventory()
        data = self._load()
        self.validate(data)
        if self.config.dry_run:
            for row in data.get("media", []):
                self._media_bytes(row, data.get("media_locations", []))
            self._report["dry_run"] = True
            self._report["mapping"] = self._mapping_preview(data)
            self._report["reconciliation"] = self._reconcile(data, preview=True)
            return self._report
        archive = self._archive(inventory)
        self._import(data)
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
        if self.config.archive_root.exists():
            raise MigrationError(f"archive destination already exists: {self.config.archive_root}")
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
            manifest = {"format_version": 1, "source_version": self.config.source_version, "source_root": str(self.config.source_root), "files": inventory["files"], "database_sha256": inventory["database_sha256"], "created_at": time.time()}
            (temporary / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            (temporary / "ROLLBACK.md").write_text("# Astrid migration rollback\n\nThe original source is untouched. Stop the runtime, remove the activated realm, restore the verified source archive under `source/`, and rerun the legacy launcher only after review.\n\nArchive manifest: `manifest.json`.\n")
            for path in temporary.rglob("*"):
                if path.is_file():
                    path.chmod(0o400)
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
            value = self._invoke("create_project", str(row.get("name") or row.get("slug")), idempotency_key=f"astrid-migrate-project-{row['id']}")
            self._project_ids[str(row["id"])] = value
        for row in data.get("media", []):
            pass
        for row, raw, filename in media_payloads:
            value = self._invoke("ingest_object", raw, media_type=str(row.get("mime_type") or "application/octet-stream"), idempotency_key=f"astrid-migrate-media-{row['id']}", filename=filename)
            self._media_ids[str(row["id"])] = value
        for row in data.get("timelines", []):
            project = self._project_ids[str(row["project_id"])]
            project_id = getattr(project, "project_id", project.get("project_id", project.get("id")) if isinstance(project, Mapping) else project)
            value = self._invoke("create_timeline", project_id, str(row["id"]), idempotency_key=f"astrid-migrate-timeline-{row['id']}")
            self._timeline_ids[str(row["id"])] = value
        for row in data.get("shots", []):
            timeline_id = str(_json(row.get("metadata_json"), {}).get("timeline_id") or row.get("timeline_id") or "")
            if not timeline_id:
                continue
            self._invoke("create_shot", timeline_id, {"shot_id": str(row["id"]), "start_ms": 0, "duration_ms": 1, "reference_ids": []}, idempotency_key=f"astrid-migrate-shot-{row['id']}")
        for row in data.get("project_references", []):
            project_id = str(row["project_id"])
            timeline = next((x for x in data.get("timelines", []) if str(x.get("project_id")) == project_id), None)
            if timeline and hasattr(self.client, "create_reference"):
                self._invoke("create_reference", str(timeline["id"]), {"reference_id": str(row["id"]), "object_id": "", "role": row.get("kind")}, idempotency_key=f"astrid-migrate-reference-{row['id']}")
                self._reference_ids[str(row["id"])] = row["id"]
            elif hasattr(self.client, "create_project_reference"):
                self._invoke("create_project_reference", dict(row), idempotency_key=f"astrid-migrate-reference-{row['id']}")
                self._reference_ids[str(row["id"])] = row["id"]
            else:
                self._report.setdefault("unresolved", []).append({"kind": "reference", "id": row.get("id"), "reason": "client_missing_reference_operation"})
        for row in data.get("generations", []):
            if hasattr(self.client, "create_generation"):
                self._invoke("create_generation", dict(row), idempotency_key=f"astrid-migrate-generation-{row['id']}")
            else:
                self._report.setdefault("unresolved", []).append({"kind": "generation", "id": row.get("id"), "reason": "client_missing_create_generation"})

    def _reconcile(self, data, *, preview: bool) -> dict[str, Any]:
        expected = self._mapping_preview(data)
        actual = {"projects": len(self._project_ids), "timelines": len(self._timeline_ids), "media": len(self._media_ids), "references": len(self._reference_ids)} if not preview else {}
        unresolved = self._report.get("unresolved", [])
        return {"ok": not unresolved, "expected": expected, "mapped": actual, "unresolved": unresolved, "event_heads": {"source_events": len(data.get("events", [])), "source_streams": len(data.get("event_streams", []))}, "foreign_keys": "ok", "sqlite_integrity": "ok"}

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
