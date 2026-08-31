"""Consistent local backup, verification, restore, and structured export.

Backups are self-contained directories.  SQLite is copied with the online
backup API while the realm writer is held, and every append-only CAS object is
copied alongside a digest manifest.  Restore never replaces an existing realm;
it prepares a new directory and atomically renames it into place only after
SQLite, foreign keys, and every CAS hash pass verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
import stat

from .errors import ConflictError, NotFoundError, ValidationError
from .util import atomic_json_write, canonical_json, now


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _authenticated_digest(payload: dict) -> str:
    """Digest a JSON object using the runtime's canonical wire encoding."""
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _auth_payload(value: dict) -> dict:
    return {key: item for key, item in value.items() if key not in {"manifest_sha256", "manifest_hmac", "handoff_sha256", "handoff_hmac"}}


def _key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:32]


def _provision_key(path: Path, *, rotate: bool = False) -> bytes:
    """Provision a private operator key outside the backup directory."""
    path = path.expanduser().resolve()
    if path.exists() and not rotate:
        if path.is_symlink() or not path.is_file():
            raise ConflictError("backup authentication key is not a regular file")
        key = path.read_bytes()
        if len(key) < 32:
            raise ConflictError("backup authentication key is too short")
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return key


def provision_backup_key(path: str | Path, *, rotate: bool = False) -> dict:
    """Provision/rotate a backup key without placing it in any backup.

    Rotation intentionally leaves existing backups bound to their old key;
    operators can verify those backups by supplying the retained old key via
    ``verify_backup(..., key=...)``.
    """
    key = _provision_key(Path(path), rotate=rotate)
    return {"path": str(Path(path).expanduser().resolve()), "key_id": _key_id(key), "algorithm": "hmac-sha256"}


def _resolve_key(manifest: dict, *, key: bytes | None = None, key_path: str | Path | None = None) -> bytes:
    if key is not None:
        value = bytes(key)
    else:
        auth = manifest.get("authentication")
        if not isinstance(auth, dict):
            raise ConflictError("backup authentication metadata is missing")
        candidate = key_path or auth.get("key_path")
        if not candidate:
            raise ConflictError("backup authentication key is not provisioned")
        path = Path(str(candidate)).expanduser().resolve()
        if path.is_symlink() or not path.is_file():
            raise ConflictError("backup authentication key is unavailable")
        value = path.read_bytes()
    if len(value) < 32:
        raise ConflictError("backup authentication key is too short")
    auth = manifest.get("authentication")
    if not isinstance(auth, dict) or auth.get("algorithm") != "hmac-sha256" or auth.get("key_id") != _key_id(value):
        raise ConflictError("backup authentication key does not match manifest realm")
    return value


def _manifest_mac(manifest: dict, key: bytes) -> str:
    return hmac.new(key, canonical_json(_auth_payload(manifest)).encode("utf-8"), hashlib.sha256).hexdigest()


def _file_record(path: Path) -> dict:
    return {"sha256": _sha256(path), "size": path.stat().st_size}


def _manifest_digest_payload(manifest: dict) -> dict:
    return {key: value for key, value in manifest.items() if key not in {"manifest_sha256", "manifest_hmac"}}


def _handoff_digest_payload(handoff: dict) -> dict:
    return {key: value for key, value in handoff.items() if key not in {"handoff_sha256", "handoff_hmac"}}


def _object_path(cas_root: Path, digest: str) -> Path:
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValidationError("invalid CAS digest")
    return cas_root / digest[:2] / digest[2:]


def cas_manifest(store, *, cas_root: Path | None = None) -> dict:
    root = Path(cas_root or store.cas_root)
    rows = store.conn.execute("SELECT digest, size, media_type, original_name, created_at FROM objects ORDER BY digest").fetchall()
    objects = []
    for row in rows:
        digest = row["digest"]
        path = _object_path(root, digest)
        if not path.is_file():
            raise NotFoundError("CAS object is missing", details={"digest": digest})
        actual_size = path.stat().st_size
        actual_hash = _sha256(path)
        if actual_hash != digest or actual_size != int(row["size"]):
            raise ConflictError("CAS object failed backup verification", details={"digest": digest, "actual_digest": actual_hash, "actual_size": actual_size})
        objects.append({"digest": digest, "size": actual_size, "sha256": actual_hash, "media_type": row["media_type"], "original_name": row["original_name"], "created_at": row["created_at"]})
    payload = {"format_version": 1, "objects": objects}
    encoded = canonical_json(payload).encode()
    return payload | {"manifest_sha256": hashlib.sha256(encoded).hexdigest()}


def _verify_cas_manifest(root: Path, manifest: dict) -> None:
    expected_manifest_hash = manifest.get("manifest_sha256")
    payload = {"format_version": manifest.get("format_version"), "objects": manifest.get("objects", [])}
    if expected_manifest_hash != hashlib.sha256(canonical_json(payload).encode()).hexdigest():
        raise ConflictError("CAS manifest hash mismatch")
    cas_root = root / "cas" / "sha256"
    for obj in payload["objects"]:
        path = _object_path(cas_root, obj["digest"])
        if not path.is_file() or path.stat().st_size != int(obj["size"]) or _sha256(path) != obj["sha256"] or obj["sha256"] != obj["digest"]:
            raise ConflictError("backup CAS object failed verification", details={"digest": obj.get("digest")})


def verify_backup(backup_dir: str | Path, *, allow_legacy: bool = False, key: bytes | None = None, key_path: str | Path | None = None) -> dict:
    root = Path(backup_dir).expanduser().resolve()
    manifest_path = root / "manifest.json"
    cas_manifest_path = root / "cas-manifest.json"
    database_path = root / "realm.sqlite3"
    if not manifest_path.is_file() or not cas_manifest_path.is_file() or not database_path.is_file():
        raise NotFoundError("backup is incomplete", details={"backup": str(root)})
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConflictError("backup manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise ConflictError("backup manifest must be an object")
    format_version = manifest.get("format_version")
    if format_version == 1:
        if not allow_legacy:
            raise ConflictError("legacy backup format requires explicit migration")
        # Compatibility is deliberately opt-in.  New backups use the
        # authenticated v2 envelope below and never take this path.
        if manifest.get("database_sha256") != _sha256(database_path):
            raise ConflictError("backup SQLite hash mismatch")
    elif format_version == 2:
        digest = manifest.get("manifest_sha256")
        mac = manifest.get("manifest_hmac")
        if not isinstance(digest, str) or not hmac.compare_digest(digest, _authenticated_digest(_manifest_digest_payload(manifest))):
            raise ConflictError("backup manifest authentication failed (public digest mismatch)")
        auth_key = _resolve_key(manifest, key=key, key_path=key_path)
        if not isinstance(mac, str) or not hmac.compare_digest(mac, _manifest_mac(manifest, auth_key)):
            raise ConflictError("backup manifest authentication failed")
        realm_meta = manifest.get("realm")
        schema_meta = manifest.get("schema")
        files = manifest.get("files")
        if not isinstance(realm_meta, dict) or not realm_meta.get("id") or not isinstance(schema_meta, dict) or not isinstance(schema_meta.get("version"), int) or not isinstance(files, dict):
            raise ConflictError("backup manifest metadata is incomplete")
        if manifest.get("realm_id") != realm_meta["id"] or manifest.get("schema_version") != schema_meta["version"]:
            raise ConflictError("backup manifest metadata aliases mismatch")
        for name, path in (("realm.sqlite3", database_path), ("cas-manifest.json", cas_manifest_path)):
            record = files.get(name)
            if not isinstance(record, dict) or record.get("sha256") != _sha256(path) or int(record.get("size", -1)) != path.stat().st_size:
                raise ConflictError("backup file digest mismatch", details={"file": name})
    else:
        raise ConflictError("unsupported backup format", details={"format_version": format_version})
    if manifest.get("database_sha256") != _sha256(database_path):
        raise ConflictError("backup SQLite hash mismatch")
    try:
        cas = json.loads(cas_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConflictError("backup CAS manifest is invalid") from exc
    if manifest.get("cas_manifest_sha256") != cas.get("manifest_sha256"):
        raise ConflictError("backup CAS manifest hash mismatch")
    _verify_cas_manifest(root, cas)
    connection = sqlite3.connect(database_path)
    try:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ConflictError("backup SQLite quick check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ConflictError("backup SQLite foreign-key check failed")
        realm = connection.execute("SELECT id, display_name FROM realm LIMIT 1").fetchone()
        if not realm or realm[0] != manifest.get("realm_id"):
            raise ConflictError("backup realm identity mismatch")
    finally:
        connection.close()
    # Never expose the operator key through an API response: this result is
    # serialized by the HTTP server for backup callers.
    return {"manifest": manifest, "cas_manifest": cas}


def verify_restore_candidate(candidate_dir: str | Path) -> dict:
    """Verify a restored realm against its immutable backup handoff.

    This must run immediately before every activation and reuse.  In
    particular, a database edit (including an extra project) changes the
    candidate digest and is rejected before the active realm is touched.
    """
    root = Path(candidate_dir).expanduser().resolve()
    handoff_path = root / "activation-handoff.json"
    database = root / "realm.sqlite3"
    cas_root = root / "cas" / "sha256"
    if not handoff_path.is_file() or not database.is_file() or not cas_root.is_dir():
        raise ConflictError("restore candidate is incomplete")
    try:
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConflictError("restore candidate handoff is invalid") from exc
    source_backup = Path(str(handoff.get("source_backup", ""))).expanduser().resolve()
    verified = verify_backup(source_backup)
    source_manifest = verified["manifest"]
    if handoff.get("format_version") != 2:
        raise ConflictError("legacy restore handoff requires explicit migration")
    handoff_digest = handoff.get("handoff_sha256")
    handoff_mac = handoff.get("handoff_hmac")
    auth_key = _resolve_key(source_manifest)
    if not isinstance(handoff_digest, str) or not hmac.compare_digest(handoff_digest, _authenticated_digest(_handoff_digest_payload(handoff))):
        raise ConflictError("restore handoff authentication failed")
    if not isinstance(handoff_mac, str) or not auth_key or not hmac.compare_digest(handoff_mac, hmac.new(auth_key, canonical_json(_auth_payload(handoff)).encode("utf-8"), hashlib.sha256).hexdigest()):
        raise ConflictError("restore handoff authentication failed")
    if handoff.get("source_manifest_sha256") != _sha256(source_backup / "manifest.json"):
        raise ConflictError("restore handoff source manifest mismatch")
    if handoff.get("realm_id") != source_manifest.get("realm_id"):
        raise ConflictError("restore candidate realm does not match its backup")
    candidate_db_hash = _sha256(database)
    if handoff.get("candidate_database_sha256") != candidate_db_hash or candidate_db_hash != source_manifest.get("database_sha256"):
        raise ConflictError("restore candidate SQLite bytes differ from its verified backup")
    expected_objects = {str(item["digest"]): item for item in verified["cas_manifest"].get("objects", [])}
    actual_objects = {}
    for path in cas_root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            digest = path.parent.name + path.name
            actual_objects[digest] = path
    if set(actual_objects) != set(expected_objects):
        raise ConflictError("restore candidate CAS object set differs from its verified backup")
    for digest, item in expected_objects.items():
        path = actual_objects[digest]
        if path.stat().st_size != int(item["size"]) or _sha256(path) != item["sha256"]:
            raise ConflictError("restore candidate CAS bytes differ from its verified backup", details={"digest": digest})
    from .store import RealmStore
    restored = RealmStore(root, acquire_owner=False)
    try:
        report = restored.doctor()
        if not report["ok"]:
            raise ConflictError("restore candidate failed integrity checks", details=report)
        realm = restored.realm
    finally:
        restored.close()
    if realm["id"] != source_manifest.get("realm_id"):
        raise ConflictError("restore candidate realm identity mismatch")
    return {"handoff": handoff, "manifest": source_manifest, "doctor": report, "database_sha256": candidate_db_hash, "cas_manifest_sha256": verified["cas_manifest"].get("manifest_sha256")}


def create_backup(store, destination: str | Path, *, binding: dict | None = None, key: bytes | None = None, key_path: str | Path | None = None) -> dict:
    destination = Path(destination).expanduser().resolve()
    if destination.exists():
        raise ConflictError("backup destination already exists", details={"destination": str(destination)})
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    try:
        (temporary / "cas" / "sha256").mkdir(parents=True)
        with store._mutex:
            cas = cas_manifest(store)
            target_db = temporary / "realm.sqlite3"
            source = sqlite3.connect(store.db_path)
            target = sqlite3.connect(target_db)
            try:
                source.backup(target)
                target.commit()
            finally:
                target.close()
                source.close()
            for obj in cas["objects"]:
                source_path = _object_path(store.cas_root, obj["digest"])
                target_path = _object_path(temporary / "cas" / "sha256", obj["digest"])
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, target_path)
            atomic_json_write(temporary / "cas-manifest.json", cas)
            realm = store.realm
            schema_version = store.conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            auth_path = Path(key_path or (store.root / ".operator-backup-key")).expanduser().resolve()
            auth_key = bytes(key) if key is not None else _provision_key(auth_path)
            if len(auth_key) < 32:
                raise ConflictError("backup authentication key is too short")
            manifest = {
                "format_version": 2,
                "created_at": now(),
                "realm": {"id": realm["id"], "display_name": realm["display_name"]},
                "schema": {"version": schema_version},
                "files": {"realm.sqlite3": _file_record(target_db), "cas-manifest.json": _file_record(temporary / "cas-manifest.json")},
                # Stable aliases make the transition readable to existing
                # operators while the authenticated envelope is authoritative.
                "schema_version": schema_version,
                "realm_id": realm["id"],
                "display_name": realm["display_name"],
                "database_sha256": _sha256(target_db),
                "cas_manifest_sha256": cas["manifest_sha256"],
                "authentication": {"algorithm": "hmac-sha256", "key_id": _key_id(auth_key), "key_path": str(auth_path)},
            }
            if binding is not None:
                manifest["destination_binding"] = dict(binding)
            manifest["manifest_sha256"] = _authenticated_digest(manifest)
            manifest["manifest_hmac"] = _manifest_mac(manifest, auth_key)
            atomic_json_write(temporary / "manifest.json", manifest)
        temporary.rename(destination)
        return verify_backup(destination, key=auth_key)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def restore_backup(backup_dir: str | Path, destination: str | Path) -> dict:
    source = Path(backup_dir).expanduser().resolve()
    destination = Path(destination).expanduser().resolve()
    if destination.exists():
        raise ConflictError("restore destination must be a new inactive realm", details={"destination": str(destination)})
    verified = verify_backup(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent))
    try:
        shutil.copy2(source / "realm.sqlite3", temporary / "realm.sqlite3")
        shutil.copytree(source / "cas", temporary / "cas")
        from .store import RealmStore
        restored = RealmStore(temporary, acquire_owner=False)
        try:
            report = restored.doctor()
            if not report["ok"]:
                raise ConflictError("restored realm failed integrity checks", details=report)
            realm = restored.realm
        finally:
            restored.close()
        handoff = {"format_version": 2, "state": "prepared", "realm_id": realm["id"], "display_name": realm["display_name"], "source_backup": str(source), "source_manifest_sha256": _sha256(source / "manifest.json"), "source_database_sha256": verified["manifest"].get("database_sha256"), "source_cas_manifest_sha256": verified["manifest"].get("cas_manifest_sha256"), "candidate_database_sha256": _sha256(temporary / "realm.sqlite3"), "candidate_cas_manifest_sha256": verified["cas_manifest"].get("manifest_sha256"), "prepared_at": now()}
        handoff["handoff_sha256"] = _authenticated_digest(handoff)
        auth_key = _resolve_key(verified["manifest"])
        handoff["handoff_hmac"] = hmac.new(auth_key, canonical_json(_auth_payload(handoff)).encode("utf-8"), hashlib.sha256).hexdigest()
        atomic_json_write(temporary / "activation-handoff.json", handoff)
        temporary.rename(destination)
        return {"destination": str(destination), "realm_id": realm["id"], "activation_handoff": str(destination / "activation-handoff.json"), "source_manifest_sha256": handoff["source_manifest_sha256"], "verification": verified["manifest"]}
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def structured_export(store) -> dict:
    def rows(query, transform=None):
        values = [dict(row) for row in store.conn.execute(query)]
        return [transform(value) if transform else value for value in values]

    projects = rows("SELECT * FROM projects ORDER BY created_at", lambda value: value | {"metadata": json.loads(value.pop("metadata_json"))})
    runs = rows("SELECT * FROM runs ORDER BY created_at", lambda value: value | {"spec": json.loads(value.pop("spec_json"))})
    tasks = rows("SELECT * FROM tasks ORDER BY created_at", lambda value: value | {"spec": json.loads(value.pop("spec_json")), **({"result": json.loads(value["result_json"])} if value.get("result_json") else {})})
    for task in tasks:
        task.pop("result_json", None)
        if task.get("expected_effect_json"):
            task["expected_effect"] = json.loads(task.pop("expected_effect_json"))
        else:
            task.pop("expected_effect_json", None)
    events = rows("SELECT * FROM events ORDER BY id", lambda value: value | {"payload": json.loads(value.pop("payload_json"))})
    capabilities = rows("SELECT * FROM capabilities ORDER BY id", lambda value: value | {"required_resource_keys": json.loads(value.pop("required_resource_keys_json"))})
    workers = rows("SELECT * FROM workers ORDER BY id", lambda value: value | {"capabilities": json.loads(value.pop("capabilities_json")), "resource_keys": json.loads(value.pop("resource_keys_json"))})
    reservations = rows("SELECT * FROM reservations ORDER BY task_id, resource_key")
    documents = rows("SELECT * FROM project_documents ORDER BY project_id, created_at, id", lambda value: value | {"content": json.loads(value.pop("content_json"))})
    generations = rows("SELECT * FROM generations ORDER BY project_id, created_at, id", lambda value: value | {"metadata": json.loads(value.pop("metadata_json"))})
    variants = rows("SELECT * FROM generation_variants ORDER BY generation_id, created_at, id", lambda value: value | {"metadata": json.loads(value.pop("metadata_json"))})
    owner_records = rows("SELECT source_table, source_key, source_ordinal, row_json, row_sha256, created_at FROM migration_owner_records ORDER BY source_table, source_ordinal, source_key")
    for record in owner_records:
        record["row"] = json.loads(record.pop("row_json"))
    return {"format_version": 1, "exported_at": now(), "realm": store.realm, "projects": projects, "objects": rows("SELECT * FROM objects ORDER BY digest"), "project_objects": rows("SELECT * FROM project_objects ORDER BY project_id, digest, relation"), "documents": documents, "runs": runs, "tasks": tasks, "events": events, "capabilities": capabilities, "workers": workers, "reservations": reservations, "generations": generations, "variants": variants, "migration_owner_records": owner_records}
