"""Fail-closed operator entry points for the real B12 Astrid migration.

The ordinary ``astrid-migrate`` command is intentionally offline.  This module
is the small, explicit bridge to :func:`run_live_migration`: it requires an
operator-selected source, realm, six nonce-bound authorizations, and a
writer-stop receipt.  It never guesses a source root or stops a process by
name.  A real host must stop legacy writers first and then provide the receipt.

The normalizer is similarly explicit.  It is only for the historical nested
Astrid intro layout; it clones into a fresh destination and rewrites verified
media locators in the clone, never the source.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
from typing import Any, Callable, Mapping

from banodoco_local.astrid_live_bridge import open_runtime
from .boundary import atomic_json_write, capture_parent, close_pinned, durable_json_bytes
from .live import LIVE_AUTHORIZATION_IDS, issue_live_authorizations, run_live_migration
from .migrator import (
    MigrationConfig,
    MigrationError,
    Migrator,
    _assert_writer_free,
    _sha256_file,
    _source_database,
)


CONFIRMATION = "MIGRATE LIVE ASTRID"

def _absolute(path: str | Path, *, label: str) -> Path:
    value = Path(path).expanduser()
    if not value.is_absolute():
        raise MigrationError(f"{label} must be an absolute path")
    return Path(os.path.abspath(str(value)))


def _has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
    return False


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _require_source(path: str | Path) -> tuple[Path, Path]:
    source = _absolute(path, label="source root")
    if _has_symlink_component(source) or source.is_symlink():
        raise MigrationError("source root must not contain a symlink component")
    if not source.is_dir():
        raise MigrationError(f"explicit source root is not a directory: {source}")
    database = _source_database(source)
    if _has_symlink_component(database) or not database.is_file():
        raise MigrationError("source database must be a regular file below the explicit source root")
    return source, database


def _reject_collisions(source: Path, active: Path, archive: Path, destination: Path, evidence: Path, support: Path) -> None:
    named = (("active realm", active), ("archive", archive), ("destination", destination), ("evidence", evidence), ("support", support))
    for label, path in named:
        if path == source or _inside(path, source) or _inside(source, path):
            raise MigrationError(f"source root collides with {label}: {source} / {path}")
    for left_name, left in named:
        for right_name, right in named:
            if left_name < right_name and (left == right or _inside(left, right) or _inside(right, left)):
                raise MigrationError(f"{left_name} collides with {right_name}: {left} / {right}")
    for label, path in named:
        if _has_symlink_component(path):
            raise MigrationError(f"{label} path contains a symlink component: {path}")


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    if _has_symlink_component(path) or not path.is_file():
        raise MigrationError(f"{label} is missing or contains a symlink: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise MigrationError(f"{label} is not valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise MigrationError(f"{label} must contain a JSON object: {path}")
    return value


def _require_owner_only(path: Path, *, label: str) -> None:
    try:
        value = path.lstat()
    except OSError as exc:
        raise MigrationError(f"{label} is unavailable: {path}") from exc
    if not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o600:
        raise MigrationError(f"{label} must be a regular owner-only 0600 file: {path}")
    if hasattr(os, "getuid") and value.st_uid != os.getuid():
        raise MigrationError(f"{label} must be owned by the current operator: {path}")


def _write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    """Publish a new operator artifact without silently replacing one."""
    if not path.is_absolute() or _has_symlink_component(path):
        raise MigrationError(f"output path must be absolute and symlink-free: {path}")
    if not path.parent.is_dir() or _has_symlink_component(path.parent):
        raise MigrationError(f"output parent must already be a normal directory: {path.parent}")
    if os.path.lexists(str(path)):
        raise MigrationError(f"refusing to replace existing operator artifact: {path}")
    # runtime_protocol's descriptor-pinned publication is used for the
    # auth/normalization receipts too; no credentials cross stdout.
    identity = capture_parent(path, require_fresh_target=True)
    try:
        atomic_json_write(path, durable_json_bytes(value), identity=identity)
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    finally:
        close_pinned(identity)


def _load_trust_key(support: Path) -> bytes:
    path = support / "activation-trust.json"
    value = _read_json(path, label="activation trust anchor")
    if value.get("version") != 1 or not isinstance(value.get("key_hex"), str):
        raise MigrationError("activation trust anchor has an unsupported format")
    try:
        key = bytes.fromhex(value["key_hex"])
    except ValueError as exc:
        raise MigrationError("activation trust anchor is not hexadecimal") from exc
    if len(key) < 32 or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise MigrationError("activation trust anchor must be owner-only and at least 32 bytes")
    if hasattr(os, "getuid") and path.stat().st_uid != os.getuid():
        raise MigrationError("activation trust anchor is not owned by the current operator")
    return key


def _require_catalog(support: Path, active: Path, realm_id: str) -> None:
    catalog_path = support / "catalog.json"
    value = _read_json(catalog_path, label="neutral realm catalog")
    if value.get("version") != 1 or value.get("selected_realm_id") != realm_id:
        raise MigrationError("neutral catalog does not select the explicitly requested realm")
    realms = [row for row in value.get("realms", []) if isinstance(row, Mapping)]
    matching = [row for row in realms if str(row.get("realm_id")) == realm_id]
    if len(realms) != 1 or len(matching) != 1:
        raise MigrationError("Stage 1 requires exactly one selected neutral realm")
    if _absolute(str(matching[0].get("data_root", "")), label="catalog realm root") != active:
        raise MigrationError("neutral catalog realm root does not match --active-root")


def _load_authorizations(path: Path, *, source: Path, realm_id: str, source_manifest: str) -> dict[str, dict[str, Any]]:
    _require_owner_only(path, label="B12 authorization file")
    envelope = _read_json(path, label="B12 authorization file")
    if envelope.get("format_version") != 1:
        raise MigrationError("B12 authorization file format_version must be 1")
    if envelope.get("source_root") != str(source) or envelope.get("realm_id") != realm_id:
        raise MigrationError("B12 authorization file is bound to a different source or realm")
    if envelope.get("source_manifest_sha256") != source_manifest:
        raise MigrationError("B12 authorization file is bound to a different source manifest")
    raw = envelope.get("authorizations")
    if not isinstance(raw, Mapping) or set(raw) != set(LIVE_AUTHORIZATION_IDS):
        raise MigrationError("B12 authorization file must contain exactly the six live authorization IDs")
    result: dict[str, dict[str, Any]] = {}
    nonces: set[str] = set()
    for authorization_id in LIVE_AUTHORIZATION_IDS:
        value = raw[authorization_id]
        if not isinstance(value, Mapping):
            raise MigrationError(f"{authorization_id} authorization is not an object")
        item = dict(value)
        if item.get("authorization_id") != authorization_id:
            raise MigrationError(f"{authorization_id} authorization ID is not self-bound")
        if item.get("source_manifest_sha256") != source_manifest or item.get("selected_realm_id") != realm_id:
            raise MigrationError(f"{authorization_id} authorization is not bound to this source and realm")
        nonce = item.get("nonce")
        if not isinstance(nonce, str) or not nonce or nonce in nonces:
            raise MigrationError("B12 authorizations require distinct non-empty nonces")
        nonces.add(nonce)
        result[authorization_id] = item
    return result


def _load_writer_receipt(path: Path, *, source: Path) -> tuple[dict[str, Any], str]:
    _require_owner_only(path, label="writer-stop receipt")
    value = _read_json(path, label="writer-stop receipt")
    if value.get("source_root") != str(source):
        raise MigrationError("writer-stop receipt is bound to a different source root")
    writer_count = value.get("writer_count")
    if (value.get("stopped") is not True or isinstance(writer_count, bool)
            or not isinstance(writer_count, int) or writer_count != 0):
        raise MigrationError("writer-stop receipt must assert stopped=true and writer_count=0")
    if not isinstance(value.get("method"), str) or not value["method"].strip():
        raise MigrationError("writer-stop receipt must identify the stop method")
    raw = path.read_bytes()
    return value, hashlib.sha256(raw).hexdigest()


def _writer_stop_callback(source: Path, database: Path, receipt_path: Path, initial_digest: str, receipt: Mapping[str, Any]):
    def stop() -> Mapping[str, Any]:
        try:
            current = receipt_path.read_bytes()
        except OSError as exc:
            raise MigrationError("writer-stop receipt disappeared before the freeze boundary") from exc
        if hashlib.sha256(current).hexdigest() != initial_digest:
            raise MigrationError("writer-stop receipt changed before the freeze boundary")
        # This is deliberately a probe, not a process killer.  Any held legacy
        # lock fails closed; the operator must stop the correct writer and retry.
        _assert_writer_free(source, database, None)
        return dict(receipt)
    return stop


def issue_authorizations(args: argparse.Namespace) -> dict[str, Any]:
    source, _ = _require_source(args.source_root)
    realm_id = str(args.realm_id)
    if not realm_id or any(char in realm_id for char in "/\\"):
        raise MigrationError("realm-id must be an opaque path-safe identifier")
    archive = _absolute(args.archive_root, label="archive root")
    destination = _absolute(args.destination_root, label="destination root")
    config = MigrationConfig(source, archive, destination, dry_run=True)
    inventory = Migrator(config, None).inventory()
    auth = issue_live_authorizations(source_manifest_sha256=inventory["source_manifest_sha256"], selected_realm_id=realm_id, ttl_seconds=args.ttl_seconds)
    output = _absolute(args.output, label="authorization output")
    _write_new_json(output, {"format_version": 1, "created_at": time.time(), "source_root": str(source), "realm_id": realm_id, "source_manifest_sha256": inventory["source_manifest_sha256"], "authorizations": auth})
    return {"ok": True, "source_root": str(source), "realm_id": realm_id, "source_manifest_sha256": inventory["source_manifest_sha256"], "authorization_file": str(output), "authorization_ids": list(LIVE_AUTHORIZATION_IDS)}


def live_migrate(args: argparse.Namespace, *, runtime_factory: Callable[..., Any] = open_runtime) -> dict[str, Any]:
    if args.confirm != CONFIRMATION:
        raise MigrationError(f"live migration requires --confirm {CONFIRMATION!r}")
    source, database = _require_source(args.source_root)
    active = _absolute(args.active_root, label="active root")
    support = _absolute(args.support_root, label="support root")
    archive = _absolute(args.archive_root, label="archive root")
    destination = _absolute(args.destination_root, label="destination root")
    evidence = _absolute(args.evidence_root, label="evidence root")
    if not active.is_dir() or not (active / "realm.sqlite3").is_file():
        raise MigrationError("--active-root must be an existing neutral realm")
    if not support.is_dir():
        raise MigrationError("--support-root must be an existing neutral support directory")
    if not args.realm_id:
        raise MigrationError("--realm-id is required; the operator must select the realm explicitly")
    realm_id = str(args.realm_id)
    _reject_collisions(source, active, archive, destination, evidence, support)
    _require_catalog(support, active, realm_id)
    trust_key = _load_trust_key(support)
    redundancy = getattr(args, "redundancy", "compact")
    config = MigrationConfig(source, archive, destination, evidence_root=evidence, capacity_margin_bytes=args.capacity_margin_bytes, expected_source_manifest_sha256=None, activation_registry_root=support / "activations", activation_trust_key=trust_key, redundancy=redundancy)
    # Compute the exact source binding before opening the active service.
    inventory = Migrator(config, None).inventory()
    source_manifest = inventory["source_manifest_sha256"]
    authorizations = _load_authorizations(_absolute(args.authorization_file, label="authorization file"), source=source, realm_id=realm_id, source_manifest=source_manifest)
    receipt_path = _absolute(args.writer_stop_receipt, label="writer-stop receipt")
    receipt, receipt_digest = _load_writer_receipt(receipt_path, source=source)
    config = MigrationConfig(source, archive, destination, evidence_root=evidence, capacity_margin_bytes=args.capacity_margin_bytes, expected_source_manifest_sha256=source_manifest, activation_registry_root=support / "activations", activation_trust_key=trust_key, redundancy=redundancy)
    runtime = None
    try:
        runtime = runtime_factory(active, display_name=args.display_name, realm_id=realm_id, support_root=support)
        if str(runtime.realm["id"]) != realm_id:
            raise MigrationError("active realm identity does not match --realm-id")
        report = run_live_migration(config, runtime, authorizations, writer_stop=_writer_stop_callback(source, database, receipt_path, receipt_digest, receipt))
        return {"ok": True, "packet": "B12", "source_root": str(source), "source_manifest_sha256": source_manifest, "realm_id": realm_id, "authorization_file": str(_absolute(args.authorization_file, label="authorization file")), "writer_stop_receipt": str(receipt_path), "writer_stop_receipt_sha256": receipt_digest, "report": report}
    finally:
        if runtime is not None:
            runtime.close()


def _copy_tree_without_source_database(source: Path, target: Path) -> None:
    shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True)


def normalize_nested_source(args: argparse.Namespace) -> dict[str, Any]:
    source = _absolute(args.source_root, label="nested source root")
    database = _absolute(args.database, label="nested database")
    destination = _absolute(args.destination_root, label="normalized destination root")
    if _has_symlink_component(source) or not source.is_dir():
        raise MigrationError("nested source root must be an existing symlink-free directory")
    for item in source.rglob("*"):
        if item.is_symlink():
            try:
                item.resolve(strict=False).relative_to(source)
            except ValueError as exc:
                raise MigrationError(f"nested source contains an escaping symlink: {item}") from exc
    if _has_symlink_component(database) or not database.is_file() or not _inside(database, source):
        raise MigrationError("nested database must be an existing regular file inside the explicit source root")
    expected_nested = source / ".astrid" / "source-projects-root-kernel" / "astrid.sqlite3"
    if database != expected_nested:
        raise MigrationError("normalization only supports the explicit source-projects-root-kernel database layout")
    if os.path.lexists(str(destination)) or _has_symlink_component(destination):
        raise MigrationError("normalized destination must be fresh and symlink-free")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.normalize-", dir=str(destination.parent)))
    try:
        _copy_tree_without_source_database(source, temporary)
        root_db = temporary / ".astrid" / "astrid.sqlite3"
        root_db.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(database, root_db)
        nested_media = source / ".astrid" / "source-projects-root-kernel" / "media"
        cloned_media = temporary / ".astrid" / "media"
        if nested_media.is_dir():
            shutil.copytree(nested_media, cloned_media, symlinks=True)
        # The nested kernel stores old absolute locators.  Map only the exact
        # known ``.astrid/media/sha256/...`` shape to the cloned nested media;
        # every other locator remains visible to the normal migrator and will
        # fail validation rather than being guessed.
        connection = sqlite3.connect(root_db)
        try:
            connection.row_factory = sqlite3.Row
            rows = connection.execute("SELECT id, realm, locator FROM media_locations ORDER BY id").fetchall()
            mappings = []
            for row in rows:
                realm, locator = str(row["realm"] or ""), str(row["locator"] or "")
                if realm in {"remote", "http", "https"}:
                    continue
                old = Path(locator).expanduser()
                parts = old.parts
                try:
                    marker = parts.index("media")
                    suffix = Path(*parts[marker:])
                except ValueError:
                    continue
                if len(suffix.parts) < 3 or suffix.parts[0] != "media" or suffix.parts[1] != "sha256":
                    continue
                nested = source / ".astrid" / "source-projects-root-kernel" / suffix
                cloned = temporary / ".astrid" / suffix
                if not nested.is_file() or not cloned.is_file():
                    raise MigrationError(f"nested media locator cannot be verified: {locator}")
                connection.execute("UPDATE media_locations SET locator=? WHERE id=?", (str(Path(".astrid") / suffix), row["id"]))
                mappings.append({"media_location_id": row["id"], "from": locator, "to": str(Path(".astrid") / suffix)})
            connection.commit()
        finally:
            connection.close()
        config = MigrationConfig(temporary, temporary.parent / f"{temporary.name}-archive", temporary.parent / f"{temporary.name}-destination", dry_run=True)
        inventory = Migrator(config, None).inventory()
        receipt = {"format_version": 1, "normalization": "astrid-intro-nested-kernel-v1", "source_root": str(source), "source_database": str(database), "destination_root": str(destination), "source_database_sha256": _sha256_file(database), "normalized_database_sha256": _sha256_file(root_db), "source_manifest_sha256": inventory["source_manifest_sha256"], "media_mappings": mappings}
        os.replace(str(temporary), str(destination))
        temporary = None
        _write_new_json(destination / "normalization-manifest.json", receipt)
        return {"ok": True, "source_root": str(source), "destination_root": str(destination), "source_manifest_sha256": inventory["source_manifest_sha256"], "media_mappings": len(mappings), "normalization_manifest": str(destination / "normalization-manifest.json")}
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="astrid-live-migrate", description="Explicit, fail-closed Astrid B12 operator tooling")
    sub = parser.add_subparsers(dest="command", required=True)
    issue = sub.add_parser("issue-authorizations", help="bind six fresh B12 nonces to a frozen source manifest")
    issue.add_argument("--source-root", required=True)
    issue.add_argument("--archive-root", required=True)
    issue.add_argument("--destination-root", required=True)
    issue.add_argument("--realm-id", required=True)
    issue.add_argument("--output", required=True)
    issue.add_argument("--ttl-seconds", type=int, default=3600)
    live = sub.add_parser("live-migrate", help="run serialized B12 against an explicitly selected neutral realm")
    live.add_argument("--source-root", required=True)
    live.add_argument("--active-root", required=True)
    live.add_argument("--support-root", required=True)
    live.add_argument("--archive-root", required=True)
    live.add_argument("--destination-root", required=True)
    live.add_argument("--evidence-root", required=True)
    live.add_argument("--realm-id", required=True)
    live.add_argument("--authorization-file", required=True)
    live.add_argument("--writer-stop-receipt", required=True)
    live.add_argument("--display-name", default="Astrid Workspace")
    live.add_argument("--capacity-margin-bytes", type=int)
    live.add_argument("--redundancy", choices=("compact", "extreme"), default="compact")
    live.add_argument("--confirm", required=True)
    normalize = sub.add_parser("normalize-nested-source", help="explicitly clone the nested Astrid intro source layout")
    normalize.add_argument("--source-root", required=True)
    normalize.add_argument("--database", required=True, help="exact .astrid/source-projects-root-kernel/astrid.sqlite3 path")
    normalize.add_argument("--destination-root", required=True)
    tiny = sub.add_parser("tiny-acceptance", help="run the small routine Stage 1 B12 live acceptance journey")
    tiny.add_argument("--output-root", required=True, help="fresh absolute root for fixture, realm, receipts, and evidence")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "issue-authorizations":
            result = issue_authorizations(args)
        elif args.command == "live-migrate":
            result = live_migrate(args)
        elif args.command == "tiny-acceptance":
            from .tiny_acceptance import run_tiny_acceptance
            result = run_tiny_acceptance(args.output_root)
        else:
            result = normalize_nested_source(args)
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return 0
    except (MigrationError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc), "source_untouched": True}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
