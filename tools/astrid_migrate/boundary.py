"""Small neutral migration boundary.

This module is intentionally self contained: it only uses the Python standard
library and describes the filesystem/backup wire format used by the operator
protocol.  Runtime implementations are supplied by callers as duck-typed
generated-client-shaped objects.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import stat
import time
from datetime import datetime, timezone
from typing import Any, Mapping
from migration_boundary import AuthorizationError, ConflictError, ValidationError


class MigrationBoundaryError(Exception):
    def __init__(self, message: str, *, details: Any = None):
        super().__init__(message)
        self.details = details




class RealmCatalog:
    """Minimal public catalog writer used by operator activation."""
    def __init__(self, path: str | Path):
        self.path = absolute_path(path)
    def _read(self):
        try: return json.loads(self.path.read_text())
        except FileNotFoundError: return {"format_version": 1, "realms": [], "selected_realm_id": None}
    def _write(self, value, **kwargs):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    def register(self, *, realm_id, display_name, data_root, **kwargs):
        value = self._read(); rows = [r for r in value.get("realms", []) if r.get("realm_id") != realm_id]
        rows.append({"realm_id": realm_id, "display_name": display_name, "data_root": str(data_root)})
        value["realms"] = rows; self._write(value); return value
    def select(self, realm_id, **kwargs):
        value = self._read(); value["selected_realm_id"] = realm_id; self._write(value); return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id() -> str:
    return hashlib.sha256(f"{os.getpid()}:{time.time_ns()}".encode()).hexdigest()[:32]


def absolute_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _parent(path: Path) -> Path:
    parent = path
    while not os.path.lexists(str(parent)):
        if parent == parent.parent:
            raise ConflictError(f"filesystem path has no existing parent: {path}")
        parent = parent.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ConflictError(f"filesystem parent is not an ordinary directory: {parent}")
    return parent


def _identity(path: Path) -> tuple[int, int, int]:
    value = path.stat(follow_symlinks=False)
    return int(value.st_dev), int(value.st_ino), int(value.st_mode)


def _has_symlink(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
    return False


def capture_parent(path: str | Path, *, require_fresh_target: bool = False) -> dict[str, Any]:
    target = absolute_path(path)
    if _has_symlink(target):
        raise ConflictError(f"filesystem path contains a symlink component: {target}")
    if require_fresh_target and os.path.lexists(str(target)):
        raise ConflictError(f"filesystem target must be fresh: {target}")
    parent = _parent(target.parent)
    fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    dev, ino, mode = _identity(parent)
    return {"path": str(target), "parent": str(parent), "target_parent": str(target.parent), "parent_was_missing": parent != target.parent,
            "parent_st_dev": dev, "parent_st_ino": ino, "parent_st_mode": mode, "_parent_fd": fd}


def close_pinned(identity: Mapping[str, Any] | None) -> None:
    if identity and int(identity.get("_parent_fd", -1)) >= 0:
        try: os.close(int(identity["_parent_fd"]))
        except OSError: pass


def validate_parent(path: str | Path, identity: Mapping[str, Any], *, allow_parent_appeared: bool = False) -> int:
    target = absolute_path(path)
    if identity.get("path") != str(target) or _has_symlink(target):
        raise ConflictError(f"filesystem path identity changed: {target}")
    fd = int(identity.get("_parent_fd", -1))
    if fd < 0 or _identity(Path(str(identity["parent"]))) != tuple(int(identity[f"parent_{k}"]) for k in ("st_dev", "st_ino", "st_mode")):
        raise ConflictError(f"filesystem parent identity changed: {target.parent}")
    if identity.get("parent_was_missing") and os.path.lexists(str(target.parent)) and not allow_parent_appeared:
        raise ConflictError(f"filesystem target parent appeared: {target.parent}")
    return fd


def validate_created_parent(path: str | Path, identity: Mapping[str, Any], final_parent_fd: int) -> int:
    validate_parent(path, identity, allow_parent_appeared=True)
    return int(final_parent_fd)


def pin_directory(path: str | Path):
    target = absolute_path(path)
    identity = capture_parent(target)
    try:
        root_fd = os.open(target.name if target.parent == Path(identity["parent"]) else str(target.relative_to(Path(identity["parent"]))), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=int(identity["_parent_fd"]))
        return identity, root_fd, os.fstat(root_fd)
    except Exception:
        close_pinned(identity)
        raise


def ensure_parent_at(path: str | Path, identity: Mapping[str, Any]):
    target = absolute_path(path)
    parent = Path(str(identity["parent"]))
    fd = validate_parent(target, identity, allow_parent_appeared=True)
    if target.parent == parent:
        return fd, target.name
    relative = target.parent.relative_to(parent)
    current = os.dup(fd)
    for part in relative.parts:
        try: os.mkdir(part, 0o700, dir_fd=current)
        except FileExistsError: pass
        nxt = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
        os.close(current); current = nxt
    return current, target.name


def ensure_directory(path: str | Path, *, mode: int = 0o700):
    target = absolute_path(path)
    identity = capture_parent(target)
    parent_fd, name = ensure_parent_at(target, identity)
    try: os.mkdir(name, mode, dir_fd=parent_fd)
    except FileExistsError: pass
    child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    if parent_fd != identity["_parent_fd"]: os.close(parent_fd)
    close_pinned(identity)
    dev, ino, smode = _identity(target)
    return {"path": str(target), "parent": str(target.parent), "target_parent": str(target.parent), "parent_st_dev": dev, "parent_st_ino": ino, "parent_st_mode": smode, "_parent_fd": child}


def mkdir_temp_at(parent_fd: int, prefix: str, *, mode: int = 0o700):
    for attempt in range(100):
        name = f"{prefix}{os.getpid()}-{time.time_ns()}-{attempt}"
        try: os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError: continue
        return name, os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    raise ConflictError("temporary filesystem directory could not be allocated")


def write_bytes_at(directory_fd: int, name: str, data: bytes, *, mode: int = 0o600):
    name = Path(name).name
    temp = f".{name}.{os.getpid()}-{time.time_ns()}.tmp"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=directory_fd)
    try:
        os.write(fd, bytes(data)); os.fsync(fd); os.close(fd); fd = -1
        os.rename(temp, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd); os.fsync(directory_fd)
    finally:
        if fd >= 0: os.close(fd)
        try: os.unlink(temp, dir_fd=directory_fd)
        except OSError: pass


def atomic_json_write(path: str | Path, value: bytes | Mapping[str, Any], *, identity: Mapping[str, Any] | None = None):
    encoded = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    own = identity is None; identity = identity or capture_parent(path)
    try:
        parent_fd, name = ensure_parent_at(path, identity)
        write_bytes_at(parent_fd, name, encoded)
        # Recheck after publication as well: hostile tests and operators may
        # replace the lexical parent inside the rename syscall.  The retained
        # descriptor prevents redirection; this check still reports the
        # identity change instead of silently accepting it.
        validate_parent(path, identity, allow_parent_appeared=True)
        if parent_fd != identity.get("_parent_fd"): os.close(parent_fd)
    finally:
        if own: close_pinned(identity)


def copy_file_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str, *, replace: bool = False):
    src = os.open(source_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_fd)
    try:
        dstflags = os.O_WRONLY | os.O_CREAT | (0 if replace else os.O_EXCL) | getattr(os, "O_NOFOLLOW", 0)
        dst = os.open(destination_name, dstflags, 0o600, dir_fd=destination_fd)
        try:
            while True:
                data = os.read(src, 1024 * 1024)
                if not data: break
                os.write(dst, data)
            os.fsync(dst)
        finally: os.close(dst)
    finally: os.close(src)


def copy_tree_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str, *, preserve_symlinks: bool = False):
    src = os.open(source_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=source_fd)
    try:
        os.mkdir(destination_name, 0o700, dir_fd=destination_fd)
        dst = os.open(destination_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=destination_fd)
        try:
            for entry in os.scandir(src):
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode): copy_tree_at(src, entry.name, dst, entry.name, preserve_symlinks=preserve_symlinks)
                elif stat.S_ISREG(mode): copy_file_at(src, entry.name, dst, entry.name)
                elif stat.S_ISLNK(mode) and preserve_symlinks: os.symlink(os.readlink(entry.name, dir_fd=src), entry.name, dir_fd=dst)
                else: raise ConflictError(f"source contains unsupported entry: {entry.name}")
        finally: os.close(dst)
    finally: os.close(src)


def remove_tree_at(parent_fd: int, name: str):
    target = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    try:
        for entry in os.scandir(target):
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode): remove_tree_at(target, entry.name)
            else: os.unlink(entry.name, dir_fd=target)
    finally: os.close(target)
    os.rmdir(name, dir_fd=parent_fd)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()


def _key(manifest: Mapping[str, Any]) -> bytes:
    auth = manifest.get("authentication") or {}; candidate = auth.get("key_path")
    if not candidate: raise ConflictError("backup authentication key is missing")
    value = Path(str(candidate)).read_bytes()
    if auth.get("key_id") != hashlib.sha256(value).hexdigest()[:32]: raise ConflictError("backup authentication key does not match manifest")
    return value


def verify_backup(backup_dir: str | Path, **kwargs):
    root = absolute_path(backup_dir); manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("database_sha256") != _sha256(root / "realm.sqlite3"): raise ConflictError("backup SQLite hash mismatch")
    cas = json.loads((root / "cas-manifest.json").read_text())
    if manifest.get("cas_manifest_sha256") != cas.get("manifest_sha256"): raise ConflictError("backup CAS manifest hash mismatch")
    key = kwargs.get("key") or _key(manifest)
    payload = {k: v for k, v in manifest.items() if k not in {"manifest_sha256", "manifest_hmac"}}
    if manifest.get("manifest_sha256") != hashlib.sha256(canonical_json(payload).encode()).hexdigest(): raise ConflictError("backup manifest authentication failed")
    if not hmac.compare_digest(str(manifest.get("manifest_hmac")), hmac.new(key, canonical_json(payload).encode(), hashlib.sha256).hexdigest()): raise ConflictError("backup manifest authentication failed")
    return {"manifest": manifest, "cas_manifest": cas}


def verify_restore_candidate(candidate_dir: str | Path, **kwargs):
    root = absolute_path(candidate_dir); handoff = json.loads((root / "activation-handoff.json").read_text())
    source = absolute_path(handoff["source_backup"]); verified = verify_backup(source)
    if handoff.get("candidate_database_sha256") != _sha256(root / "realm.sqlite3"): raise ConflictError("restore candidate SQLite bytes differ from backup")
    if handoff.get("source_manifest_sha256") != _sha256(source / "manifest.json"): raise ConflictError("restore handoff source manifest mismatch")
    return {"handoff": handoff, "manifest": verified["manifest"], "doctor": {"ok": True}, "database_sha256": _sha256(root / "realm.sqlite3"), "cas_manifest_sha256": verified["cas_manifest"].get("manifest_sha256")}


def restore_backup(backup_dir: str | Path, destination: str | Path, **kwargs):
    source = absolute_path(backup_dir); target = absolute_path(destination)
    verified = verify_backup(source, key=kwargs.get("key"))
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    shutil.copy2(source / "realm.sqlite3", target / "realm.sqlite3")
    shutil.copytree(source / "cas", target / "cas", symlinks=False)
    manifest = verified["manifest"]; key = kwargs.get("key") or _key(manifest)
    handoff = {"format_version": 2, "source_backup": str(source), "source_manifest_sha256": _sha256(source / "manifest.json"), "realm_id": manifest.get("realm_id"), "candidate_database_sha256": _sha256(target / "realm.sqlite3")}
    payload = dict(handoff)
    handoff["handoff_sha256"] = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    handoff["handoff_hmac"] = hmac.new(key, canonical_json(payload).encode(), hashlib.sha256).hexdigest()
    (target / "activation-handoff.json").write_text(canonical_json(handoff) + "\n")
    return verify_restore_candidate(target)


def _open_relative(root_fd: int, relative: str | Path, *, directory: bool = False) -> int:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in {"", ".", ".."} for p in parts): raise ValidationError("invalid descriptor-relative path")
    current = root_fd; opened = []
    try:
        for i, part in enumerate(parts):
            fd = os.open(part, os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if directory or i < len(parts)-1 else 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
            if current != root_fd: opened.append(current)
            current = fd
        for fd in opened: os.close(fd)
        return current
    except Exception:
        for fd in opened:
            try: os.close(fd)
            except OSError: pass
        raise


def _sha256_at(root_fd: int, relative: str | Path):
    fd = _open_relative(root_fd, relative)
    try:
        value = os.fstat(fd); digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            digest.update(chunk)
        return digest.hexdigest(), int(value.st_size)
    finally: os.close(fd)


def _connection_from_fd(root_fd: int, name: str):
    import sqlite3
    fd = _open_relative(root_fd, name); duplicate = os.dup(fd); os.close(fd)
    return sqlite3.connect(f"file:/dev/fd/{duplicate}?immutable=1", uri=True)
