from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Mapping, Any

from .util import atomic_json_write, new_id, now
from .dirfd import capture_parent, close_pinned, validate_parent
from .backup import _open_relative


def _safe_path(path: str | Path, label: str) -> Path:
    """Validate an authority path before any resolve/open operation."""
    target = Path(path).expanduser()
    if not target.is_absolute():
        raise ValueError(f"{label} must be absolute")
    current = Path(target.anchor)
    for component in target.parts[1:]:
        current /= component
        if current.is_symlink() and current not in {Path("/var"), Path("/tmp")}:
            raise ValueError(f"{label} must not traverse a symlink")
    return target


def process_birth_identity(pid: int | None = None) -> str | None:
    """Return an OS birth marker that changes when a PID is reused.

    Linux exposes the process start tick in ``/proc/<pid>/stat``.  macOS and
    other POSIX hosts do not, so use ``ps``'s start-time rendering there.  The
    value is only an identity fence; it is never treated as an authorization
    secret.
    """
    value = os.getpid() if pid is None else int(pid)
    if value <= 0:
        return None
    stat_path = Path(f"/proc/{value}/stat")
    try:
        raw = stat_path.read_text(encoding="utf-8")
        # The comm field may contain ')' so split at the final closing paren.
        fields = raw.rsplit(")", 1)[-1].split()
        if len(fields) >= 20:
            return f"proc-start-ticks:{fields[19]}"
    except (OSError, ValueError):
        pass
    try:
        result = subprocess.run(
            ["ps", "-p", str(value), "-o", "lstart="],
            capture_output=True, text=True, check=False, timeout=1,
        )
        rendered = result.stdout.strip()
        if result.returncode == 0 and rendered:
            return f"ps-lstart:{rendered}"
    except (OSError, subprocess.SubprocessError):
        pass
    return None


class RealmCatalog:
    """Persistent machine composition state, intentionally separate from realm authority."""

    def __init__(self, path: str | Path):
        self.path = _safe_path(path, "catalog path")
        self._path_identity = None

    def __del__(self):  # pragma: no cover - interpreter cleanup
        try:
            close_pinned(self._path_identity)
        except Exception:
            pass

    def read(self, *, path_identity: Mapping[str, Any] | None = None) -> dict:
        if path_identity is not None:
            own = False
            identity = path_identity
        else:
            if self._path_identity is None:
                self._path_identity = capture_parent(self.path)
            own = False
            identity = self._path_identity
        fd = -1
        try:
            validate_parent(self.path, identity, allow_parent_appeared=True)
            parent = Path(str(identity["parent"]))
            fd = _open_relative(int(identity["_parent_fd"]), self.path.relative_to(parent))
            value = os.fstat(fd)
            if not stat.S_ISREG(value.st_mode):
                raise ValueError("catalog is not a regular file")
            data = bytearray()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                data.extend(chunk)
            result = json.loads(bytes(data).decode("utf-8"))
            validate_parent(self.path, identity, allow_parent_appeared=True)
            return result
        except FileNotFoundError:
            return {"version": 1, "realms": [], "selected_realm_id": None}
        finally:
            if fd >= 0:
                os.close(fd)
            if own:
                close_pinned(identity)

    def register(self, *, realm_id: str, display_name: str, data_root: str, path_identity: Mapping[str, Any] | None = None) -> dict:
        if not isinstance(realm_id, str) or not realm_id or "/" in realm_id or "\\" in realm_id:
            raise ValueError("realm id must be an opaque path-safe identifier")
        root = _safe_path(data_root, "realm root")
        catalog = self.read(path_identity=path_identity)
        realms = [r for r in catalog.get("realms", []) if r.get("realm_id") != realm_id]
        realms.append({"realm_id": realm_id, "display_name": display_name, "data_root": str(root), "registered_at": now()})
        catalog.update(version=1, realms=realms, selected_realm_id=catalog.get("selected_realm_id") or realm_id)
        atomic_json_write(self.path, catalog, identity=path_identity)
        return catalog

    def select(self, realm_id: str, *, path_identity: Mapping[str, Any] | None = None) -> dict:
        catalog = self.read(path_identity=path_identity)
        if not any(row.get("realm_id") == realm_id for row in catalog.get("realms", [])):
            raise KeyError(realm_id)
        catalog["selected_realm_id"] = realm_id
        atomic_json_write(self.path, catalog, identity=path_identity)
        return catalog


class LiveDiscovery:
    """Ephemeral process advertisement; never includes a database path or secret."""

    def __init__(self, path: str | Path):
        self.path = _safe_path(path, "discovery path")

    def publish(self, **fields):
        allowed = {"version", "endpoint", "pid", "process_birth_id", "active_realm", "runtime_instance_id", "protocol_version", "schema_version", "coordinator_epoch", "credential_file", "worker_credential_file", "worker_actor", "worker_scopes"}
        atomic_json_write(self.path, {k: fields[k] for k in allowed if k in fields})

    def clear(self, instance_id: str | None = None):
        if self.path.is_symlink():
            return
        if not self.path.exists():
            return
        if instance_id is None or self.read().get("runtime_instance_id") == instance_id:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    def read(self):
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("discovery is not a regular file")
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return json.loads(b"".join(chunks).decode("utf-8"))
        finally:
            os.close(fd)
