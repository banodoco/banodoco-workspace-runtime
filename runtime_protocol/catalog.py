from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from .util import atomic_json_write, new_id, now


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
        self.path = Path(path).expanduser().resolve()

    def read(self) -> dict:
        if not self.path.exists():
            return {"version": 1, "realms": [], "selected_realm_id": None}
        with self.path.open(encoding="utf-8") as stream:
            value = json.load(stream)
        return value

    def register(self, *, realm_id: str, display_name: str, data_root: str) -> dict:
        catalog = self.read()
        realms = [r for r in catalog.get("realms", []) if r.get("realm_id") != realm_id]
        realms.append({"realm_id": realm_id, "display_name": display_name, "data_root": str(Path(data_root).resolve()), "registered_at": now()})
        catalog.update(version=1, realms=realms, selected_realm_id=catalog.get("selected_realm_id") or realm_id)
        atomic_json_write(self.path, catalog)
        return catalog

    def select(self, realm_id: str) -> dict:
        catalog = self.read()
        if not any(row.get("realm_id") == realm_id for row in catalog.get("realms", [])):
            raise KeyError(realm_id)
        catalog["selected_realm_id"] = realm_id
        atomic_json_write(self.path, catalog)
        return catalog


class LiveDiscovery:
    """Ephemeral process advertisement; never includes a database path or secret."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()

    def publish(self, **fields):
        # Canonical discovery is shared with banodoco-local. Legacy aliases
        # remain readable for older neutral clients during this beta.
        allowed = {"version", "endpoint", "pid", "process_birth_id", "active_realm", "runtime_instance_id", "protocol_version", "schema_version", "coordinator_epoch", "credential_file", "instance_id", "realm_id"}
        atomic_json_write(self.path, {k: fields[k] for k in allowed if k in fields})

    def clear(self, instance_id: str | None = None):
        if not self.path.exists():
            return
        if instance_id is None or self.read().get("instance_id") == instance_id:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    def read(self):
        with self.path.open(encoding="utf-8") as stream:
            return json.load(stream)
