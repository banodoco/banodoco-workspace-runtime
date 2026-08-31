"""B13.2 recovery, disposable purge, reboot-R2, and final reactivation.

This module is deliberately an operator-side composition of the neutral runtime
and the already verified backup/restore primitives.  It does not make a live
realm disposable, and it never treats a missing path or a journal label as
proof that a destructive operation happened.  Every destructive step is
bound to the selected realm, durable artifact digests, and a one-shot
authorization digest.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import secrets
import sqlite3
import time
from typing import Any, Callable, Mapping

from .boundary import restore_backup, verify_backup, verify_restore_candidate, _open_relative, _sha256_at, _connection_from_fd, canonical_json, new_id, atomic_json_write as _atomic_json_write, capture_parent as _capture_parent, close_pinned as _close_pinned, ensure_directory as _ensure_directory, mkdir_temp_at as _mkdir_temp_at, remove_tree_at as _remove_tree_at, validate_parent as _validate_parent, pin_directory as _pin_directory

from .migrator import MigrationError, _sha256_file
from .capacity import CapacityPlan, CapacityReservation, StorageDomain, capture_activation_path, capture_write_path, revalidate_activation_path, revalidate_write_path
from .rehearsal import RuntimeServiceAdapter, _tree_digest


B13_AUTHORIZATION_IDS = (
    "AUTH-PURGE-B13",
    "AUTH-REBOOT-R2",
    "AUTH-ROLLBACK-B13",
    "AUTH-REACTIVATION-B13",
)


def _absolute_path(value: str | Path) -> Path:
    """Make a lexical absolute path without following symlinks."""
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _has_symlink_component(path: Path) -> bool:
    """Return whether any existing component of ``path`` is a symlink."""
    path = _absolute_path(path)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def _read_json_pinned(path: str | Path, *, identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Read a JSON artifact through a retained lexical parent descriptor."""
    target = _absolute_path(path)
    own_identity = identity is None
    identity = identity or _capture_parent(target)
    fd = -1
    try:
        _validate_parent(target, identity, allow_parent_appeared=True)
        parent = Path(str(identity["parent"]))
        fd = _open_relative(int(identity["_parent_fd"]), target.relative_to(parent))
        # The target is already pinned; decode its bytes without reopening a
        # pathname.
        os.lseek(fd, 0, os.SEEK_SET)
        data = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        value = json.loads(bytes(data).decode("utf-8"))
        if not isinstance(value, dict):
            raise MigrationError(f"B13.2 JSON artifact is not an object: {target}")
        _validate_parent(target, identity, allow_parent_appeared=True)
        return value
    except FileNotFoundError:
        raise
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise MigrationError(f"B13.2 JSON artifact is invalid: {target}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if own_identity:
            _close_pinned(identity)


def _hash_file_pinned(path: str | Path) -> str:
    target = _absolute_path(path)
    identity = _capture_parent(target)
    fd = -1
    try:
        _validate_parent(target, identity, allow_parent_appeared=True)
        parent = Path(str(identity["parent"]))
        fd = _open_relative(int(identity["_parent_fd"]), target.relative_to(parent))
        digest = hashlib.sha256()
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise MigrationError(f"B13.2 artifact is not a regular file: {target}")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        _validate_parent(target, identity, allow_parent_appeared=True)
        return digest.hexdigest()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise MigrationError(f"B13.2 artifact cannot be hashed: {target}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        _close_pinned(identity)


def _host_boot_identity() -> str:
    """Return the host boot marker used by the real R2 reboot boundary."""
    linux_marker = Path("/proc/sys/kernel/random/boot_id")
    try:
        value = linux_marker.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    if value:
        return f"linux-boot:{value}"
    try:
        result = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, check=True, timeout=2)
        value = result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        value = ""
    if value:
        return f"darwin-boot:{value}"
    raise MigrationError("B13.2 cannot establish an OS boot identity for R2")


def actual_reboot_executor(command: str, checkpoint: Mapping[str, Any]) -> Any:
    """Production executor hook for a real host reboot.

    The caller must opt into this hook explicitly (usually with the daemon's
    privileged command policy).  A successful command is not treated as a
    post-boot receipt: the process must terminate/restart and the next run
    seals the receipt only after observing a changed boot identity and epoch.
    """
    if command != "reboot":
        raise MigrationError(f"B13.2 unsupported reboot command: {command}")
    for candidate in ("/sbin/reboot", "/usr/sbin/reboot", "reboot"):
        try:
            subprocess.run([candidate], check=True, timeout=10)
        except FileNotFoundError:
            continue
        except (OSError, subprocess.SubprocessError) as exc:
            raise MigrationError("B13.2 host reboot command failed") from exc
        raise MigrationError("B13.2 host reboot command returned; resume after the operating system reboots")
    raise MigrationError("B13.2 host reboot command is unavailable")


def _stat_identity(path: Path) -> dict[str, Any]:
    try:
        value = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise MigrationError(f"B13.2 purge target identity is unavailable: {path}") from exc
    return {"st_dev": int(value.st_dev), "st_ino": int(value.st_ino), "st_mode": int(value.st_mode), "path": str(_absolute_path(path))}


def _catalog_paths(value: Any, *, key: str = "") -> list[tuple[str, str]]:
    """Collect path-bearing catalog fields for fail-closed purge fencing."""
    result: list[tuple[str, str]] = []
    if isinstance(value, Mapping):
        for name, item in value.items():
            result.extend(_catalog_paths(item, key=str(name)))
    elif isinstance(value, list):
        for item in value:
            result.extend(_catalog_paths(item, key=key))
    elif isinstance(value, str) and ("root" in key or "path" in key or "archive" in key or "backup" in key or "migration" in key or "source" in key or "destination" in key):
        result.append((key, value))
    return result


def _database_snapshot_sha256(path: Path, *, connection: sqlite3.Connection) -> str:
    """Hash a consistent SQLite view, including committed WAL frames."""
    path = _absolute_path(path)
    parent_identity = _capture_parent(path)
    parent_fd = int(parent_identity.get("_parent_fd"))
    source = connection
    temporary_name = None
    temporary_fd = -1
    cwd_fd = -1
    try:
        temporary_name, temporary_fd = _mkdir_temp_at(parent_fd, ".b13-db-snapshot-")
        cwd_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fchdir(parent_fd)
            target = sqlite3.connect(str(Path(temporary_name) / "snapshot.sqlite3"), timeout=10)
            try:
                source.backup(target)
                target.commit()
            finally:
                target.close()
        finally:
            os.fchdir(cwd_fd)
            os.close(cwd_fd)
            cwd_fd = -1
        snapshot_fd = os.open("snapshot.sqlite3", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=temporary_fd)
        try:
            digest = hashlib.sha256()
            while True:
                block = os.read(snapshot_fd, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
            return digest.hexdigest()
        finally:
            os.close(snapshot_fd)
    finally:
        if cwd_fd >= 0:
            try:
                os.fchdir(cwd_fd)
            finally:
                os.close(cwd_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name is not None:
            try:
                _remove_tree_at(parent_fd, temporary_name)
                os.fsync(parent_fd)
            except OSError:
                pass
        _close_pinned(parent_identity)


def _database_semantic_sha256(path: Path, *, connection: sqlite3.Connection | None = None) -> str:
    """Hash realm data while ignoring startup-owned runtime control rows."""
    identity = root_fd = -1
    own_connection = connection is None
    if connection is None:
        identity, root_fd, _ = _pin_directory(Path(path).parent)
        connection = _connection_from_fd(root_fd, Path(path).name)
    connection.row_factory = sqlite3.Row
    try:
        ignored = {"runtime_lifecycle", "capabilities", "sqlite_sequence"}
        tables = [str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name") if row[0] not in ignored]
        value = {table: [dict(row) for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')] for table in tables}
    finally:
        if own_connection:
            connection.close()
        if root_fd >= 0:
            os.close(root_fd)
        if identity != -1:
            _close_pinned(identity)
    return _canonical_digest(value)


def issue_b13_authorizations(*, selected_realm_id: str | None = None, ttl_seconds: int = 3600) -> dict[str, dict[str, Any]]:
    """Issue distinct, short-lived operator inputs for the B13 commands."""
    if ttl_seconds <= 0:
        raise ValueError("authorization TTL must be positive")
    if not isinstance(selected_realm_id, str) or not selected_realm_id.strip():
        raise ValueError("B13 authorizations require a concrete selected realm")
    expires_at = time.time() + ttl_seconds
    return {
        authorization_id: {
            "authorization_id": authorization_id,
            "scope": authorization_id.removeprefix("AUTH-").lower(),
            "nonce": secrets.token_urlsafe(32),
            "selected_realm_id": selected_realm_id,
            "expires_at": expires_at,
        }
        for authorization_id in B13_AUTHORIZATION_IDS
    }


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _tree_size(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file() and not path.is_symlink())


def _semantic_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Remove the database digest, which changes when the boot epoch advances."""
    return {str(key): value for key, value in snapshot.items() if key != "database_sha256"}


class RecoveryJournal:
    """Durable B13 cursor with append-only transitions and effects."""

    _states = (
        "prepared", "recovery_base", "purged", "checkpointed",
        "reboot_requested", "recovered", "rolled_back", "reactivated",
    )
    _allowed = {
        "prepared": {"recovery_base"},
        "recovery_base": {"purged"},
        "purged": {"checkpointed"},
        "checkpointed": {"reboot_requested"},
        "reboot_requested": {"recovered"},
        "recovered": {"rolled_back"},
        "rolled_back": {"reactivated"},
        "reactivated": set(),
    }

    def __init__(self, path: str | Path, *, crash_at: str | None = None, fault_injector: Callable[[str], None] | None = None):
        self.path = _absolute_path(path)
        self._path_identity = _capture_parent(self.path)
        self.crash_at = crash_at
        self.fault_injector = fault_injector

    def __del__(self):  # pragma: no cover - interpreter cleanup
        try:
            _close_pinned(self._path_identity)
        except Exception:
            pass

    def _inject(self, seam: str) -> None:
        if self.crash_at == seam:
            raise MigrationError(f"injected B13.2 crash at {seam}")
        if self.fault_injector is not None:
            self.fault_injector(seam)

    @staticmethod
    def _hash(value: Mapping[str, Any]) -> str:
        return _canonical_digest({key: item for key, item in value.items() if key not in {"entry_sha256", "effect_sha256"}})

    def read(self) -> dict[str, Any]:
        try:
            value = _read_json_pinned(self.path, identity=self._path_identity)
        except FileNotFoundError:
            return {"format_version": 1, "generation": 0, "state": "prepared", "entries": [], "effects": []}
        except (OSError, ValueError, MigrationError) as exc:
            raise MigrationError("B13.2 recovery journal is corrupt or interrupted") from exc
        if not isinstance(value, dict) or value.get("format_version") != 1 or not isinstance(value.get("entries"), list) or not isinstance(value.get("effects"), list):
            raise MigrationError("B13.2 recovery journal has an invalid envelope")
        state = value.get("state")
        if state not in self._states or not isinstance(value.get("generation"), int):
            raise MigrationError("B13.2 recovery journal has an invalid state")
        previous, generation = "prepared", 0
        for entry in value["entries"]:
            if not isinstance(entry, dict) or entry.get("from") != previous or entry.get("to") not in self._states or int(entry.get("generation", -1)) != generation + 1 or entry.get("entry_sha256") != self._hash(entry):
                raise MigrationError("B13.2 recovery journal has a broken transition chain")
            previous, generation = entry["to"], generation + 1
        if previous != state or generation != value["generation"]:
            raise MigrationError("B13.2 recovery journal generation/state mismatch")
        for effect in value["effects"]:
            if not isinstance(effect, dict) or not effect.get("name") or effect.get("effect_sha256") != self._hash(effect):
                raise MigrationError("B13.2 recovery journal has a broken effect record")
        return value

    def effects(self) -> dict[str, dict[str, Any]]:
        return {str(effect["name"]): effect for effect in self.read().get("effects", []) if isinstance(effect, dict) and effect.get("name")}

    def bind(self, **payload: Any) -> dict[str, Any]:
        current = self.read()
        if current.get("binding") is not None:
            if current["binding"] != payload:
                raise MigrationError("B13.2 recovery request binding conflict")
            return current
        if current["state"] != "prepared":
            raise MigrationError("B13.2 recovery binding must be established while prepared")
        result = current | {"binding": dict(payload)}
        self._inject("before_bind")
        _atomic_json_write(self.path, (canonical_json(result) + "\n").encode(), identity=self._path_identity)
        self._inject("after_bind")
        return result

    def effect(self, name: str, **payload: Any) -> dict[str, Any]:
        current = self.read()
        for effect in current["effects"]:
            if effect.get("name") == name:
                if effect.get("payload") != payload:
                    raise MigrationError(f"B13.2 effect {name!r} conflicts with its durable record")
                return current
        effect = {"name": name, "payload": payload, "generation": current["generation"]}
        effect["effect_sha256"] = self._hash(effect)
        result = current | {"effects": [*current["effects"], effect]}
        self._inject(f"before_effect_{name}")
        _atomic_json_write(self.path, (canonical_json(result) + "\n").encode(), identity=self._path_identity)
        self._inject(f"after_effect_{name}")
        return result

    def transition(self, state: str, **payload: Any) -> dict[str, Any]:
        current = self.read()
        if current["state"] == state:
            if payload:
                last = current["entries"][-1] if current["entries"] else {}
                for key, value in payload.items():
                    if last.get(key) != value:
                        raise MigrationError(f"B13.2 terminal replay conflicts on {key}")
            return current
        if state not in self._allowed.get(current["state"], set()):
            raise MigrationError(f"invalid B13.2 recovery transition {current['state']} -> {state}")
        entry = {"from": current["state"], "to": state, "generation": current["generation"] + 1, **payload}
        entry["entry_sha256"] = self._hash(entry)
        result = current | {"state": state, "generation": entry["generation"], "entries": [*current["entries"], entry]}
        self._inject(f"before_{current['state']}_to_{state}")
        _atomic_json_write(self.path, (canonical_json(result) + "\n").encode(), identity=self._path_identity)
        self._inject(f"after_{current['state']}_to_{state}")
        return result


@dataclass
class B13Recovery:
    """Run the product-level B13.2 recovery journey against one selected realm."""

    active_runtime: Any
    recovery_base_backup: Path
    rollback_archive: Path
    evidence_root: Path
    disposable_root: Path
    authorizations: Mapping[str, Mapping[str, Any]]
    crash_at: str | None = None
    fault_injector: Callable[[str], None] | None = None
    reboot_executor: Callable[..., Any] | None = None
    boot_identity_provider: Callable[[], str] | None = None
    source_root: Path | None = None

    def __post_init__(self) -> None:
        missing = [item for item in B13_AUTHORIZATION_IDS if item not in self.authorizations]
        if missing:
            raise MigrationError(f"B13.2 requires fresh authorizations: {', '.join(missing)}")
        nonces = [str(self.authorizations[item].get("nonce") or "") for item in B13_AUTHORIZATION_IDS]
        if any(not nonce for nonce in nonces) or len(set(nonces)) != len(nonces):
            raise MigrationError("B13.2 authorizations must have distinct nonces")
        for authorization_id in B13_AUTHORIZATION_IDS:
            value = self.authorizations[authorization_id]
            if not isinstance(value, Mapping):
                raise MigrationError(f"invalid B13.2 authorization instance {authorization_id}")
            expected_scope = authorization_id.removeprefix("AUTH-").lower()
            if value.get("scope") != expected_scope:
                raise MigrationError(f"{authorization_id} scope does not match the requested operation")
            selected_realm_id = value.get("selected_realm_id")
            if not isinstance(selected_realm_id, str) or not selected_realm_id.strip():
                raise MigrationError(f"{authorization_id} requires a concrete selected realm")
        # Preserve lexical paths until safety checks have rejected symlinks.
        self.recovery_base_backup = _absolute_path(self.recovery_base_backup)
        self.rollback_archive = _absolute_path(self.rollback_archive)
        self.evidence_root = _absolute_path(self.evidence_root)
        self.disposable_root = _absolute_path(self.disposable_root)
        if self.source_root is not None:
            self.source_root = _absolute_path(self.source_root)

    @staticmethod
    def _nonce_digest(value: Mapping[str, Any]) -> str:
        return hashlib.sha256(str(value["nonce"]).encode("utf-8")).hexdigest()

    def _validate_auth(self, authorization_id: str, realm_id: str) -> Mapping[str, Any]:
        value = self.authorizations[authorization_id]
        if not isinstance(value, Mapping):
            raise MigrationError(f"invalid B13.2 authorization instance {authorization_id}")
        if value.get("authorization_id") != authorization_id:
            raise MigrationError(f"invalid B13.2 authorization instance {authorization_id}")
        expected_scope = authorization_id.removeprefix("AUTH-").lower()
        if value.get("scope") != expected_scope:
            raise MigrationError(f"{authorization_id} scope does not match the requested operation")
        if value.get("selected_realm_id") != realm_id:
            raise MigrationError(f"{authorization_id} is bound to a different selected realm")
        try:
            if float(value.get("expires_at", 0)) <= time.time():
                raise MigrationError(f"{authorization_id} has expired")
        except (TypeError, ValueError) as exc:
            raise MigrationError(f"{authorization_id} has an invalid expiry") from exc
        return value

    def _consume_auth(self, journal: RecoveryJournal, authorization_id: str, realm_id: str) -> None:
        value = self._validate_auth(authorization_id, realm_id)
        digest = self._nonce_digest(value)
        name = f"authorization:{authorization_id}"
        existing = journal.effects().get(name)
        if existing:
            if existing.get("payload") != {"authorization_id": authorization_id, "nonce_sha256": digest, "realm_id": realm_id}:
                raise MigrationError(f"{authorization_id} conflicts with its durable consumption")
            return
        journal.effect(name, authorization_id=authorization_id, nonce_sha256=digest, realm_id=realm_id)

    def _write(self, name: str, value: Mapping[str, Any]) -> Path:
        reservation = getattr(self, "_capacity_reservation", None)
        if reservation is not None:
            reservation.recheck()
        path = self.evidence_root / name
        identity = _capture_parent(path)
        try:
            _atomic_json_write(path, (canonical_json(dict(value)) + "\n").encode(), identity=identity)
        finally:
            _close_pinned(identity)
        return path

    def _capacity_plan(self) -> tuple[CapacityPlan, dict[str, Any]]:
        """Estimate every B13 output against its actual storage domain."""
        active_root = _absolute_path(self.active_runtime.store.root)
        active_bytes = _tree_size(active_root)
        evidence_bytes = max(_tree_size(self.evidence_root), 1024 * 1024)
        allocations = (
            ("active_runtime", active_root, 0),
            ("recovery_base_backup", self.recovery_base_backup, active_bytes),
            ("rollback_archive", self.rollback_archive, 0),
            ("evidence", self.evidence_root, evidence_bytes),
            ("disposable", self.disposable_root, active_bytes),
            ("final_rollback_candidate", self.evidence_root / "b13-final-rollback-candidate", active_bytes),
            ("final_reactivation_candidate", self.evidence_root / "b13-final-reactivation-candidate", active_bytes),
        )
        if self.source_root is not None:
            allocations += (("source", self.source_root, 0),)
        plan = CapacityPlan.from_allocations(allocations, margin_bytes=0)
        receipt = plan.receipt(packet="B13.2", components={"active_bytes": active_bytes, "evidence_bytes": evidence_bytes, "reservation_scope": "filesystem-device-and-mount"})
        receipt["domain_count"] = len(receipt["domains"])
        return plan, receipt

    def _acquire_capacity(self, journal: RecoveryJournal) -> CapacityReservation:
        plan, receipt = self._capacity_plan()
        capacity_path = self.evidence_root / "capacity-receipt-b13.json"
        effect = journal.effects().get("capacity-reservation")
        if effect:
            payload = effect.get("payload", {})
            if payload.get("domain_ids") != sorted(plan.domains):
                raise MigrationError("B13.2 capacity reservation conflicts with its durable receipt")
            try:
                stored = _read_json_pinned(capacity_path)
                stored_sha256 = _hash_file_pinned(capacity_path)
            except FileNotFoundError as exc:
                raise MigrationError("B13.2 capacity receipt is missing or changed") from exc
            if payload.get("receipt_sha256") != stored_sha256:
                raise MigrationError("B13.2 capacity receipt is missing or changed")
            if stored.get("reserved") is not True:
                raise MigrationError("B13.2 capacity receipt is not reserved")
            # Reconstruct the original reservation amounts.  Existing output
            # bytes naturally grow after the first checkpoint; replay must
            # retain the durable peak estimate rather than charging them a
            # second time, while still proving that every domain identity and
            # output root is unchanged.
            stored_domains = stored.get("domains", [])
            stored_shape = [{key: row.get(key) for key in ("domain_id", "device", "mount", "probe_path")} | {"root_labels": sorted(dict(row.get("roots", {})))} for row in stored_domains]
            current_shape = [{key: row.get(key) for key in ("domain_id", "device", "mount", "probe_path")} | {"root_labels": sorted(dict(row.get("roots", {})))} for row in receipt.get("domains", [])]
            if stored_shape != current_shape:
                raise MigrationError("B13.2 capacity receipt storage domain changed")
            replay_plan = CapacityPlan({}, int(stored.get("margin_bytes", 0)))
            for record in stored_domains:
                domain = StorageDomain.identify(record.get("probe_path", ""))
                if domain.key != record.get("domain_id") or int(domain.device) != int(record.get("device")) or domain.mount != record.get("mount"):
                    raise MigrationError("B13.2 capacity receipt storage domain changed")
                domain.roots = {str(key): int(value) for key, value in dict(record.get("roots", {})).items()}
                domain.required_bytes = int(record.get("required_bytes"))
                replay_plan.domains[domain.key] = domain
            plan = replay_plan
        else:
            # Acquire first. The receipt itself is a lifecycle write and must
            # be covered by the same storage-domain lock.
            reservation_id = secrets.token_urlsafe(18)
            reservation = CapacityReservation.acquire(plan=plan, reservation_id=reservation_id)
            try:
                receipt["reserved"] = True
                self._write("capacity-receipt-b13.json", receipt)
                journal.effect("capacity-reservation", reservation_id=reservation_id, domain_ids=sorted(plan.domains), required_bytes=receipt["required_bytes"], receipt_sha256=_hash_file_pinned(capacity_path))
                return reservation
            except Exception:
                reservation.release()
                raise
        reservation_id = str(effect["payload"].get("reservation_id") or "")
        if not reservation_id:
            raise MigrationError("B13.2 capacity reservation has no durable identity")
        return CapacityReservation.acquire(plan=plan, reservation_id=reservation_id)

    def _verify_backup(self, path: Path, realm_id: str) -> dict[str, Any]:
        if _has_symlink_component(path):
            raise MigrationError(f"B13.2 backup path contains a symlink component: {path}")
        try:
            verified = verify_backup(path)
        except Exception as exc:
            raise MigrationError(f"B13.2 backup is not authenticated and complete: {path}") from exc
        if verified["manifest"].get("realm_id") != realm_id:
            raise MigrationError(f"B13.2 backup belongs to a different realm: {path}")
        return verified

    def _restore_or_reuse(self, backup: Path, destination: Path, *, realm_id: str, journal: RecoveryJournal, effect_name: str, seam: str) -> dict[str, Any]:
        # Re-authenticate the source on every replay.  A durable restore effect
        # is not permission to consume a backup that was replaced after the
        # first attempt.
        self._verify_backup(backup, realm_id)
        if _has_symlink_component(destination):
            raise MigrationError(f"B13.2 {effect_name} destination contains a symlink component")
        existing = journal.effects().get(effect_name)
        if existing:
            payload = existing["payload"]
            if payload.get("destination") != str(destination) or payload.get("realm_id") != realm_id:
                raise MigrationError(f"B13.2 {effect_name} has a conflicting destination")
            try:
                verification = verify_restore_candidate(destination)
            except Exception as exc:
                raise MigrationError(f"B13.2 durable restore candidate is invalid: {destination}") from exc
        elif os.path.lexists(str(destination)):
            try:
                verification = verify_restore_candidate(destination)
            except Exception as exc:
                raise MigrationError(f"B13.2 pre-existing restore candidate is not reusable: {destination}") from exc
        else:
            reservation = getattr(self, "_capacity_reservation", None)
            if reservation is not None:
                reservation.recheck()
            write_identity = capture_write_path(destination)
            source_identity = None
            try:
                source_identity = _capture_parent(backup)
                journal._inject(f"before_{seam}")
                if reservation is not None:
                    reservation.recheck()
                # The seam is inside the storage-domain lease.  Revalidate the
                # complete parent chain after the seam and immediately before
                # restore so a hostile parent rename/symlink/device swap cannot
                # redirect restore_backup's temporary directory or final rename.
                revalidate_write_path(destination, write_identity)
                restore_backup(backup, destination, destination_identity=write_identity, source_identity=source_identity)
                journal._inject(f"after_{seam}")
            finally:
                _close_pinned(write_identity)
                if source_identity is not None:
                    _close_pinned(source_identity)
            verification = verify_restore_candidate(destination)
        if verification["manifest"].get("realm_id") != realm_id:
            raise MigrationError("B13.2 restore candidate realm identity mismatch")
        journal.effect(effect_name, destination=str(destination), realm_id=realm_id, database_sha256=verification["database_sha256"], source_manifest_sha256=verification["handoff"].get("source_manifest_sha256"))
        return {"destination": str(destination), "realm_id": realm_id, "verification": verification}

    @staticmethod
    def _within(candidate: Path, root: Path) -> bool:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            return False

    def _catalog_classification(self, target: Path, realm_id: str) -> dict[str, Any]:
        """Classify a purge target from the current catalog, fail closed.

        The classification is re-read during interrupted-purge resume and
        terminal replay.  A receipt made before a catalog change must not
        authorize deletion merely because its old boolean flags were safe.
        """
        result = {"selected": False, "live": False, "migration_source": False, "migration_destination": False, "backup": False, "rollback_archive": False, "source": False}
        catalog = self.active_runtime.support_root / "catalog.json" if self.active_runtime.support_root else None
        result["catalog_path"] = str(_absolute_path(catalog)) if catalog is not None else None
        result["catalog_sha256"] = None
        if catalog is None:
            return result
        if _has_symlink_component(catalog):
            raise MigrationError("B13.2 cannot classify a disposable target through a symlinked catalog")
        try:
            catalog_value = _read_json_pinned(catalog)
            catalog_sha256 = _hash_file_pinned(catalog)
        except FileNotFoundError as exc:
            raise MigrationError("B13.2 cannot classify a disposable target without its catalog") from exc
        except (OSError, ValueError, MigrationError) as exc:
            raise MigrationError("B13.2 cannot classify a disposable target against an invalid catalog") from exc
        if not isinstance(catalog_value, Mapping):
            raise MigrationError("B13.2 disposable target catalog is not an object")
        realms = catalog_value.get("realms")
        if not isinstance(realms, list) or not isinstance(catalog_value.get("selected_realm_id"), str) or not catalog_value.get("selected_realm_id", "").strip():
            raise MigrationError("B13.2 disposable target catalog is incomplete")
        result["catalog_sha256"] = catalog_sha256
        selected_realm = catalog_value.get("selected_realm_id")
        for row in realms:
            if not isinstance(row, Mapping):
                continue
            data_root = row.get("data_root")
            if not isinstance(data_root, str) or not data_root.strip():
                continue
            row_root = _absolute_path(data_root)
            if self._within(_absolute_path(target), row_root) or self._within(row_root, _absolute_path(target)):
                result["live"] = True
                if row.get("realm_id") == selected_realm or row.get("realm_id") == realm_id:
                    result["selected"] = True
        for key, value in _catalog_paths(catalog_value):
            try:
                catalog_path = _absolute_path(value)
            except (TypeError, ValueError):
                raise MigrationError("B13.2 disposable target catalog contains an invalid path")
            if _has_symlink_component(catalog_path):
                raise MigrationError("B13.2 disposable target catalog contains a symlinked path")
            if not (self._within(_absolute_path(target), catalog_path) or self._within(catalog_path, _absolute_path(target))):
                continue
            lower = key.lower()
            if "migration" in lower and "source" in lower:
                result["migration_source"] = True
            elif "migration" in lower and "destination" in lower:
                result["migration_destination"] = True
            elif "rollback" in lower:
                result["rollback_archive"] = True
            elif "backup" in lower or "archive" in lower:
                result["backup"] = True
            elif "source" in lower:
                result["source"] = True
            else:
                result["live"] = True
        return result

    def _safe_disposable_target(self, realm_id: str) -> dict[str, Any]:
        target = self.disposable_root
        # Check the lexical path before resolving it: resolving a pre-existing
        # symlink would turn an unsafe delete into an apparently safe target.
        if _has_symlink_component(target):
            raise MigrationError("B13.2 purge target is not a fresh ordinary path")
        if os.path.lexists(str(target)):
            raise MigrationError("B13.2 purge target must not pre-exist")
        protected = {
            "live": _absolute_path(self.active_runtime.store.root),
            "backup": _absolute_path(self.recovery_base_backup),
            "rollback_archive": _absolute_path(self.rollback_archive),
        }
        if self.source_root is not None:
            protected["source"] = _absolute_path(self.source_root)

        classification = {"realm_class": "disposable", "selected": False, "live": False, "migration_source": False, "migration_destination": False, "backup": False, "rollback_archive": False, "source": False, "realm_id": realm_id, "root": str(target)}
        for name, root in protected.items():
            if self._within(_absolute_path(target), root) or self._within(root, _absolute_path(target)):
                classification[name] = True
        catalog_classification = self._catalog_classification(target, realm_id)
        for key in ("selected", "live", "migration_source", "migration_destination", "backup", "rollback_archive", "source"):
            classification[key] = bool(classification[key] or catalog_classification[key])
        classification["catalog_path"] = catalog_classification["catalog_path"]
        classification["catalog_sha256"] = catalog_classification["catalog_sha256"]
        forbidden = ("selected", "live", "migration_source", "migration_destination", "backup", "rollback_archive", "source")
        if any(classification[key] for key in forbidden):
            raise MigrationError("B13.2 purge target is classified as selected, live, migration, backup, rollback, or source")
        return classification

    def _validate_purge_classification(self, target: Path, realm_id: str, classification: Mapping[str, Any]) -> None:
        if classification.get("realm_class") != "disposable" or classification.get("realm_id") != realm_id or classification.get("root") != str(_absolute_path(target)):
            raise MigrationError("B13.2 purge classification is not bound to this target")
        forbidden = ("selected", "live", "migration_source", "migration_destination", "backup", "rollback_archive", "source")
        if any(classification.get(key) for key in forbidden):
            raise MigrationError("B13.2 purge target is classified as selected, live, migration, backup, rollback, or source")
        if _has_symlink_component(target):
            raise MigrationError("B13.2 unsafe purge target")
        target_abs = _absolute_path(target)
        protected = [_absolute_path(self.active_runtime.store.root), _absolute_path(self.recovery_base_backup), _absolute_path(self.rollback_archive)]
        if self.source_root is not None:
            protected.append(_absolute_path(self.source_root))
        for root in protected:
            if _has_symlink_component(root):
                raise MigrationError("B13.2 authoritative purge root contains a symlink component")
            if self._within(target_abs, root):
                raise MigrationError("B13.2 purge target is not separate from an authoritative root")
            if self._within(root, target_abs):
                raise MigrationError("B13.2 purge target would contain an authoritative root")
        current_catalog = self._catalog_classification(target_abs, realm_id)
        for key in ("catalog_path", "catalog_sha256"):
            if classification.get(key) != current_catalog.get(key):
                raise MigrationError("B13.2 purge classification catalog changed while interrupted")
        for key in ("selected", "live", "migration_source", "migration_destination", "backup", "rollback_archive", "source"):
            if bool(classification.get(key)) != bool(current_catalog.get(key)):
                raise MigrationError("B13.2 purge classification changed while interrupted")

    def _read_purge_marker(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        marker = Path(str(payload.get("marker_path", "")))
        try:
            value = _read_json_pinned(marker)
        except (FileNotFoundError, OSError, ValueError, MigrationError) as exc:
            raise MigrationError("B13.2 purge marker is unreadable") from exc
        if not isinstance(value, dict) or _canonical_digest(value) != payload.get("marker_sha256"):
            raise MigrationError("B13.2 purge marker digest changed")
        if value != payload.get("marker"):
            raise MigrationError("B13.2 purge marker conflicts with its durable receipt")
        return value

    def _revalidate_purge_target(self, target: Path, realm_id: str, payload: Mapping[str, Any]) -> None:
        """Recheck the object that is about to be removed, including identity."""
        if not os.path.lexists(str(target)):
            # A completed destructive syscall may have happened before its
            # journal effect was published. Even in that case, retain the
            # parent fence: replacing/removing the parent changes the object
            # to which the absence receipt refers.
            if _has_symlink_component(target) or _stat_identity(target.parent) != payload.get("parent_identity"):
                raise MigrationError("B13.2 purge target parent identity changed while interrupted")
            return
        if not target.is_dir() or target.is_symlink() or _stat_identity(target) != payload.get("target_identity") or _stat_identity(target.parent) != payload.get("parent_identity"):
            raise MigrationError("B13.2 purge target or parent identity changed while interrupted")
        if _tree_digest(target) != payload.get("tombstoned_tree_sha256") or _sha256_file(target / "realm.sqlite3") != payload.get("tombstoned_database_sha256"):
            raise MigrationError("B13.2 purge target bytes changed while interrupted")
        # The authenticated post-tombstone database/tree digests above already
        # cover the realm and lifecycle rows. Do not reopen the runtime store (or even
        # a normal read-only SQLite connection) here: SQLite may create a
        # ``-shm`` sidecar on open, changing the exact tree receipt we are
        # validating immediately before deletion.

    def _purge_disposable(self, journal: RecoveryJournal, realm_id: str, base: Mapping[str, Any]) -> dict[str, Any]:
        target = self.disposable_root
        existing = journal.effects().get("purge-complete")
        if existing:
            if os.path.lexists(str(target)):
                raise MigrationError("B13.2 purge receipt says target is gone but the target exists")
            payload = existing["payload"]
            classification = payload.get("classification")
            if not isinstance(classification, Mapping):
                raise MigrationError("B13.2 purge receipt has no classification")
            self._validate_purge_classification(target, realm_id, classification)
            self._read_purge_marker(payload)
            self._revalidate_purge_target(target, realm_id, payload)
            return dict(existing["payload"])
        # Tombstoning is the irreversible lifecycle precondition for purge;
        # require the dedicated purge authorization before changing it.
        self._validate_auth("AUTH-PURGE-B13", realm_id)
        self._consume_auth(journal, "AUTH-PURGE-B13", realm_id)
        started = journal.effects().get("purge-started")
        if not started:
            if _has_symlink_component(target):
                raise MigrationError("B13.2 unsafe purge target")
            if not os.path.lexists(str(target)) or not target.exists():
                raise MigrationError("B13.2 disposable purge target is missing before purge")
            self._validate_purge_classification(target, realm_id, base)
            target_identity = _stat_identity(target)
            parent_identity = _stat_identity(target.parent)
            reservation = getattr(self, "_capacity_reservation", None)
            if reservation is not None:
                reservation.recheck()
            target_store = type(self.active_runtime.store)(target, acquire_owner=True)
            try:
                lifecycle = target_store.realm_lifecycle()
                if target_store.realm["id"] != realm_id or lifecycle["state"] != "active":
                    if target_store.realm["id"] != realm_id or lifecycle["state"] != "tombstoned":
                        raise MigrationError("B13.2 disposable target identity/lifecycle is invalid")
                pre_purge_tree = _tree_digest(target)
                pre_purge_database = _sha256_file(target / "realm.sqlite3")
                if lifecycle["state"] == "active":
                    target_store.tombstone_realm(reason="B13.2 disposable purge")
                tombstoned = target_store.realm_lifecycle()
            finally:
                target_store.close()
            # Closing the SQLite owner may checkpoint/remove WAL sidecars, so
            # bind the resume receipt to the post-close bytes actually left on
            # disk rather than to a transient open-connection tree.
            tombstoned_tree = _tree_digest(target)
            tombstoned_database = _sha256_file(target / "realm.sqlite3")
            marker = {"packet": "B13.2", "marker_version": 1, "marker_id": secrets.token_urlsafe(18), "target": str(_absolute_path(target)), "realm_id": realm_id, "target_identity": target_identity, "parent_identity": parent_identity, "pre_purge_tree_sha256": pre_purge_tree, "pre_purge_database_sha256": pre_purge_database, "tombstoned_tree_sha256": tombstoned_tree, "tombstoned_database_sha256": tombstoned_database, "classification": dict(base)}
            marker_path = self._write("purge-marker-b13.json", marker)
            payload = {"target": str(_absolute_path(target)), "realm_id": realm_id, "pre_purge_tree_sha256": pre_purge_tree, "pre_purge_database_sha256": pre_purge_database, "tombstoned_tree_sha256": tombstoned_tree, "tombstoned_database_sha256": tombstoned_database, "lifecycle": tombstoned, "classification": dict(base), "target_identity": target_identity, "parent_identity": parent_identity, "marker_path": str(marker_path), "marker_sha256": _canonical_digest(marker), "marker": marker}
            journal.effect("purge-started", **payload)
            started = journal.effects()["purge-started"]
        payload = started["payload"]
        classification = payload.get("classification")
        if not isinstance(classification, Mapping):
            raise MigrationError("B13.2 purge receipt has no classification")
        self._validate_purge_classification(target, realm_id, classification)
        self._read_purge_marker(payload)
        if payload.get("target") != str(_absolute_path(target)):
            raise MigrationError("B13.2 purge receipt target path changed")
        # Revalidate the exact target and its parent on every resume.  A
        # replacement directory, inode, marker, or symlinked parent must never
        # be accepted merely because purge-started was already journaled.
        self._revalidate_purge_target(target, realm_id, payload)
        reservation = getattr(self, "_capacity_reservation", None)
        if reservation is not None:
            reservation.recheck()
        purge_parent = _capture_parent(target)
        journal._inject("before_purge")
        # Fault/restart hooks are an adversarial boundary: validate again after
        # the hook and immediately before the destructive syscall so a
        # replacement cannot be deleted on the resume path.
        self._revalidate_purge_target(target, realm_id, payload)
        if reservation is not None:
            reservation.recheck()
        try:
            parent_fd = int(purge_parent.get("_parent_fd"))
            parent_stat = os.fstat(parent_fd)
            expected_parent = payload.get("parent_identity") or {}
            if (int(parent_stat.st_dev), int(parent_stat.st_ino), int(parent_stat.st_mode)) != tuple(int(expected_parent[key]) for key in ("st_dev", "st_ino", "st_mode")):
                raise MigrationError("B13.2 purge target parent identity changed before deletion")
            if os.path.lexists(str(target)):
                # Delete only through the retained parent descriptor. A
                # replacement at the lexical parent cannot redirect this call.
                _remove_tree_at(parent_fd, target.name)
                os.fsync(parent_fd)
        finally:
            _close_pinned(purge_parent)
        if os.path.lexists(str(target)):
            raise MigrationError("B13.2 disposable purge did not remove its exact target")
        journal._inject("after_purge")
        payload = payload | {"purged": True, "post_purge_exists": False}
        journal.effect("purge-complete", **payload)
        return payload

    def _boot_identity(self) -> str:
        provider = self.boot_identity_provider or _host_boot_identity
        try:
            value = provider()
        except MigrationError:
            raise
        except Exception as exc:
            raise MigrationError("B13.2 boot identity provider failed") from exc
        if not isinstance(value, str) or not value.strip():
            raise MigrationError("B13.2 boot identity provider returned no identity")
        return value

    @staticmethod
    def _runtime_session(runtime: Any) -> str:
        value = getattr(runtime, "runtime_session_id", None)
        if not isinstance(value, str) or not value:
            raise MigrationError("B13.2 runtime has no boot session identity")
        return value

    def _call_reboot_executor(self, command: str, checkpoint: Mapping[str, Any]) -> Any:
        executor = self.reboot_executor
        if executor is None:
            raise MigrationError("B13.2 R2 requires an injectable reboot executor")
        import inspect
        try:
            signature = inspect.signature(executor)
        except (TypeError, ValueError):
            return executor(command, checkpoint)
        try:
            signature.bind(command=command, checkpoint=checkpoint)
        except TypeError:
            try:
                signature.bind(command, checkpoint)
            except TypeError as exc:
                raise MigrationError("B13.2 reboot executor must accept command and checkpoint") from exc
            return executor(command, checkpoint)
        return executor(command=command, checkpoint=checkpoint)

    def _resume_reboot(self, journal: RecoveryJournal, realm_id: str, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(checkpoint, Mapping):
            raise MigrationError("B13.2 R2 checkpoint is not an object")
        required = ("checkpoint_id", "realm_id", "active_root", "runtime_epoch", "runtime_session_id_before", "boot_identity_before", "authorization_nonce_sha256", "semantic_snapshot_sha256")
        if any(key not in checkpoint for key in required):
            raise MigrationError("B13.2 R2 checkpoint is incomplete")
        if checkpoint.get("realm_id") != realm_id or checkpoint.get("active_root") != str(self.active_runtime.store.root.resolve()):
            raise MigrationError("B13.2 R2 checkpoint is bound to a different realm or root")
        if not isinstance(checkpoint.get("checkpoint_id"), str) or not checkpoint["checkpoint_id"].strip() or not isinstance(checkpoint.get("authorization_nonce_sha256"), str) or not checkpoint["authorization_nonce_sha256"].strip():
            raise MigrationError("B13.2 R2 checkpoint has no authorization identity")
        reboot_auth = journal.effects().get("authorization:AUTH-REBOOT-R2")
        expected_auth = {"authorization_id": "AUTH-REBOOT-R2", "nonce_sha256": checkpoint["authorization_nonce_sha256"], "realm_id": realm_id}
        if not reboot_auth or reboot_auth.get("payload") != expected_auth:
            raise MigrationError("B13.2 R2 checkpoint authorization is missing or conflicting")
        try:
            expected = int(checkpoint["runtime_epoch"])
        except (TypeError, ValueError) as exc:
            raise MigrationError("B13.2 R2 checkpoint has an invalid runtime epoch") from exc
        before_boot = checkpoint["boot_identity_before"]
        before_session = checkpoint["runtime_session_id_before"]
        if not isinstance(before_boot, str) or not before_boot.strip() or not isinstance(before_session, str) or not before_session.strip():
            raise MigrationError("B13.2 R2 checkpoint has no boot/session identity")
        current_runtime = self.active_runtime
        current_epoch = int(current_runtime.health()["runtime_epoch"])
        current_session = self._runtime_session(current_runtime)
        current_boot = self._boot_identity()
        effect = journal.effects().get("reboot-complete")
        if effect:
            payload = effect["payload"]
            try:
                recorded_after_epoch = int(payload.get("runtime_epoch_after"))
            except (TypeError, ValueError) as exc:
                raise MigrationError("B13.2 R2 reboot receipt has an invalid observed epoch") from exc
            # A process may restart again after the reboot receipt was
            # published but before the recovery transition is observed. The
            # OS boot identity must remain the one receipt recorded, while
            # the durable runtime epoch may have advanced further. Never
            # invoke the reboot executor again in that case.
            if (payload.get("status") != "executed" or payload.get("command") != "reboot" or payload.get("checkpoint_id") != checkpoint["checkpoint_id"] or payload.get("realm_id") != realm_id or payload.get("root") != str(current_runtime.store.root) or payload.get("boot_identity_before") != before_boot or payload.get("boot_identity_after") != current_boot or payload.get("runtime_session_id_before") != before_session or payload.get("runtime_epoch_before") != expected or recorded_after_epoch < expected + 1 or current_epoch < recorded_after_epoch or current_session == before_session):
                raise MigrationError("B13.2 R2 reboot receipt does not match the observed boot")
            if not current_runtime.doctor().get("ok") or current_runtime.realm["id"] != realm_id:
                raise MigrationError("B13.2 R2 post-boot runtime is unhealthy or has the wrong realm")
            return dict(payload)

        request_payload = {"checkpoint_id": checkpoint["checkpoint_id"], "command": "reboot", "realm_id": realm_id, "boot_identity_before": before_boot, "runtime_epoch_before": expected, "runtime_session_id_before": before_session, "authorization_nonce_sha256": checkpoint.get("authorization_nonce_sha256")}
        request_effect = journal.effects().get("reboot-requested")
        if request_effect and request_effect.get("payload") != request_payload:
            raise MigrationError("B13.2 R2 reboot request conflicts with its durable authorization")
        if not request_effect:
            journal.effect("reboot-requested", **request_payload)

        # A changed host boot plus the exact runtime epoch is a successful
        # request that lost its receipt before publication.  Seal it without
        # invoking the external reboot command again.
        if current_epoch >= expected + 1 and current_boot != before_boot and current_session != before_session:
            if current_runtime.realm["id"] != realm_id or str(current_runtime.store.root) != str(self.active_runtime.store.root) or not current_runtime.doctor().get("ok"):
                raise MigrationError("B13.2 post-R2 runtime is unhealthy or has the wrong realm")
            snapshot = RuntimeServiceAdapter(current_runtime).destination_snapshot()
            payload = {"status": "executed", "realm_id": realm_id, "root": str(current_runtime.store.root), "checkpoint_id": checkpoint["checkpoint_id"], "command": "reboot", "boot_identity_before": before_boot, "boot_identity_after": current_boot, "runtime_session_id_before": before_session, "runtime_session_id_after": current_session, "runtime_epoch_before": expected, "runtime_epoch_after": current_epoch, "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(snapshot)), "doctor_ok": True}
            self.active_runtime = current_runtime
            journal._inject("after_reboot_execute")
            journal.effect("reboot-complete", **payload)
            return payload
        if current_epoch != expected or current_boot != before_boot or current_session != before_session:
            raise MigrationError("B13.2 R2 runtime is neither at the checkpoint nor at a verified post-boot identity")

        outcome = self._call_reboot_executor("reboot", checkpoint)
        if not isinstance(outcome, Mapping):
            raise MigrationError("B13.2 reboot executor must return a receipt mapping")
        after_boot = outcome.get("after_boot_identity")
        if outcome.get("status") not in ("executed", "rebooted") or outcome.get("before_boot_identity") != before_boot or not isinstance(after_boot, str) or not after_boot.strip() or after_boot == before_boot:
            raise MigrationError("B13.2 reboot executor did not prove a changed OS boot identity")
        if outcome.get("runtime_epoch_before") != expected or outcome.get("runtime_epoch_after") != expected + 1 or outcome.get("before_runtime_session_id") != before_session:
            raise MigrationError("B13.2 reboot executor returned an invalid exactly-once epoch receipt")
        candidate_runtime = outcome.get("runtime") or self.active_runtime
        try:
            observed_epoch = int(candidate_runtime.health()["runtime_epoch"])
            observed_session = self._runtime_session(candidate_runtime)
            observed_boot = self._boot_identity()
        except Exception as exc:
            raise MigrationError("B13.2 reboot executor did not publish a post-boot runtime") from exc
        if str(candidate_runtime.store.root.resolve()) != checkpoint["active_root"] or observed_epoch != expected + 1 or observed_session == before_session or observed_boot != after_boot:
            raise MigrationError("B13.2 reboot executor post-state does not match its receipt")
        if candidate_runtime.realm["id"] != realm_id or not candidate_runtime.doctor().get("ok"):
            raise MigrationError("B13.2 R2 post-boot runtime is unhealthy or has the wrong realm")
        self.active_runtime = candidate_runtime
        snapshot = RuntimeServiceAdapter(candidate_runtime).destination_snapshot()
        payload = {"status": "executed", "realm_id": realm_id, "root": str(candidate_runtime.store.root), "checkpoint_id": checkpoint["checkpoint_id"], "command": "reboot", "boot_identity_before": before_boot, "boot_identity_after": after_boot, "runtime_session_id_before": before_session, "runtime_session_id_after": observed_session, "runtime_epoch_before": expected, "runtime_epoch_after": observed_epoch, "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(snapshot)), "doctor_ok": True, "executor_receipt": {str(key): value for key, value in outcome.items() if key != "runtime"}}
        journal._inject("after_reboot_execute")
        journal.effect("reboot-complete", **payload)
        return payload

    @staticmethod
    def _cas_content_map(root: Path) -> dict[str, str]:
        cas_root = root / "cas" / "sha256"
        result = {}
        if not cas_root.is_dir():
            return result
        for path in cas_root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                result[path.parent.name + path.name] = _sha256_file(path)
        return result

    def _active_matches_candidate(self, candidate: Path, realm_id: str) -> bool:
        try:
            if _has_symlink_component(candidate) or candidate.is_symlink():
                return False
            verification = verify_restore_candidate(candidate)
            current = self.active_runtime
            if current.realm["id"] != realm_id or not current.doctor().get("ok"):
                return False
            # Runtime startup rewrites only control rows (epoch/session and
            # capability metadata). Compare the candidate's semantic realm
            # content, not the main SQLite file, so a WAL-only user mutation
            # cannot make an activation appear reusable.
            if _database_semantic_sha256(current.store.db_path, connection=current.store.conn) != _database_semantic_sha256(candidate / "realm.sqlite3"):
                return False
            return self._cas_content_map(_absolute_path(current.store.root)) == self._cas_content_map(candidate)
        except Exception:
            return False

    def _activate(self, candidate: Path, state: str, *, realm_id: str, journal: RecoveryJournal, seam: str) -> dict[str, Any]:
        if _has_symlink_component(candidate) or candidate.is_symlink() or not candidate.is_dir():
            raise MigrationError(f"B13.2 {state} candidate is not an ordinary directory")
        # A crash after the swap but before its journal effect leaves the
        # active root already equal to this candidate.  Reuse that exact state
        # rather than swapping it again and advancing the runtime epoch twice.
        if self._active_matches_candidate(candidate, realm_id):
            return {"state": state, "reused": True, "candidate": str(candidate), "runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "realm_id": realm_id}
        reservation = getattr(self, "_capacity_reservation", None)
        if reservation is not None:
            reservation.recheck()
        target_identity = capture_activation_path(self.active_runtime.store.root)
        if reservation is not None:
            reservation.recheck()
        journal._inject(f"before_{seam}")
        if reservation is not None:
            reservation.recheck()
        revalidate_activation_path(self.active_runtime.store.root, target_identity)
        result = RuntimeServiceAdapter(self.active_runtime).activate_destination(candidate, state=state, target_identity=target_identity)
        journal._inject(f"after_{seam}")
        if self.active_runtime.realm["id"] != realm_id or not self.active_runtime.doctor()["ok"]:
            raise MigrationError(f"B13.2 {state} activation failed identity/integrity verification")
        return result

    def _activation_catalog_identity(self, realm_id: str) -> dict[str, Any]:
        root = _absolute_path(self.active_runtime.store.root)
        activation_path = root / "activation-manifest.json"
        if _has_symlink_component(activation_path):
            raise MigrationError("B13.2 activation manifest path contains a symlink")
        activation = {"status": "not_configured", "sha256": None}
        try:
            value = _read_json_pinned(activation_path)
            activation_sha256 = _hash_file_pinned(activation_path)
        except FileNotFoundError:
            value = None
        if value is not None:
            try:
                if not isinstance(value, Mapping) or value.get("state") != "activated":
                    raise MigrationError("B13.2 activation manifest identity is invalid")
            except (OSError, ValueError) as exc:
                raise MigrationError("B13.2 activation manifest is unreadable") from exc
            if not isinstance(value.get("destination_root"), str) or not value.get("destination_root", "").strip():
                raise MigrationError("B13.2 activation manifest has no destination identity")
            activation = {"status": "ready", "sha256": activation_sha256, "state": value.get("state"), "destination_root": value.get("destination_root")}
        catalog = {"status": "not_configured", "sha256": None}
        if self.active_runtime.support_root is not None:
            path = _absolute_path(self.active_runtime.support_root) / "catalog.json"
            try:
                value = _read_json_pinned(path)
                catalog_sha256 = _hash_file_pinned(path)
            except (FileNotFoundError, OSError, ValueError, MigrationError) as exc:
                raise MigrationError("B13.2 catalog is unreadable") from exc
            rows = [row for row in value.get("realms", []) if isinstance(row, Mapping) and row.get("realm_id") == realm_id]
            if value.get("selected_realm_id") != realm_id or len(rows) != 1 or _absolute_path(rows[0].get("data_root", "")) != root:
                raise MigrationError("B13.2 catalog selection or data-root identity changed")
            catalog = {"status": "ready", "sha256": catalog_sha256, "selected_realm_id": realm_id, "data_root": str(root)}
        return {"activation_manifest": activation, "catalog": catalog}

    def _verify_purge_terminal(self, identity: Mapping[str, Any], realm_id: str) -> None:
        target = self.disposable_root
        if os.path.lexists(str(target)):
            raise MigrationError("B13.2 terminal replay found the purged target present")
        purge_effect = RecoveryJournal(self.evidence_root / "migration-journal-b13.json").effects().get("purge-complete")
        if not purge_effect:
            raise MigrationError("B13.2 terminal replay has no purge-complete receipt")
        payload = purge_effect.get("payload", {})
        if payload.get("target") != str(_absolute_path(target)) or payload.get("realm_id") != realm_id or payload.get("post_purge_exists") is not False or payload.get("purged") is not True:
            raise MigrationError("B13.2 terminal purge receipt identity is invalid")
        classification = payload.get("classification")
        if not isinstance(classification, Mapping):
            raise MigrationError("B13.2 terminal purge receipt has no classification")
        self._validate_purge_classification(target, realm_id, classification)
        self._read_purge_marker(payload)
        self._revalidate_purge_target(target, realm_id, payload)
        receipt_path = self.evidence_root / "purge-receipt-b13.json"
        try:
            receipt = _read_json_pinned(receipt_path)
            receipt_sha256 = _hash_file_pinned(receipt_path)
        except (FileNotFoundError, OSError, ValueError, MigrationError) as exc:
            raise MigrationError("B13.2 terminal purge receipt is missing or changed") from exc
        if identity.get("purge_receipt_sha256") != receipt_sha256:
            raise MigrationError("B13.2 terminal purge receipt is missing or changed")
        if not isinstance(receipt, Mapping) or receipt.get("purged") is not True or receipt.get("target") != payload.get("target") or receipt.get("marker_sha256") != payload.get("marker_sha256"):
            raise MigrationError("B13.2 terminal purge receipt does not prove target absence")

    def _terminal_replay(self, journal: RecoveryJournal, realm_id: str) -> dict[str, Any]:
        current = journal.read()
        binding = current.get("binding") or {}
        for authorization_id in B13_AUTHORIZATION_IDS:
            self._validate_auth(authorization_id, realm_id)
        expected_binding = self._request_binding(realm_id)
        if binding != expected_binding:
            raise MigrationError("B13.2 terminal replay conflicts with the durable request binding")
        identity = current["entries"][-1].get("identity") if current["entries"] else None
        if not isinstance(identity, Mapping):
            raise MigrationError("B13.2 terminal journal has no final identity")
        final_effect = journal.effects().get("final-identity")
        if not final_effect or final_effect.get("payload", {}).get("identity") != dict(identity):
            raise MigrationError("B13.2 terminal journal final identity effect is missing or conflicting")
        if identity.get("realm_id") != realm_id or identity.get("root") != str(self.active_runtime.store.root.resolve()):
            raise MigrationError("B13.2 terminal identity binding is invalid")
        for path, expected in ((self.recovery_base_backup, identity.get("recovery_base_manifest_sha256")), (self.rollback_archive, identity.get("rollback_archive_manifest_sha256"))):
            if _has_symlink_component(path) or not path.is_dir():
                raise MigrationError(f"B13.2 terminal replay backup is missing: {path}")
            try:
                self._verify_backup(path, realm_id)
            except MigrationError:
                raise
            if expected != _sha256_file(path / "manifest.json"):
                raise MigrationError(f"B13.2 terminal replay backup manifest changed: {path}")
        if not self.active_runtime.doctor().get("ok"):
            raise MigrationError("B13.2 terminal replay current runtime is unhealthy")
        snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
        if identity.get("semantic_snapshot_sha256") != _canonical_digest(_semantic_snapshot(snapshot)):
            raise MigrationError("B13.2 terminal replay conflicts with active final identity")
        try:
            identity_epoch = int(identity.get("runtime_epoch"))
        except (TypeError, ValueError) as exc:
            raise MigrationError("B13.2 terminal identity has no valid runtime epoch") from exc
        current_epoch = int(self.active_runtime.health()["runtime_epoch"])
        same_session = identity.get("runtime_session_id") == getattr(self.active_runtime, "runtime_session_id", None)
        if same_session or current_epoch <= identity_epoch:
            if identity.get("database_sha256") != _database_snapshot_sha256(self.active_runtime.store.db_path, connection=self.active_runtime.store.conn):
                raise MigrationError("B13.2 terminal replay conflicts with active live database identity")
        elif identity.get("database_semantic_sha256") != _database_semantic_sha256(self.active_runtime.store.db_path, connection=self.active_runtime.store.conn):
            raise MigrationError("B13.2 terminal replay conflicts with active durable database state")
        if identity.get("cas_manifest_sha256") != _canonical_digest(sorted([{key: item.get(key) for key in ("digest", "size", "sha256")} for item in snapshot.get("cas_objects", [])], key=lambda item: str(item.get("digest")))):
            raise MigrationError("B13.2 terminal replay conflicts with active CAS content")
        self._verify_purge_terminal(identity, realm_id)
        artifacts = self._activation_catalog_identity(realm_id)
        if identity.get("activation_catalog_identity") != artifacts:
            raise MigrationError("B13.2 terminal replay activation or catalog identity changed")
        release = journal.effects().get("capacity-release")
        reservation_effect = journal.effects().get("capacity-reservation")
        if not release or not reservation_effect or release.get("payload", {}).get("reservation_id") != reservation_effect.get("payload", {}).get("reservation_id"):
            raise MigrationError("B13.2 terminal capacity reservation was not durably released")
        return {"packet": "B13.2", "journal": current, "identity": dict(identity), "idempotent": True, "active_runtime": self.active_runtime}

    def _request_binding(self, realm_id: str) -> dict[str, Any]:
        return {
            "realm_id": realm_id,
            "active_root": str(self.active_runtime.store.root.resolve()),
            "recovery_base_backup": str(self.recovery_base_backup),
            "rollback_archive": str(self.rollback_archive),
            "evidence_root": str(self.evidence_root),
            "disposable_root": str(self.disposable_root),
            "source_root": str(self.source_root) if self.source_root is not None else None,
            "authorization_nonce_sha256": {item: self._nonce_digest(self.authorizations[item]) for item in B13_AUTHORIZATION_IDS},
            "authorization_binding": {
                item: {
                    "authorization_id": self.authorizations[item].get("authorization_id"),
                    "scope": self.authorizations[item].get("scope"),
                    "selected_realm_id": self.authorizations[item].get("selected_realm_id"),
                    "nonce_sha256": self._nonce_digest(self.authorizations[item]),
                }
                for item in B13_AUTHORIZATION_IDS
            },
        }

    def run(self) -> dict[str, Any]:
        """Run B13.2 while holding all affected storage-domain reservations."""
        # Terminal replay has no writes and the prior run has already sealed
        # its release receipt, so do not reacquire a capacity lease here.
        evidence_identity = _ensure_directory(self.evidence_root)
        _close_pinned(evidence_identity)
        journal = RecoveryJournal(self.evidence_root / "migration-journal-b13.json", crash_at=self.crash_at, fault_injector=self.fault_injector)
        if journal.read()["state"] == "reactivated":
            return self._terminal_replay(journal, str(self.active_runtime.realm["id"]))
        if _has_symlink_component(self.disposable_root):
            raise MigrationError("B13.2 disposable target must be a fresh ordinary path")
        reservation = self._acquire_capacity(journal)
        self._capacity_reservation = reservation
        try:
            return self._run_reserved()
        finally:
            reservation.release()

    def _run_reserved(self) -> dict[str, Any]:
        realm_id = str(self.active_runtime.realm["id"])
        for authorization_id in B13_AUTHORIZATION_IDS:
            self._validate_auth(authorization_id, realm_id)
        journal = RecoveryJournal(self.evidence_root / "migration-journal-b13.json", crash_at=self.crash_at, fault_injector=self.fault_injector)
        current = journal.read()
        if current["state"] == "reactivated":
            return self._terminal_replay(journal, realm_id)
        binding = self._request_binding(realm_id)
        journal.bind(**binding)
        current = journal.read()

        if current["state"] == "prepared":
            if _has_symlink_component(self.recovery_base_backup) or _has_symlink_component(self.rollback_archive):
                raise MigrationError("B13.2 backup path contains a symlink component")
            if self.recovery_base_backup.exists():
                self._verify_backup(self.recovery_base_backup, realm_id)
            else:
                self._capacity_reservation.recheck()
                identity = _capture_parent(self.recovery_base_backup)
                try:
                    self.active_runtime.backup(self.recovery_base_backup, destination_identity=identity)
                finally:
                    _close_pinned(identity)
            base = self._verify_backup(self.recovery_base_backup, realm_id)
            rollback = self._verify_backup(self.rollback_archive, realm_id)
            base_effect = journal.effects().get("recovery-base")
            disposable_effect = journal.effects().get("disposable-restore")
            if disposable_effect or (base_effect and os.path.lexists(str(self.disposable_root))):
                # A crash after restore but before its durable effect leaves
                # the cursor in ``prepared`` with a candidate on disk. Reuse
                # only a candidate authenticated by the exact recovery backup
                # and classification captured before that restore; do not
                # mistake it for an operator-created pre-existing target.
                if not isinstance(base_effect, Mapping):
                    raise MigrationError("B13.2 restored disposable target has no recovery-base classification")
                classification = base_effect.get("payload", {}).get("classification")
                if not isinstance(classification, Mapping):
                    raise MigrationError("B13.2 recovery-base classification is missing")
                self._validate_purge_classification(self.disposable_root, realm_id, classification)
            else:
                classification = self._safe_disposable_target(realm_id)
            if base_effect:
                base_receipt = dict(base_effect.get("payload", {}))
                if base_receipt.get("classification") != dict(classification):
                    raise MigrationError("B13.2 recovery-base classification conflicts with its durable receipt")
                receipt_path = self.evidence_root / "b13-recovery-base.json"
                try:
                    existing_receipt = _read_json_pinned(receipt_path)
                except FileNotFoundError:
                    self._write("b13-recovery-base.json", base_receipt)
                except (OSError, ValueError, MigrationError) as exc:
                    raise MigrationError("B13.2 recovery-base receipt is unreadable") from exc
                else:
                    if existing_receipt != {"packet": "B13.2", **base_receipt}:
                        raise MigrationError("B13.2 recovery-base receipt conflicts with its durable effect")
            else:
                base_receipt = {"packet": "B13.2", "realm_id": realm_id, "active_root": str(self.active_runtime.store.root), "recovery_base_backup": str(self.recovery_base_backup), "recovery_base_manifest_sha256": _hash_file_pinned(self.recovery_base_backup / "manifest.json"), "rollback_archive": str(self.rollback_archive), "rollback_archive_manifest_sha256": _hash_file_pinned(self.rollback_archive / "manifest.json"), "active_runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "classification": classification}
                self._write("b13-recovery-base.json", base_receipt)
                journal.effect("recovery-base", **base_receipt)
            self._restore_or_reuse(self.recovery_base_backup, self.disposable_root, realm_id=realm_id, journal=journal, effect_name="disposable-restore", seam="disposable_restore")
            journal.transition("recovery_base", recovery_base_manifest_sha256=base["manifest"].get("manifest_sha256"), rollback_manifest_sha256=rollback["manifest"].get("manifest_sha256"), disposable_root=str(self.disposable_root))
            journal._inject("after_recovery_base")
            current = journal.read()

        if current["state"] == "recovery_base":
            base_effect = journal.effects().get("recovery-base")
            classification = (base_effect or {}).get("payload", {}).get("classification") or self._safe_disposable_target(realm_id)
            purge = self._purge_disposable(journal, realm_id, classification)
            purge_receipt_path = self.evidence_root / "purge-receipt-b13.json"
            purge_receipt = {"packet": "B13.2", **purge}
            try:
                existing_receipt = _read_json_pinned(purge_receipt_path)
            except FileNotFoundError:
                existing_receipt = None
            except (OSError, ValueError, MigrationError) as exc:
                raise MigrationError("B13.2 durable purge receipt is unreadable") from exc
            if existing_receipt is not None:
                if existing_receipt != purge_receipt:
                    raise MigrationError("B13.2 durable purge receipt conflicts with the purge effect")
            else:
                self._write("purge-receipt-b13.json", purge_receipt)
            journal.transition("purged", purge_receipt_sha256=_hash_file_pinned(purge_receipt_path))
            current = journal.read()

        if current["state"] == "purged":
            checkpoint = journal.effects().get("checkpoint")
            if checkpoint:
                checkpoint_payload = checkpoint["payload"]
            else:
                snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
                checkpoint_payload = {"packet": "B13.2", "checkpoint_id": new_id(), "realm_id": realm_id, "active_root": str(self.active_runtime.store.root.resolve()), "runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "runtime_session_id_before": self._runtime_session(self.active_runtime), "boot_identity_before": self._boot_identity(), "authorization_nonce_sha256": self._nonce_digest(self.authorizations["AUTH-REBOOT-R2"]), "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(snapshot)), "recovery_base_manifest_sha256": _hash_file_pinned(self.recovery_base_backup / "manifest.json"), "rollback_archive_manifest_sha256": _hash_file_pinned(self.rollback_archive / "manifest.json"), "created_at": time.time()}
                self._write("checkpoint-r2.json", checkpoint_payload)
                journal.effect("checkpoint", **checkpoint_payload)
            self._consume_auth(journal, "AUTH-REBOOT-R2", realm_id)
            journal.transition("checkpointed", checkpoint_id=checkpoint_payload["checkpoint_id"], runtime_epoch=checkpoint_payload["runtime_epoch"])
            current = journal.read()

        if current["state"] == "checkpointed":
            checkpoint = journal.effects()["checkpoint"]["payload"]
            self._consume_auth(journal, "AUTH-REBOOT-R2", realm_id)
            journal.transition("reboot_requested", checkpoint_id=checkpoint["checkpoint_id"])
            current = journal.read()

        if current["state"] == "reboot_requested":
            checkpoint = journal.effects()["checkpoint"]["payload"]
            reboot = self._resume_reboot(journal, realm_id, checkpoint)
            journal.transition("recovered", reboot=reboot, checkpoint_id=checkpoint["checkpoint_id"])
            current = journal.read()

        if current["state"] == "recovered":
            rollback_effect = journal.effects().get("final-rollback-restore")
            candidate = self.evidence_root / "b13-final-rollback-candidate"
            if rollback_effect:
                candidate = Path(rollback_effect["payload"]["destination"])
                verify_restore_candidate(candidate)
            else:
                self._restore_or_reuse(self.rollback_archive, candidate, realm_id=realm_id, journal=journal, effect_name="final-rollback-restore", seam="final_rollback_restore")
            self._consume_auth(journal, "AUTH-ROLLBACK-B13", realm_id)
            activation = journal.effects().get("final-rollback-activation")
            if activation:
                activation_payload = activation.get("payload", {})
                stored_epoch = activation_payload.get("runtime_epoch")
                current_epoch = int(self.active_runtime.health()["runtime_epoch"])
                if (activation_payload.get("destination") != str(candidate) or isinstance(stored_epoch, bool) or not isinstance(stored_epoch, int) or stored_epoch > current_epoch or _has_symlink_component(candidate) or not self._active_matches_candidate(candidate, realm_id)):
                    raise MigrationError("B13.2 durable rollback activation is not reusable")
                rollback = activation_payload["activation"]
            else:
                rollback = self._activate(candidate, "rolled_back", realm_id=realm_id, journal=journal, seam="final_rollback_activation")
                journal.effect("final-rollback-activation", activation=rollback, destination=str(candidate), runtime_epoch=int(self.active_runtime.health()["runtime_epoch"]))
            rollback_snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
            rollback_identity = {"realm_id": realm_id, "runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(rollback_snapshot)), "database_sha256": _database_snapshot_sha256(self.active_runtime.store.db_path, connection=self.active_runtime.store.conn)}
            self._write("activated-destination-b13-rollback.json", {"packet": "B13.2", "state": "rolled_back", **rollback_identity})
            journal.transition("rolled_back", activation=rollback, identity=rollback_identity)
            current = journal.read()

        if current["state"] == "rolled_back":
            react_effect = journal.effects().get("final-reactivation-restore")
            candidate = self.evidence_root / "b13-final-reactivation-candidate"
            if react_effect:
                candidate = Path(react_effect["payload"]["destination"])
                verify_restore_candidate(candidate)
            else:
                self._restore_or_reuse(self.recovery_base_backup, candidate, realm_id=realm_id, journal=journal, effect_name="final-reactivation-restore", seam="final_reactivation_restore")
            self._consume_auth(journal, "AUTH-REACTIVATION-B13", realm_id)
            activation = journal.effects().get("final-reactivation-activation")
            if activation:
                activation_payload = activation.get("payload", {})
                stored_epoch = activation_payload.get("runtime_epoch")
                current_epoch = int(self.active_runtime.health()["runtime_epoch"])
                if (activation_payload.get("destination") != str(candidate) or isinstance(stored_epoch, bool) or not isinstance(stored_epoch, int) or stored_epoch > current_epoch or _has_symlink_component(candidate) or not self._active_matches_candidate(candidate, realm_id)):
                    raise MigrationError("B13.2 durable reactivation is not reusable")
                reactivated = activation_payload["activation"]
            else:
                reactivated = self._activate(candidate, "reactivated", realm_id=realm_id, journal=journal, seam="final_reactivation_activation")
                journal.effect("final-reactivation-activation", activation=reactivated, destination=str(candidate), runtime_epoch=int(self.active_runtime.health()["runtime_epoch"]))
            final_snapshot = RuntimeServiceAdapter(self.active_runtime).destination_snapshot()
            checkpoint = journal.effects()["checkpoint"]["payload"]
            purge_receipt_path = self.evidence_root / "purge-receipt-b13.json"
            artifacts = self._activation_catalog_identity(realm_id)
            identity = {"packet": "B13.2", "state": "reactivated", "realm_id": realm_id, "root": str(self.active_runtime.store.root.resolve()), "runtime_epoch": int(self.active_runtime.health()["runtime_epoch"]), "runtime_session_id": self.active_runtime.runtime_session_id, "semantic_snapshot_sha256": _canonical_digest(_semantic_snapshot(final_snapshot)), "database_sha256": _database_snapshot_sha256(self.active_runtime.store.db_path, connection=self.active_runtime.store.conn), "database_semantic_sha256": _database_semantic_sha256(self.active_runtime.store.db_path, connection=self.active_runtime.store.conn), "cas_manifest_sha256": _canonical_digest(sorted([{key: item.get(key) for key in ("digest", "size", "sha256")} for item in final_snapshot.get("cas_objects", [])], key=lambda item: str(item.get("digest")))), "recovery_base_manifest_sha256": checkpoint["recovery_base_manifest_sha256"], "rollback_archive_manifest_sha256": checkpoint["rollback_archive_manifest_sha256"], "purge_receipt_sha256": _hash_file_pinned(purge_receipt_path), "purged_disposable_root": str(self.disposable_root), "activation_catalog_identity": artifacts, "integrity_ok": bool(self.active_runtime.doctor()["ok"])}
            if not identity["integrity_ok"] or identity["semantic_snapshot_sha256"] != checkpoint["semantic_snapshot_sha256"]:
                raise MigrationError("B13.2 final reactivation does not match the pre-R2 active identity")
            self._write("activated-destination-b13.json", identity)
            journal.effect("final-identity", identity=identity)
            reservation = getattr(self, "_capacity_reservation", None)
            if reservation is not None:
                journal.effect("capacity-release", reservation_id=reservation.reservation_id, reason="terminal")
            final = journal.transition("reactivated", activation=reactivated, identity=identity)
            return {"packet": "B13.2", "journal": final, "recovery_base": journal.effects().get("recovery-base", {}).get("payload"), "purge": journal.effects().get("purge-complete", {}).get("payload"), "reboot": journal.effects().get("reboot-complete", {}).get("payload"), "rollback": rollback_identity if "rollback_identity" in locals() else None, "reactivation": reactivated, "identity": identity, "active_runtime": self.active_runtime, "idempotent": False}

        raise MigrationError(f"B13.2 recovery stopped in unexpected state {journal.read()['state']!r}")


def run_b13_recovery(active_runtime: Any, *, recovery_base_backup: str | Path, rollback_archive: str | Path, evidence_root: str | Path, disposable_root: str | Path, authorizations: Mapping[str, Mapping[str, Any]], crash_at: str | None = None, fault_injector: Callable[[str], None] | None = None, reboot_executor: Callable[..., Any] | None = None, boot_identity_provider: Callable[[], str] | None = None, source_root: str | Path | None = None) -> dict[str, Any]:
    return B13Recovery(active_runtime, Path(recovery_base_backup), Path(rollback_archive), Path(evidence_root), Path(disposable_root), authorizations, crash_at=crash_at, fault_injector=fault_injector, reboot_executor=reboot_executor, boot_identity_provider=boot_identity_provider, source_root=Path(source_root) if source_root is not None else None).run()


__all__ = ["B13_AUTHORIZATION_IDS", "B13Recovery", "RecoveryJournal", "actual_reboot_executor", "issue_b13_authorizations", "run_b13_recovery"]
