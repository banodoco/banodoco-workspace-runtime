"""Durable digest-only state for the private two-owner Runtime handoff."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .errors import ConflictError, ValidationError


RECORD_VERSION = "runtime.local-worker-handoff-record/v1"
CAPABILITY_VERSION = "runtime.local-worker-handoff-capability/v1"
EXPORT_SEAL_VERSION = "runtime.local-worker-handoff-export-seal/v1"
STATES = (
    "OWNED", "PREPARED", "COMMITTED_ORPHAN", "FINALIZING", "ADOPTED", "ABORTED",
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLEANUP_ROLES = ("worker", "host", "engine", "engine_listener")
_TRANSITIONS = {
    "OWNED": frozenset({"PREPARED", "ABORTED"}),
    "PREPARED": frozenset({"OWNED", "COMMITTED_ORPHAN", "ABORTED"}),
    "COMMITTED_ORPHAN": frozenset({"FINALIZING", "ABORTED"}),
    "FINALIZING": frozenset({"ADOPTED", "ABORTED"}),
    "ADOPTED": frozenset(),
    "ABORTED": frozenset(),
}


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError("handoff value must be canonical JSON") from exc


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def nonce_digest(raw_nonce: str) -> str:
    if not isinstance(raw_nonce, str) or len(raw_nonce) < 32:
        raise ValidationError("handoff capability nonce is invalid")
    return "sha256:" + hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()


def _contains_raw_capability(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            key in {"nonce", "raw_nonce"} or _contains_raw_capability(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_raw_capability(item) for item in value)
    return False


def _validate_cleanup_receipt(receipt: object, sealed_export: object) -> None:
    required = {
        "version", "runtime_instance_id", "receipt_evidence_digest",
        "expected_processes", "graph_and_engine_listener_absent",
        "authority_descriptors_closed", "worker_credential_revoked",
        "catalog_neutral", "discovery_absent",
        "replacement_graph_not_launched", "final_census", "complete",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != required:
        raise ConflictError("ABORTED handoff cleanup receipt is invalid")
    export_receipt = (
        sealed_export.get("receipt") if isinstance(sealed_export, Mapping) else None
    )
    if not isinstance(export_receipt, Mapping):
        raise ConflictError("ABORTED cleanup is not bound to the sealed export receipt")
    for field in (
        "graph_and_engine_listener_absent", "authority_descriptors_closed",
        "worker_credential_revoked", "catalog_neutral", "discovery_absent",
        "replacement_graph_not_launched", "complete",
    ):
        if receipt.get(field) is not True:
            raise ConflictError("ABORTED handoff cleanup receipt is incomplete")
    if (
        not isinstance(receipt.get("runtime_instance_id"), str)
        or not receipt["runtime_instance_id"]
        or not isinstance(receipt.get("receipt_evidence_digest"), str)
        or not _SHA256_RE.fullmatch(receipt["receipt_evidence_digest"])
    ):
        raise ConflictError("ABORTED handoff cleanup authority is invalid")
    expected = receipt.get("expected_processes")
    if not isinstance(expected, list) or len(expected) != len(_CLEANUP_ROLES):
        raise ConflictError("ABORTED cleanup expected process set is incomplete")
    expected_by_role: dict[str, Mapping[str, Any]] = {}
    for row in expected:
        if not isinstance(row, Mapping) or set(row) != {
            "role", "identity", "identity_digest",
        }:
            raise ConflictError("ABORTED cleanup process identity row is invalid")
        role = row.get("role")
        identity = row.get("identity")
        if (
            role not in _CLEANUP_ROLES
            or role in expected_by_role
            or not isinstance(identity, Mapping)
            or isinstance(identity.get("pid"), bool)
            or not isinstance(identity.get("pid"), int)
            or identity["pid"] <= 0
            or not isinstance(identity.get("birth_id"), str)
            or not identity["birth_id"]
            or row.get("identity_digest") != digest(identity)
        ):
            raise ConflictError("ABORTED cleanup process identity row is invalid")
        expected_by_role[str(role)] = row
    if set(expected_by_role) != set(_CLEANUP_ROLES):
        raise ConflictError("ABORTED cleanup process roles are incomplete")
    if receipt.get("receipt_evidence_digest") != export_receipt.get("evidence_digest"):
        raise ConflictError("ABORTED cleanup evidence digest changed from sealed export")
    for role in _CLEANUP_ROLES:
        if expected_by_role[role]["identity"] != export_receipt.get(role):
            raise ConflictError("ABORTED cleanup identity changed from sealed export")
    census = receipt.get("final_census")
    if not isinstance(census, Mapping) or set(census) != {
        "process_rows", "listener", "uncertainties", "census_digest",
    }:
        raise ConflictError("ABORTED final cleanup census is invalid")
    rows = census.get("process_rows")
    if not isinstance(rows, list) or len(rows) != len(_CLEANUP_ROLES):
        raise ConflictError("ABORTED final process census is incomplete")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "role", "pid", "expected_birth_id", "identity_digest",
            "observed_birth_id", "associated_alive", "absent",
        }:
            raise ConflictError("ABORTED final process census row is invalid")
        role = row.get("role")
        expected_row = expected_by_role.get(str(role))
        identity = expected_row.get("identity") if expected_row else None
        if (
            expected_row is None
            or role in seen
            or row.get("pid") != identity.get("pid")
            or row.get("expected_birth_id") != identity.get("birth_id")
            or row.get("identity_digest") != expected_row.get("identity_digest")
            or row.get("associated_alive") is not False
            or row.get("absent") is not True
            or (
                row.get("observed_birth_id") is not None
                and row.get("observed_birth_id") == row.get("expected_birth_id")
            )
        ):
            raise ConflictError("ABORTED final process census row is invalid")
        seen.add(str(role))
    listener = census.get("listener")
    engine_listener = expected_by_role["engine_listener"]["identity"]
    engine_binding = export_receipt.get("engine_binding")
    parsed_endpoint = urlsplit(
        str(engine_binding.get("endpoint") or "")
        if isinstance(engine_binding, Mapping) else ""
    )
    try:
        endpoint_host, endpoint_port = parsed_endpoint.hostname, parsed_endpoint.port
    except ValueError as exc:
        raise ConflictError("sealed export listener endpoint is invalid") from exc
    if (
        seen != set(_CLEANUP_ROLES)
        or not isinstance(listener, Mapping)
        or set(listener) != {
            "host", "port", "expected_owner_pid", "expected_owner_birth_id",
            "observed_owner_pid", "owner_absent", "port_free",
        }
        or listener.get("expected_owner_pid") != engine_listener.get("pid")
        or listener.get("expected_owner_birth_id") != engine_listener.get("birth_id")
        or endpoint_host != listener.get("host")
        or endpoint_port != listener.get("port")
        or not isinstance(engine_binding, Mapping)
        or engine_binding.get("socket_owner_pid") != engine_listener.get("pid")
        or listener.get("observed_owner_pid") is not None
        or listener.get("owner_absent") is not True
        or listener.get("port_free") is not True
        or not isinstance(listener.get("host"), str)
        or isinstance(listener.get("port"), bool)
        or not isinstance(listener.get("port"), int)
        or not (1 <= listener["port"] <= 65535)
        or census.get("uncertainties") != []
    ):
        raise ConflictError("ABORTED final listener census is invalid")
    unsigned_census = {
        key: item for key, item in census.items() if key != "census_digest"
    }
    if census.get("census_digest") != digest(unsigned_census):
        raise ConflictError("ABORTED final cleanup census digest is invalid")


def _safe_parent(path: Path) -> None:
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ValidationError("handoff record parent must be an ordinary directory")
    observed = parent.lstat()
    if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != 0o700:
        raise ValidationError("handoff record parent must be owner-only")


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _safe_parent(path)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


class HandoffRecord:
    """Owner-only CAS record. Raw capabilities are never accepted here."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValidationError("handoff record path must be absolute")
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    @staticmethod
    def _without_record_digest(value: Mapping[str, Any]) -> dict[str, Any]:
        return {key: item for key, item in value.items() if key != "record_digest"}

    @staticmethod
    def _validate(value: Mapping[str, Any]) -> None:
        if value.get("version") != RECORD_VERSION or value.get("state") not in STATES:
            raise ConflictError("handoff record version or state is invalid")
        required_base = {
            "version", "state", "handoff_id", "realm_id", "realm_root",
            "support_root", "deadline_monotonic", "deadline_unix_ms",
            "nonce_digest", "sealed_record_digest", "old_owner", "export",
            "export_sealed_digest", "adopter", "record_digest",
            "predecessor_active_ref_digest",
        }
        if not required_base.issubset(value):
            raise ConflictError("handoff record schema is incomplete")
        if (
            not isinstance(value.get("handoff_id"), str)
            or not value["handoff_id"]
            or not isinstance(value.get("realm_id"), str)
            or not value["realm_id"]
            or not isinstance(value.get("realm_root"), str)
            or not Path(value["realm_root"]).is_absolute()
            or not isinstance(value.get("support_root"), str)
            or not Path(value["support_root"]).is_absolute()
            or isinstance(value.get("deadline_monotonic"), bool)
            or not isinstance(value.get("deadline_monotonic"), (int, float))
            or not math.isfinite(float(value["deadline_monotonic"]))
            or isinstance(value.get("deadline_unix_ms"), bool)
            or not isinstance(value.get("deadline_unix_ms"), int)
            or not isinstance(value.get("old_owner"), Mapping)
            or value.get("export") is not None
            and not isinstance(value.get("export"), Mapping)
            or value.get("adopter") is not None
            and not isinstance(value.get("adopter"), Mapping)
        ):
            raise ConflictError("handoff record schema is invalid")
        for field in ("nonce_digest", "sealed_record_digest", "export_sealed_digest"):
            observed = value.get(field)
            if observed is not None and (
                not isinstance(observed, str) or not _SHA256_RE.fullmatch(observed)
            ):
                raise ConflictError(f"handoff record {field} is invalid")
        predecessor = value.get("predecessor_active_ref_digest")
        if predecessor is not None and (
            not isinstance(predecessor, str) or not _SHA256_RE.fullmatch(predecessor)
        ):
            raise ConflictError("handoff predecessor active-reference digest is invalid")
        if _contains_raw_capability(value):
            raise ConflictError("handoff record must not contain a raw capability")
        expected = digest(HandoffRecord._without_record_digest(value))
        if value.get("record_digest") != expected:
            raise ConflictError("handoff record digest is invalid")
        if value.get("state") == "ABORTED":
            receipt = value.get("cleanup_receipt")
            _validate_cleanup_receipt(receipt, value.get("export"))
            if value.get("cleanup_receipt_digest") != digest(receipt):
                raise ConflictError("ABORTED handoff cleanup receipt is invalid")
        if value.get("state") == "ADOPTED":
            finalization = value.get("finalization")
            final_ack = finalization.get("final_ack") if isinstance(finalization, dict) else None
            if (
                value.get("owner_a_released") is not True
                or not isinstance(value.get("adopter"), Mapping)
                or not isinstance(value.get("new_owner"), Mapping)
                or not isinstance(value.get("result"), Mapping)
                or not isinstance(finalization, dict)
                or set(finalization) != {"final_ack", "ready_surfaces"}
                or finalization.get("ready_surfaces") is not True
                or not isinstance(final_ack, dict)
                or set(final_ack) != {
                    "request_digest", "worker_ack_digest", "host_ack_digest",
                }
                or any(
                    not isinstance(final_ack.get(key), str)
                    or not _SHA256_RE.fullmatch(final_ack[key])
                    for key in final_ack
                )
                or not isinstance(value.get("publication_predecessor_digest"), str)
                or not _SHA256_RE.fullmatch(value["publication_predecessor_digest"])
            ):
                raise ConflictError("ADOPTED handoff publication evidence is invalid")

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            observed = self.path.lstat()
            if self.path.is_symlink() or not stat.S_ISREG(observed.st_mode):
                raise ConflictError("handoff record must be an ordinary file")
            if observed.st_uid != os.getuid() or stat.S_IMODE(observed.st_mode) != 0o600:
                raise ConflictError("handoff record must be owner-only")
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConflictError("handoff record is unavailable") from exc
        if not isinstance(value, dict):
            raise ConflictError("handoff record must be an object")
        self._validate(value)
        return value

    def read(self) -> dict[str, Any]:
        return self._read_unlocked()

    def create(self, initial: Mapping[str, Any]) -> dict[str, Any]:
        if self.path.exists() or self.path.is_symlink():
            raise ConflictError("handoff record already exists")
        value = dict(initial)
        if value.get("version") != RECORD_VERSION or value.get("state") != "OWNED":
            raise ValidationError("new handoff record must begin in OWNED")
        if value.get("nonce_digest") is not None or value.get("sealed_record_digest") is not None:
            raise ValidationError("new handoff record must be unsealed")
        if _contains_raw_capability(value):
            raise ValidationError("handoff record must not contain a raw capability")
        value["record_digest"] = digest(self._without_record_digest(value))
        _atomic_json(self.path, value)
        self._validate(value)
        return value

    def _locked(self):
        _safe_parent(self.path)
        descriptor = os.open(
            self.lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor

    def seal(self, *, expected_record_digest: str, nonce_sha256: str) -> dict[str, Any]:
        if not isinstance(nonce_sha256, str) or not _SHA256_RE.fullmatch(nonce_sha256):
            raise ValidationError("handoff capability digest is invalid")
        descriptor = self._locked()
        try:
            current = self._read_unlocked()
            if current["record_digest"] != expected_record_digest or current["state"] != "OWNED":
                raise ConflictError("handoff record changed before sealing")
            if current.get("nonce_digest") is not None:
                raise ConflictError("handoff record capability is already sealed")
            candidate = {
                **self._without_record_digest(current),
                "nonce_digest": nonce_sha256,
            }
            sealed = digest(
                {
                    key: item
                    for key, item in candidate.items()
                    if key != "sealed_record_digest"
                }
            )
            candidate["sealed_record_digest"] = sealed
            candidate["record_digest"] = digest(self._without_record_digest(candidate))
            _atomic_json(self.path, candidate)
            return candidate
        finally:
            os.close(descriptor)

    def transition(
        self,
        *,
        expected_state: str,
        new_state: str,
        handoff_id: str,
        sealed_record_digest: str,
        expected_record_digest: str | None = None,
        updates: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if new_state not in STATES:
            raise ValidationError("handoff state transition target is invalid")
        if new_state not in _TRANSITIONS.get(expected_state, frozenset()):
            raise ValidationError("handoff state transition is invalid")
        descriptor = self._locked()
        try:
            current = self._read_unlocked()
            if (
                current.get("state") != expected_state
                or current.get("handoff_id") != handoff_id
                or current.get("sealed_record_digest") != sealed_record_digest
                or (
                    expected_record_digest is not None
                    and current.get("record_digest") != expected_record_digest
                )
            ):
                raise ConflictError("handoff state compare-and-swap failed")
            update_values = dict(updates or {})
            if set(update_values) & {
                "version", "handoff_id", "realm_id", "realm_root", "support_root",
                "deadline_monotonic", "deadline_unix_ms", "nonce_digest",
                "sealed_record_digest", "old_owner", "export", "export_sealed_digest",
                "adopter",
                "predecessor_active_ref_digest",
            }:
                raise ValidationError("handoff immutable authority fields cannot be rewritten")
            candidate = {**self._without_record_digest(current), **update_values}
            if _contains_raw_capability(candidate):
                raise ValidationError("handoff state must not persist a raw capability")
            candidate["state"] = new_state
            candidate["record_digest"] = digest(self._without_record_digest(candidate))
            self._validate(candidate)
            _atomic_json(self.path, candidate)
            return candidate
        finally:
            os.close(descriptor)

    def bind_export(
        self,
        *,
        handoff_id: str,
        sealed_record_digest: str,
        expected_record_digest: str,
        export: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Bind immutable receipt/graph facts before authority descriptors move."""

        if not isinstance(export, Mapping) or not export:
            raise ValidationError("handoff export facts are invalid")
        if _contains_raw_capability(export):
            raise ValidationError("handoff export facts must not contain a raw capability")
        descriptor = self._locked()
        try:
            current = self._read_unlocked()
            if (
                current.get("state") != "OWNED"
                or current.get("handoff_id") != handoff_id
                or current.get("sealed_record_digest") != sealed_record_digest
                or current.get("record_digest") != expected_record_digest
                or current.get("export") is not None
                or current.get("export_sealed_digest") is not None
            ):
                raise ConflictError("handoff export compare-and-swap failed")
            export_value = dict(export)
            export_sealed_digest = digest({
                "version": EXPORT_SEAL_VERSION,
                "sealed_record_digest": sealed_record_digest,
                "nonce_digest": current["nonce_digest"],
                "export": export_value,
            })
            candidate = {
                **self._without_record_digest(current),
                "export": export_value,
                "export_sealed_digest": export_sealed_digest,
            }
            candidate["record_digest"] = digest(self._without_record_digest(candidate))
            _atomic_json(self.path, candidate)
            return candidate
        finally:
            os.close(descriptor)

    def bind_adopter(
        self,
        *,
        handoff_id: str,
        sealed_record_digest: str,
        expected_record_digest: str,
        adopter: Mapping[str, Any],
    ) -> dict[str, Any]:
        """CAS-bind exactly one owner B while state remains COMMITTED_ORPHAN."""

        expected_keys = {"pid", "birth_id", "runtime_instance_id"}
        if (
            not isinstance(adopter, Mapping)
            or set(adopter) != expected_keys
            or isinstance(adopter.get("pid"), bool)
            or not isinstance(adopter.get("pid"), int)
            or int(adopter["pid"]) <= 0
            or not all(isinstance(adopter.get(key), str) and adopter.get(key) for key in ("birth_id", "runtime_instance_id"))
        ):
            raise ValidationError("handoff adopter identity is invalid")
        descriptor = self._locked()
        try:
            current = self._read_unlocked()
            if (
                current.get("state") != "COMMITTED_ORPHAN"
                or current.get("handoff_id") != handoff_id
                or current.get("sealed_record_digest") != sealed_record_digest
                or current.get("record_digest") != expected_record_digest
                or current.get("adopter") is not None
            ):
                raise ConflictError("handoff sole-adopter compare-and-swap failed")
            candidate = {
                **self._without_record_digest(current),
                "adopter": dict(adopter),
            }
            candidate["record_digest"] = digest(self._without_record_digest(candidate))
            _atomic_json(self.path, candidate)
            return candidate
        finally:
            os.close(descriptor)

    def checkpoint_finalizing(
        self,
        *,
        handoff_id: str,
        sealed_record_digest: str,
        expected_record_digest: str,
        final_ack: Mapping[str, str] | None,
        ready_surfaces: bool,
    ) -> dict[str, Any]:
        """Advance B's recoverable publication checkpoints while claims stay closed."""

        if final_ack is not None and (
            not isinstance(final_ack, Mapping)
            or set(final_ack) != {
                "request_digest", "worker_ack_digest", "host_ack_digest",
            }
            or any(
                not isinstance(value, str) or not _SHA256_RE.fullmatch(value)
                for value in final_ack.values()
            )
        ):
            raise ValidationError("handoff final acknowledgement evidence is invalid")
        if not isinstance(ready_surfaces, bool):
            raise ValidationError("handoff ready-surface checkpoint must be boolean")
        if ready_surfaces and final_ack is None:
            raise ValidationError("handoff ready surfaces require a final acknowledgement")
        descriptor = self._locked()
        try:
            current = self._read_unlocked()
            if (
                current.get("state") != "FINALIZING"
                or current.get("handoff_id") != handoff_id
                or current.get("sealed_record_digest") != sealed_record_digest
                or current.get("record_digest") != expected_record_digest
            ):
                raise ConflictError("handoff finalization compare-and-swap failed")
            observed = current.get("finalization")
            if not isinstance(observed, Mapping) or set(observed) != {
                "final_ack", "ready_surfaces",
            }:
                raise ConflictError("handoff finalization state is invalid")
            observed_ack = observed["final_ack"]
            if observed_ack is not None and final_ack != observed_ack:
                raise ConflictError("handoff final acknowledgement cannot be rolled back")
            if bool(observed["ready_surfaces"]) and not ready_surfaces:
                raise ConflictError("handoff ready surfaces cannot be rolled back")
            candidate = {
                **self._without_record_digest(current),
                "finalization": {
                    "final_ack": final_ack,
                    "ready_surfaces": ready_surfaces,
                },
            }
            candidate["record_digest"] = digest(self._without_record_digest(candidate))
            _atomic_json(self.path, candidate)
            return candidate
        finally:
            os.close(descriptor)


__all__ = [
    "CAPABILITY_VERSION",
    "EXPORT_SEAL_VERSION",
    "HandoffRecord",
    "RECORD_VERSION",
    "STATES",
    "canonical_bytes",
    "digest",
    "nonce_digest",
]
