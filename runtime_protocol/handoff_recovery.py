"""Strict, shared recovery for cleanup-complete orderly handoffs.

Both the installed launcher and a direct Runtime start enter this gate before
ordinary support-state mutation.  Launcher lock order is bootstrap then
coordinator; direct starts acquire the same pair in that order.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterator, Mapping

from .errors import ConflictError
from .orderly_handoff import HandoffRecord, digest
from .util import atomic_json_write

try:
    import fcntl
except ImportError:  # pragma: no cover - supported beta host is POSIX
    fcntl = None


_REQUEST_NAME = "orderly-handoff-request.json"
_ACTIVE_NAME = "orderly-handoff-adopted-owner.json"
_RESOLUTION_PREFIX = "orderly-handoff-predecessor-resolution-"
_RESOLUTION_SUFFIX = ".json"
_QUARANTINE_PREFIX = ".orderly-handoff-request-clearing-"
_QUARANTINE_SUFFIX = ".json"
_RETIRED_PREFIX = ".orderly-handoff-retired-"
_RETIRED_SUFFIX = ".json"
_RETIRED_SITES = ("dual-name", "clearance")
_TRANSFER_VERSION = "runtime.local-worker-handoff-transfer/v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_MAX_AUTHORITY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class _OwnerJSON:
    path: Path
    raw: bytes
    value: dict[str, Any]
    device: int
    inode: int
    mode: int
    uid: int

    @property
    def file_sha256(self) -> str:
        return hashlib.sha256(self.raw).hexdigest()

    @property
    def signature(self) -> tuple[object, ...]:
        return (
            self.path.name,
            self.device,
            self.inode,
            self.mode,
            self.uid,
            len(self.raw),
            self.file_sha256,
        )


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ConflictError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise ConflictError(f"{label} must be an object")
    return value


def _owner_json(path: Path, label: str) -> _OwnerJSON:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ConflictError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise ConflictError(f"{label} is not an owner-only regular file")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ConflictError(f"{label} changed while opening")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, _MAX_AUTHORITY_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_AUTHORITY_BYTES:
                raise ConflictError(f"{label} is too large")
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            raise ConflictError(f"{label} changed while reading")
    except OSError as exc:
        raise ConflictError(f"{label} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raw = b"".join(chunks)
    return _OwnerJSON(
        path=path,
        raw=raw,
        value=_json_object(raw, label),
        device=int(opened.st_dev),
        inode=int(opened.st_ino),
        mode=stat.S_IMODE(opened.st_mode),
        uid=int(opened.st_uid),
    )


def _optional_owner_json(path: Path, label: str) -> _OwnerJSON | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConflictError(f"{label} is unavailable") from exc
    return _owner_json(path, label)


def _resolution_paths(support_root: Path) -> list[Path]:
    try:
        names = sorted(
            entry.name
            for entry in os.scandir(support_root)
            if entry.name.startswith(_RESOLUTION_PREFIX)
            and entry.name.endswith(_RESOLUTION_SUFFIX)
        )
    except OSError as exc:
        raise ConflictError("handoff predecessor journal enumeration failed") from exc
    return [support_root / name for name in names]


def _quarantine_paths(support_root: Path) -> list[Path]:
    try:
        names = sorted(
            entry.name
            for entry in os.scandir(support_root)
            if entry.name.startswith(_QUARANTINE_PREFIX)
            and entry.name.endswith(_QUARANTINE_SUFFIX)
        )
    except OSError as exc:
        raise ConflictError("handoff pointer quarantine enumeration failed") from exc
    return [support_root / name for name in names]


def _retired_paths(support_root: Path) -> list[Path]:
    try:
        names = sorted(
            entry.name
            for entry in os.scandir(support_root)
            if entry.name.startswith(_RETIRED_PREFIX)
            and entry.name.endswith(_RETIRED_SUFFIX)
        )
    except OSError as exc:
        raise ConflictError("retired handoff pointer enumeration failed") from exc
    return [support_root / name for name in names]


def _validate_resolution(
    support_root: Path, snapshot: _OwnerJSON
) -> dict[str, Any]:
    value = snapshot.value
    expected = {
        "version", "state", "handoff_id", "aborted_record_path",
        "aborted_record_digest", "cleanup_receipt_digest",
        "predecessor_active_ref_digest", "predecessor_record_path",
        "predecessor_record_digest", "archived_active_reference_path",
        "active_reference_file_sha256", "active_reference_archived",
        "successor_request_pointer_path", "successor_request_pointer_sha256",
        "successor_request_pointer_byte_length",
        "successor_request_pointer_device", "successor_request_pointer_inode",
        "successor_request_pointer_mode", "successor_request_pointer_uid",
        "successor_request_quarantine_path",
        "resolution_digest",
    }
    handoff_id = value.get("handoff_id")
    state = value.get("state")
    try:
        raw_paths = {
            name: value[name]
            for name in (
                "aborted_record_path",
                "predecessor_record_path",
                "archived_active_reference_path",
                "successor_request_pointer_path",
                "successor_request_quarantine_path",
            )
        }
        if any(type(item) is not str or not item for item in raw_paths.values()):
            raise ValueError("resolution path is not a nonempty string")
        parsed_paths = {name: Path(item) for name, item in raw_paths.items()}
        if any(
            not path.is_absolute() or str(path) != raw_paths[name]
            for name, path in parsed_paths.items()
        ):
            raise ValueError("resolution path is not canonical absolute spelling")
        aborted_path = parsed_paths["aborted_record_path"]
        predecessor_path = parsed_paths["predecessor_record_path"]
        archive_path = parsed_paths["archived_active_reference_path"]
        pointer_path = parsed_paths["successor_request_pointer_path"]
        quarantine_path = parsed_paths["successor_request_quarantine_path"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ConflictError("handoff predecessor resolution paths are invalid") from exc
    numeric = (
        value.get("successor_request_pointer_byte_length"),
        value.get("successor_request_pointer_device"),
        value.get("successor_request_pointer_inode"),
        value.get("successor_request_pointer_mode"),
        value.get("successor_request_pointer_uid"),
    )
    if (
        set(value) != expected
        or value.get("version") != 1
        or state not in {"PREPARED", "COMPLETE"}
        or not isinstance(handoff_id, str)
        or not handoff_id
        or len(handoff_id) > 256
        or snapshot.path.name
        != f"{_RESOLUTION_PREFIX}{handoff_id}{_RESOLUTION_SUFFIX}"
        or aborted_path != support_root / f"orderly-handoff-record-{handoff_id}.json"
        or predecessor_path.parent != support_root
        or not predecessor_path.name.startswith("orderly-handoff-record-")
        or predecessor_path.suffix != ".json"
        or archive_path
        != support_root / f"orderly-handoff-predecessor-active-{handoff_id}.json"
        or pointer_path != support_root / _REQUEST_NAME
        or quarantine_path
        != support_root / f"{_QUARANTINE_PREFIX}{handoff_id}{_QUARANTINE_SUFFIX}"
        or not all(
            isinstance(value.get(name), str)
            and value[name].startswith("sha256:")
            and _SHA256_RE.fullmatch(value[name][7:]) is not None
            for name in (
                "aborted_record_digest",
                "cleanup_receipt_digest",
                "predecessor_active_ref_digest",
                "predecessor_record_digest",
            )
        )
        or not isinstance(value.get("active_reference_file_sha256"), str)
        or _SHA256_RE.fullmatch(value["active_reference_file_sha256"]) is None
        or not isinstance(value.get("successor_request_pointer_sha256"), str)
        or _SHA256_RE.fullmatch(value["successor_request_pointer_sha256"]) is None
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in numeric
        )
        or value.get("successor_request_pointer_byte_length") < 1
        or value.get("successor_request_pointer_device") < 1
        or value.get("successor_request_pointer_inode") < 1
        or value.get("successor_request_pointer_mode") != 0o600
        or value.get("successor_request_pointer_uid") != os.getuid()
        or value.get("active_reference_archived") is not (state == "COMPLETE")
        or value.get("resolution_digest")
        != digest({key: item for key, item in value.items() if key != "resolution_digest"})
    ):
        raise ConflictError("handoff predecessor resolution is invalid")
    return value


def _scan_resolutions(
    support_root: Path,
) -> list[tuple[_OwnerJSON, dict[str, Any]]]:
    initial_names = [path.name for path in _resolution_paths(support_root)]
    first = [
        (_owner_json(path, "handoff predecessor resolution"), None)
        for path in (support_root / name for name in initial_names)
    ]
    validated = [
        (snapshot, _validate_resolution(support_root, snapshot))
        for snapshot, _ in first
    ]
    final_names = [path.name for path in _resolution_paths(support_root)]
    if final_names != initial_names:
        raise ConflictError("handoff predecessor journal set changed during enumeration")
    repeated = [
        _owner_json(support_root / name, "handoff predecessor resolution")
        for name in final_names
    ]
    if [item.signature for item in repeated] != [
        item.signature for item, _ in validated
    ]:
        raise ConflictError("handoff predecessor journal changed during validation")
    if [item.raw for item in repeated] != [item.raw for item, _ in validated]:
        raise ConflictError("handoff predecessor journal bytes changed during validation")
    prepared = [value for _, value in validated if value["state"] == "PREPARED"]
    if len(prepared) > 1:
        raise ConflictError("multiple predecessor resolution journals are actionable")
    return validated


def _scan_quarantines(
    support_root: Path,
    journals: list[tuple[_OwnerJSON, dict[str, Any]]],
) -> list[tuple[_OwnerJSON, dict[str, Any]]]:
    initial_names = [path.name for path in _quarantine_paths(support_root)]
    first = [
        _owner_json(path, "quarantined orderly handoff request pointer")
        for path in (support_root / name for name in initial_names)
    ]
    final_names = [path.name for path in _quarantine_paths(support_root)]
    if final_names != initial_names:
        raise ConflictError("handoff pointer quarantine set changed during enumeration")
    repeated = [
        _owner_json(
            support_root / name, "quarantined orderly handoff request pointer"
        )
        for name in final_names
    ]
    if [item.signature for item in repeated] != [item.signature for item in first] or [
        item.raw for item in repeated
    ] != [item.raw for item in first]:
        raise ConflictError("handoff pointer quarantine changed during validation")
    bound: list[tuple[_OwnerJSON, dict[str, Any]]] = []
    for snapshot in first:
        matching = [
            value
            for _, value in journals
            if value["state"] == "COMPLETE"
            and Path(str(value["successor_request_quarantine_path"]))
            == snapshot.path
        ]
        if len(matching) != 1:
            raise ConflictError("handoff pointer quarantine is not uniquely journal-bound")
        bound.append((snapshot, matching[0]))
    if len(bound) > 1:
        raise ConflictError("multiple handoff pointer quarantines are unresolved")
    return bound


def _scan_retired(
    support_root: Path,
    journals: list[tuple[_OwnerJSON, dict[str, Any]]],
) -> list[tuple[_OwnerJSON, dict[str, Any], str]]:
    initial_names = [path.name for path in _retired_paths(support_root)]
    first = [
        _owner_json(path, "retired orderly handoff request pointer")
        for path in (support_root / name for name in initial_names)
    ]
    final_names = [path.name for path in _retired_paths(support_root)]
    if final_names != initial_names:
        raise ConflictError("retired handoff pointer set changed during enumeration")
    repeated = [
        _owner_json(support_root / name, "retired orderly handoff request pointer")
        for name in final_names
    ]
    if [item.signature for item in repeated] != [item.signature for item in first] or [
        item.raw for item in repeated
    ] != [item.raw for item in first]:
        raise ConflictError("retired handoff pointer changed during validation")
    bound: list[tuple[_OwnerJSON, dict[str, Any], str]] = []
    for snapshot in first:
        matching = [
            (value, site)
            for _, value in journals
            if value["state"] == "COMPLETE"
            for site in _RETIRED_SITES
            if snapshot.path
            == support_root
            / f"{_RETIRED_PREFIX}{value['handoff_id']}-{site}{_RETIRED_SUFFIX}"
        ]
        if len(matching) != 1:
            raise ConflictError("retired handoff pointer is not uniquely journal-bound")
        resolution, site = matching[0]
        if not _pointer_identity_matches_resolution(snapshot, resolution):
            raise ConflictError("retired successor request pointer custody changed")
        bound.append((snapshot, resolution, site))
    return bound


def _pointer_snapshot(support_root: Path) -> _OwnerJSON | None:
    path = support_root / _REQUEST_NAME
    snapshot = _optional_owner_json(path, "orderly handoff request pointer")
    if snapshot is None:
        return None
    value = snapshot.value
    expected = {
        "version", "handoff_id", "record_path", "socket_path",
        "coordinator_pid", "coordinator_birth_id",
    }
    try:
        record_path = Path(str(value["record_path"]))
        socket_path = Path(str(value["socket_path"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ConflictError("orderly handoff request pointer paths are invalid") from exc
    pid = value.get("coordinator_pid")
    if (
        set(value) != expected
        or value.get("version") != _TRANSFER_VERSION
        or not isinstance(value.get("handoff_id"), str)
        or not value["handoff_id"]
        or len(value["handoff_id"]) > 256
        or record_path
        != support_root / f"orderly-handoff-record-{value['handoff_id']}.json"
        or not socket_path.is_absolute()
        or socket_path.name != "coordinator.sock"
        or isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 0
        or not isinstance(value.get("coordinator_birth_id"), str)
        or not value["coordinator_birth_id"]
    ):
        raise ConflictError("orderly handoff request pointer is invalid")
    return snapshot


def validate_pending_adopter_request(
    support_root: Path,
    *,
    handoff_id: str,
    record_path: Path,
    record_digest: str,
    predecessor_active_ref_digest: str | None,
    old_owner: Mapping[str, Any],
) -> dict[str, Any]:
    """Authenticate B's already-framed request without taking recovery locks."""

    support_root = Path(support_root)
    expected_record_path = support_root / f"orderly-handoff-record-{handoff_id}.json"
    if (
        not handoff_id
        or record_path != expected_record_path
        or not isinstance(record_digest, str)
        or not record_digest.startswith("sha256:")
        or _SHA256_RE.fullmatch(record_digest[7:]) is None
        or (
            predecessor_active_ref_digest is not None
            and (
                not isinstance(predecessor_active_ref_digest, str)
                or not predecessor_active_ref_digest.startswith("sha256:")
                or _SHA256_RE.fullmatch(predecessor_active_ref_digest[7:]) is None
            )
        )
        or not isinstance(old_owner, Mapping)
        or not {"pid", "birth_id"}.issubset(old_owner)
    ):
        raise ConflictError("pending adopter request binding is invalid")
    pointer = _pointer_snapshot(support_root)
    if pointer is None or (
        pointer.value.get("handoff_id") != handoff_id
        or pointer.value.get("record_path") != str(record_path)
    ):
        raise ConflictError("pending adopter request pointer is invalid")
    try:
        record = HandoffRecord(record_path).read()
    except Exception as exc:
        raise ConflictError("pending adopter handoff record is invalid") from exc
    if (
        record.get("state") != "COMMITTED_ORPHAN"
        or record.get("handoff_id") != handoff_id
        or record.get("record_digest") != record_digest
        or record.get("predecessor_active_ref_digest")
        != predecessor_active_ref_digest
        or record.get("old_owner") != dict(old_owner)
        or record.get("adopter") is not None
    ):
        raise ConflictError("pending adopter handoff record binding is invalid")
    return record


def _pointer_matches_resolution(
    pointer: _OwnerJSON, resolution: Mapping[str, Any]
) -> bool:
    return (
        pointer.path == Path(str(resolution["successor_request_pointer_path"]))
        and _pointer_identity_matches_resolution(pointer, resolution)
    )


def _pointer_identity_matches_resolution(
    pointer: _OwnerJSON, resolution: Mapping[str, Any]
) -> bool:
    return (
        pointer.file_sha256 == resolution["successor_request_pointer_sha256"]
        and len(pointer.raw) == resolution["successor_request_pointer_byte_length"]
        and pointer.device == resolution["successor_request_pointer_device"]
        and pointer.inode == resolution["successor_request_pointer_inode"]
        and pointer.mode == resolution["successor_request_pointer_mode"]
        and pointer.uid == resolution["successor_request_pointer_uid"]
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _pointer_quarantine_path(
    support_root: Path, resolution: Mapping[str, Any]
) -> Path:
    return Path(str(resolution["successor_request_quarantine_path"]))


def _atomic_rename_noreplace(source_path: Path, destination_path: Path) -> None:
    """Atomically move custody without replacing a concurrently-created target."""

    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(source_path)
    destination = os.fsencode(destination_path)
    if hasattr(libc, "renameatx_np"):
        # Darwin RENAME_EXCL: fail if the destination exists.
        result = libc.renameatx_np(-2, source, -2, destination, 0x00000004)
    elif hasattr(libc, "renameat2"):
        # Linux RENAME_NOREPLACE.
        result = libc.renameat2(-100, source, -100, destination, 0x1)
    else:  # pragma: no cover - supported hosts expose one primitive
        raise ConflictError("atomic no-replace pointer quarantine is unsupported")
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ConflictError("successor request pointer quarantine already exists")
        raise ConflictError("successor request pointer quarantine move failed") from OSError(
            error, os.strerror(error)
        )


def _rename_pointer_to_quarantine(pointer_path: Path, quarantine_path: Path) -> None:
    _atomic_rename_noreplace(pointer_path, quarantine_path)


def _restore_quarantined_replacement(
    pointer_path: Path, quarantine_path: Path
) -> None:
    """Restore without replacing anything which appeared at the source name."""

    try:
        pointer_path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ConflictError("successor request pointer restoration is unavailable") from exc
    else:
        _fsync_directory(pointer_path.parent)
        return
    _atomic_rename_noreplace(quarantine_path, pointer_path)
    _fsync_directory(pointer_path.parent)


def _retire_exact_quarantine(
    support_root: Path,
    quarantine: _OwnerJSON,
    resolution: Mapping[str, Any],
    *,
    site: str,
) -> Path:
    """Atomically remove a public quarantine name without pathname unlink.

    The exact validated inode is moved with an atomic no-replace operation to
    a deterministic, journal-bound retained name.  A replacement installed at
    the source boundary is moved rather than destroyed, detected by the
    no-follow re-open, and restored when the public quarantine name is still
    absent.  Successful retirement retains the authorized inode as bounded
    audit material; one name exists per handoff and clearance site.
    """

    handoff_id = str(resolution["handoff_id"])
    retired = support_root / f".orderly-handoff-retired-{handoff_id}-{site}.json"
    if retired.exists() or retired.is_symlink():
        raise ConflictError("retired successor request pointer already exists")
    _atomic_rename_noreplace(quarantine.path, retired)
    _fsync_directory(support_root)
    moved = _owner_json(retired, "retired orderly handoff request pointer")
    if (
        moved.signature[1:] != quarantine.signature[1:]
        or moved.raw != quarantine.raw
        or not _pointer_identity_matches_resolution(moved, resolution)
    ):
        try:
            quarantine.path.lstat()
        except FileNotFoundError:
            _atomic_rename_noreplace(retired, quarantine.path)
            _fsync_directory(support_root)
        except OSError:
            pass
        raise ConflictError("quarantined successor request pointer changed at retirement")
    return retired


def _validate_retired_evidence(
    support_root: Path, resolution: Mapping[str, Any]
) -> tuple[_OwnerJSON, ...]:
    """Validate every retained custody checkpoint for this resolution.

    A crash may occur after the atomic custody rename and before the moved
    inode is re-opened.  Replays therefore authenticate retained material
    before treating a missing public/quarantine name as completed clearance.
    """

    handoff_id = str(resolution["handoff_id"])
    observed = []
    for site in ("dual-name", "clearance"):
        path = support_root / f".orderly-handoff-retired-{handoff_id}-{site}.json"
        retained = _optional_owner_json(
            path, "retired orderly handoff request pointer"
        )
        if retained is None:
            continue
        if not _pointer_identity_matches_resolution(retained, resolution):
            raise ConflictError("retired successor request pointer custody changed")
        observed.append(retained)
    return tuple(observed)


def _remove_exact_quarantine(
    support_root: Path,
    quarantine_path: Path,
    resolution: Mapping[str, Any],
    *,
    expected_raw: bytes | None,
) -> None:
    quarantined = _owner_json(
        quarantine_path, "quarantined orderly handoff request pointer"
    )
    if not _pointer_identity_matches_resolution(quarantined, resolution) or (
        expected_raw is not None and quarantined.raw != expected_raw
    ):
        _restore_quarantined_replacement(
            support_root / _REQUEST_NAME, quarantine_path
        )
        raise ConflictError("quarantined successor request pointer custody changed")
    try:
        (support_root / _REQUEST_NAME).lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ConflictError("successor request pointer clearance is unavailable") from exc
    else:
        raise ConflictError("successor request pointer was replaced during clearance")
    # The source name is now absent and the exact pinned inode is held under a
    # private same-directory name.  Persist the custody move before deleting it.
    _fsync_directory(support_root)
    final = _owner_json(
        quarantine_path, "quarantined orderly handoff request pointer"
    )
    if final.signature != quarantined.signature or final.raw != quarantined.raw:
        _restore_quarantined_replacement(
            support_root / _REQUEST_NAME, quarantine_path
        )
        raise ConflictError("quarantined successor request pointer changed")
    _retire_exact_quarantine(
        support_root, final, resolution, site="clearance"
    )


def _clear_pointer(
    support_root: Path,
    resolution: Mapping[str, Any],
    *,
    expected_raw: bytes | None,
    absence_allowed: bool,
) -> None:
    pointer_path = support_root / _REQUEST_NAME
    quarantine_path = _pointer_quarantine_path(support_root, resolution)
    _validate_retired_evidence(support_root, resolution)
    current = _pointer_snapshot(support_root)
    if current is None:
        quarantine = _optional_owner_json(
            quarantine_path, "quarantined orderly handoff request pointer"
        )
        if quarantine is not None:
            _remove_exact_quarantine(
                support_root,
                quarantine_path,
                resolution,
                expected_raw=expected_raw,
            )
            return
        if absence_allowed:
            return
        raise ConflictError("successor request pointer disappeared before clearance")
    if quarantine_path.exists() or quarantine_path.is_symlink():
        raise ConflictError("successor request pointer quarantine is ambiguous")
    if not _pointer_matches_resolution(current, resolution) or (
        expected_raw is not None and current.raw != expected_raw
    ):
        raise ConflictError("successor request pointer exact-byte custody changed")
    # The no-follow re-open pins the exact inode while the source name is moved.
    immediate = _owner_json(pointer_path, "orderly handoff request pointer")
    if (
        immediate.signature != current.signature
        or immediate.raw != current.raw
        or not _pointer_matches_resolution(immediate, resolution)
    ):
        raise ConflictError("successor request pointer changed before clearance")
    _rename_pointer_to_quarantine(pointer_path, quarantine_path)
    _remove_exact_quarantine(
        support_root,
        quarantine_path,
        resolution,
        expected_raw=current.raw,
    )


def _resolution_snapshot(
    support_root: Path, handoff_id: str
) -> tuple[_OwnerJSON, dict[str, Any]] | None:
    path = support_root / f"{_RESOLUTION_PREFIX}{handoff_id}{_RESOLUTION_SUFFIX}"
    snapshot = _optional_owner_json(path, "handoff predecessor resolution")
    if snapshot is None:
        return None
    return snapshot, _validate_resolution(support_root, snapshot)


def resolve_aborted_predecessor(
    support_root: Path,
    *,
    handoff_record: HandoffRecord,
    aborted: dict[str, object],
) -> dict[str, object] | None:
    """Archive B's exact active reference and clear C's exact request pointer."""

    support_root = Path(support_root)
    predecessor_digest = aborted.get("predecessor_active_ref_digest")
    if predecessor_digest is None:
        return None
    handoff_id = str(aborted.get("handoff_id") or "")
    active_path = support_root / _ACTIVE_NAME
    archived_path = (
        support_root / f"orderly-handoff-predecessor-active-{handoff_id}.json"
    )
    resolution_path = (
        support_root / f"{_RESOLUTION_PREFIX}{handoff_id}{_RESOLUTION_SUFFIX}"
    )
    aborted_current = handoff_record.read()
    if (
        aborted_current.get("state") != "ABORTED"
        or aborted_current.get("record_digest") != aborted.get("record_digest")
        or aborted_current.get("cleanup_receipt_digest")
        != aborted.get("cleanup_receipt_digest")
        or aborted_current.get("predecessor_active_ref_digest") != predecessor_digest
    ):
        raise ConflictError("handoff aborted successor tombstone changed")

    resolution_entry = _resolution_snapshot(support_root, handoff_id)
    resolution = resolution_entry[1] if resolution_entry is not None else None
    pointer = _pointer_snapshot(support_root)
    if pointer is not None and (
        pointer.value.get("handoff_id") != handoff_id
        or pointer.value.get("record_path") != str(handoff_record.path)
    ):
        raise ConflictError("successor request pointer does not match aborted handoff")
    if resolution is None and pointer is None:
        raise ConflictError("successor request pointer is unavailable")
    if resolution is not None and pointer is not None and not _pointer_matches_resolution(
        pointer, resolution
    ):
        raise ConflictError("successor request pointer changed during recovery")
    if resolution is not None and resolution["state"] == "PREPARED" and pointer is None:
        raise ConflictError("prepared predecessor resolution lost its request pointer")

    active = _optional_owner_json(
        active_path, "handoff predecessor active reference"
    )
    archived = _optional_owner_json(
        archived_path, "archived handoff predecessor active reference"
    )
    if resolution is None and active is None:
        raise ConflictError("handoff predecessor active reference is unavailable")
    expected_reference = active.value if active is not None else (
        archived.value if archived is not None else None
    )
    expected_snapshot = active if active is not None else archived
    if expected_reference is None or expected_snapshot is None:
        raise ConflictError("handoff predecessor custody is unavailable")
    if (
        expected_reference.get("reference_digest") != predecessor_digest
        or digest({
            key: item
            for key, item in expected_reference.items()
            if key != "reference_digest"
        })
        != predecessor_digest
    ):
        raise ConflictError("handoff predecessor active reference changed")
    predecessor_record_path = Path(str(expected_reference.get("record_path")))
    if predecessor_record_path.parent != support_root:
        raise ConflictError("handoff predecessor tombstone path changed")
    predecessor_record = HandoffRecord(predecessor_record_path).read()
    if (
        predecessor_record.get("state") != "ADOPTED"
        or predecessor_record.get("record_digest")
        != expected_reference.get("record_digest")
    ):
        raise ConflictError("handoff predecessor tombstone changed")
    expected_file_sha = expected_snapshot.file_sha256
    if resolution is None:
        assert pointer is not None
        resolution = {
            "version": 1,
            "state": "PREPARED",
            "handoff_id": handoff_id,
            "aborted_record_path": str(handoff_record.path),
            "aborted_record_digest": aborted["record_digest"],
            "cleanup_receipt_digest": aborted["cleanup_receipt_digest"],
            "predecessor_active_ref_digest": predecessor_digest,
            "predecessor_record_path": str(expected_reference["record_path"]),
            "predecessor_record_digest": expected_reference["record_digest"],
            "archived_active_reference_path": str(archived_path),
            "active_reference_file_sha256": expected_file_sha,
            "active_reference_archived": False,
            "successor_request_pointer_path": str(pointer.path),
            "successor_request_pointer_sha256": pointer.file_sha256,
            "successor_request_pointer_byte_length": len(pointer.raw),
            "successor_request_pointer_device": pointer.device,
            "successor_request_pointer_inode": pointer.inode,
            "successor_request_pointer_mode": pointer.mode,
            "successor_request_pointer_uid": pointer.uid,
            "successor_request_quarantine_path": str(
                support_root
                / f"{_QUARANTINE_PREFIX}{handoff_id}{_QUARANTINE_SUFFIX}"
            ),
        }
        resolution["resolution_digest"] = digest(resolution)
        atomic_json_write(resolution_path, resolution)
    elif (
        resolution.get("aborted_record_path") != str(handoff_record.path)
        or resolution.get("aborted_record_digest") != aborted.get("record_digest")
        or resolution.get("cleanup_receipt_digest")
        != aborted.get("cleanup_receipt_digest")
        or resolution.get("predecessor_active_ref_digest") != predecessor_digest
        or resolution.get("predecessor_record_path")
        != str(expected_reference["record_path"])
        or resolution.get("predecessor_record_digest")
        != expected_reference["record_digest"]
        or resolution.get("active_reference_file_sha256") != expected_file_sha
    ):
        raise ConflictError("handoff predecessor resolution changed")

    if resolution["state"] == "COMPLETE":
        if active is not None or archived is None:
            raise ConflictError("completed predecessor resolution custody changed")
        _clear_pointer(
            support_root,
            resolution,
            expected_raw=pointer.raw if pointer is not None else None,
            absence_allowed=True,
        )
        return dict(resolution)

    assert pointer is not None
    if not _pointer_matches_resolution(
        _owner_json(pointer.path, "orderly handoff request pointer"),
        resolution,
    ):
        raise ConflictError("successor request pointer changed before archive")
    if active is not None:
        if archived is not None:
            raise ConflictError("handoff predecessor active/archive custody is ambiguous")
        current_active = _owner_json(
            active_path, "handoff predecessor active reference"
        )
        if (
            current_active.signature != active.signature
            or current_active.raw != active.raw
        ):
            raise ConflictError("handoff predecessor active reference changed")
        os.rename(active_path, archived_path)
    elif archived is None or archived.raw != expected_snapshot.raw:
        raise ConflictError("handoff predecessor archive proof is unavailable")
    _fsync_directory(support_root)
    completed = {
        **{key: item for key, item in resolution.items() if key != "resolution_digest"},
        "state": "COMPLETE",
        "active_reference_archived": True,
    }
    completed["resolution_digest"] = digest(completed)
    atomic_json_write(resolution_path, completed)
    _clear_pointer(
        support_root,
        completed,
        expected_raw=pointer.raw,
        absence_allowed=False,
    )
    return completed


@contextmanager
def _owner_mutex(path: Path) -> Iterator[None]:
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        try:
            descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            descriptor = os.open(path, flags)
    except OSError as exc:
        raise ConflictError(f"Runtime recovery mutex is unavailable: {path.name}") from exc
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise ConflictError(f"Runtime recovery mutex is invalid: {path.name}")
        if fcntl is None:
            raise ConflictError("Runtime recovery mutex is unsupported")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)


def _scan_signature(
    journals: list[tuple[_OwnerJSON, dict[str, Any]]],
    pointer: _OwnerJSON | None,
    quarantines: list[tuple[_OwnerJSON, dict[str, Any]]],
    retired: list[tuple[_OwnerJSON, dict[str, Any], str]],
) -> tuple[object, ...]:
    return (
        tuple(
            (
                snapshot.signature,
                snapshot.raw,
                value["state"],
                value["resolution_digest"],
            )
            for snapshot, value in journals
        ),
        None if pointer is None else (pointer.signature, pointer.raw),
        tuple(
            (snapshot.signature, snapshot.raw, value["resolution_digest"])
            for snapshot, value in quarantines
        ),
        tuple(
            (
                snapshot.signature,
                snapshot.raw,
                value["resolution_digest"],
                site,
            )
            for snapshot, value, site in retired
        ),
    )


def _recover_locked(
    support_root: Path,
    baseline: tuple[object, ...],
) -> dict[str, object] | None:
    journals = _scan_resolutions(support_root)
    pointer = _pointer_snapshot(support_root)
    quarantines = _scan_quarantines(support_root, journals)
    retired = _scan_retired(support_root, journals)
    if _scan_signature(journals, pointer, quarantines, retired) != baseline:
        raise ConflictError("handoff recovery authority changed before lock acquisition")
    prepared = [value for _, value in journals if value["state"] == "PREPARED"]
    if pointer is None:
        if prepared:
            raise ConflictError("prepared predecessor resolution lost its request pointer")
        if quarantines:
            _snapshot, resolution = quarantines[0]
            _clear_pointer(
                support_root,
                resolution,
                expected_raw=None,
                absence_allowed=True,
            )
            return dict(resolution)
        for _snapshot, resolution in journals:
            if resolution["state"] == "COMPLETE":
                _validate_retired_evidence(support_root, resolution)
        return None
    if quarantines:
        quarantine, resolution = quarantines[0]
        if (
            pointer.device != quarantine.device
            or pointer.inode != quarantine.inode
            or pointer.raw != quarantine.raw
            or pointer.mode != quarantine.mode
            or pointer.uid != quarantine.uid
        ):
            raise ConflictError("public and quarantined handoff pointers are ambiguous")
        # A crash after restoration's no-replace hard link and before removal
        # leaves both names on one exact inode.  Finish only that proven
        # checkpoint.  A swapped pointer remains public and startup stays
        # closed; an exact pinned inode continues through ordinary replay.
        if not _pointer_identity_matches_resolution(pointer, resolution):
            raise ConflictError("restored alternate handoff pointer requires audit")
        _retire_exact_quarantine(
            support_root, quarantine, resolution, site="dual-name"
        )
    handoff_id = str(pointer.value["handoff_id"])
    matching = [value for _, value in journals if value["handoff_id"] == handoff_id]
    if len(matching) > 1 or (
        prepared and not matching
    ):
        raise ConflictError("predecessor resolution journal selection is ambiguous")
    record = HandoffRecord(Path(str(pointer.value["record_path"])))
    try:
        aborted = record.read()
    except Exception as exc:
        raise ConflictError("handoff successor tombstone is invalid") from exc
    if (
        aborted.get("state") != "ABORTED"
        or aborted.get("handoff_id") != handoff_id
        or aborted.get("predecessor_active_ref_digest") is None
    ):
        if matching:
            raise ConflictError("predecessor resolution journal has no valid successor")
        return None
    return resolve_aborted_predecessor(
        support_root, handoff_record=record, aborted=aborted
    )


def recover_aborted_predecessor_resolution(
    support_root: Path,
    *,
    bootstrap_lock_held: bool = False,
) -> dict[str, object] | None:
    """Replay one unambiguous journal under bootstrap→coordinator lock order."""

    support_root = Path(support_root)
    try:
        observed = support_root.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ConflictError("Runtime support root is unavailable") from exc
    journal_paths = _resolution_paths(support_root)
    quarantine_paths = _quarantine_paths(support_root)
    retired_paths = _retired_paths(support_root)
    try:
        (support_root / _REQUEST_NAME).lstat()
        pointer_present = True
    except FileNotFoundError:
        pointer_present = False
    except OSError as exc:
        raise ConflictError("orderly handoff request pointer is unavailable") from exc
    if (
        not journal_paths
        and not pointer_present
        and not quarantine_paths
        and not retired_paths
    ):
        return None
    if (
        support_root.is_symlink()
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise ConflictError("Runtime support root is invalid")
    journals = _scan_resolutions(support_root)
    pointer = _pointer_snapshot(support_root)
    quarantines = _scan_quarantines(support_root, journals)
    retired = _scan_retired(support_root, journals)
    if not journals and pointer is None and not quarantines and not retired:
        return None
    baseline = _scan_signature(journals, pointer, quarantines, retired)

    def under_coordinator() -> dict[str, object] | None:
        with _owner_mutex(support_root / "orderly-handoff-coordinator.lock"):
            return _recover_locked(support_root, baseline)

    if bootstrap_lock_held:
        return under_coordinator()
    with _owner_mutex(support_root / "bootstrap.lock"):
        return under_coordinator()


__all__ = [
    "recover_aborted_predecessor_resolution",
    "resolve_aborted_predecessor",
    "validate_pending_adopter_request",
]
