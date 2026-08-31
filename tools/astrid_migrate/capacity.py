"""Fail-closed storage-domain capacity reservations for lifecycle operations.

The lock is keyed by the device/filesystem identity, rather than by the
requested destination directory.  This matters when two destinations are
siblings on one volume: they consume the same free-byte pool.  Directory file
descriptors are retained while a reservation is held, so free-space checks do
not follow a path that an attacker can swap for a symlink.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Iterable, Mapping

from .migrator import MigrationError


def _absolute_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _has_symlink_component(path: str | Path) -> bool:
    path = _absolute_path(path)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            if current.is_symlink():
                return True
        except OSError:
            raise MigrationError(f"capacity path cannot be inspected safely: {path}")
    return False


def _existing_directory(path: Path) -> Path:
    """Find an existing directory without traversing a symlink component."""
    path = _absolute_path(path)
    if _has_symlink_component(path):
        raise MigrationError(f"capacity path contains a symlink component: {path}")
    candidate = path
    if not candidate.exists():
        candidate = candidate.parent
        while not candidate.exists():
            if candidate == candidate.parent:
                raise MigrationError(f"capacity path has no existing parent: {path}")
            candidate = candidate.parent
    if not candidate.is_dir() or candidate.is_symlink():
        raise MigrationError(f"capacity probe is not an ordinary directory: {candidate}")
    # O_NOFOLLOW makes the identity check below stable if a parent is swapped
    # after the lexical check.  Keep only a short-lived descriptor here; the
    # reservation opens and verifies its own probe descriptor again.
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = _open_directory_chain(candidate)
    except OSError as exc:
        raise MigrationError(f"capacity probe cannot open safely: {candidate}") from exc
    try:
        actual = os.fstat(fd)
        if actual.st_dev != os.stat(candidate, follow_symlinks=False).st_dev:
            raise MigrationError(f"capacity probe changed during inspection: {candidate}")
    finally:
        os.close(fd)
    return candidate


def _open_directory_chain(path: Path) -> int:
    """Open each component with ``openat(..., O_NOFOLLOW)``.

    Checking ``O_NOFOLLOW`` only on the final component still permits a
    concurrent parent-directory swap to redirect the lookup.  Walking from
    the anchor makes every component part of the identity fence.
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


class _ActivationIdentity(dict):
    """Process-local activation identity that owns its retained parent FD."""

    __slots__ = ("_retained_parent_fd",)

    def __init__(self, value: Mapping[str, Any], parent_fd: int):
        super().__init__(value)
        self._retained_parent_fd = parent_fd

    def get(self, key, default=None):
        if key == "_parent_fd":
            return self._retained_parent_fd
        return super().get(key, default)

    def __getitem__(self, key):
        if key == "_parent_fd":
            return self._retained_parent_fd
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        if key == "_parent_fd":
            self._retained_parent_fd = value
            return
        super().__setitem__(key, value)

    def __del__(self):  # pragma: no cover - exercised by interpreter cleanup
        fd = getattr(self, "_retained_parent_fd", None)
        if fd is not None:
            try:
                os.close(int(fd))
            except OSError:
                pass


def capture_write_path(path: str | Path) -> dict[str, Any]:
    """Capture the ordinary parent identity for a new material write.

    The lifecycle writers create a temporary directory below ``path.parent``
    and rename it into ``path``.  A lexical symlink check alone is not enough:
    an attacker can rename the checked parent and replace it with another
    directory (or mount/device) between the check and the write.  Opening the
    complete parent chain with ``O_NOFOLLOW`` gives us the identity that must
    still be present immediately before the write seam.
    """
    target = _absolute_path(path)
    if _has_symlink_component(target) or os.path.lexists(str(target)):
        raise MigrationError(f"capacity write target is not a fresh ordinary path: {target}")
    target_parent = target.parent
    parent = target_parent
    while not os.path.lexists(str(parent)):
        if parent == parent.parent:
            raise MigrationError(f"capacity write path has no existing parent: {target}")
        parent = parent.parent
    try:
        parent_fd = _open_directory_chain(parent)
    except OSError as exc:
        raise MigrationError(f"capacity write parent cannot be opened safely: {parent}") from exc
    try:
        identity = os.fstat(parent_fd)
    except OSError as exc:
        raise MigrationError(f"capacity write parent identity unavailable: {parent}") from exc
    finally:
        os.close(parent_fd)
    if not stat.S_ISDIR(identity.st_mode):
        raise MigrationError(f"capacity write parent is not an ordinary directory: {parent}")
    return {
        "path": str(target),
        "parent": str(parent),
        "target_parent": str(target_parent),
        "parent_was_missing": target_parent != parent,
        "st_dev": int(identity.st_dev),
        "st_ino": int(identity.st_ino),
        "st_mode": int(identity.st_mode),
    }


def revalidate_write_path(path: str | Path, identity: Mapping[str, Any]) -> None:
    """Fail closed if a captured new-write path or its parent changed."""
    target = _absolute_path(path)
    target_parent = target.parent
    if identity.get("path") != str(target) or identity.get("target_parent") != str(target_parent):
        raise MigrationError(f"capacity write path identity changed: {target}")
    if _has_symlink_component(target) or os.path.lexists(str(target)):
        raise MigrationError(f"capacity write target changed before material write: {target}")
    # ``restore_backup`` is allowed to create a missing destination parent.
    # Preserve that behavior, but require the same missing-path shape at the
    # final seam; an attacker-created replacement directory must not be
    # mistaken for the parent that was observed during capture.
    if bool(identity.get("parent_was_missing")):
        if os.path.lexists(str(target_parent)):
            raise MigrationError(f"capacity write parent appeared before material write: {target_parent}")
    elif not os.path.lexists(str(target_parent)):
        raise MigrationError(f"capacity write parent disappeared before material write: {target_parent}")
    parent = Path(str(identity["parent"]))
    try:
        parent_fd = _open_directory_chain(parent)
    except OSError as exc:
        raise MigrationError(f"capacity write parent changed before material write: {parent}") from exc
    try:
        current = os.fstat(parent_fd)
    except OSError as exc:
        raise MigrationError(f"capacity write parent identity unavailable: {parent}") from exc
    finally:
        os.close(parent_fd)
    if not stat.S_ISDIR(current.st_mode) or any(
        int(getattr(current, key)) != int(identity[key]) for key in ("st_dev", "st_ino", "st_mode")
    ):
        raise MigrationError(f"capacity write parent identity changed before material write: {parent}")


def capture_activation_path(path: str | Path) -> dict[str, Any]:
    """Capture the lexical identity of an activation target and its parent.

    Activation replaces an existing authority directory, unlike a restore
    write which requires a fresh target.  The target is therefore recorded as
    either absent or as an ordinary directory with its ``st_dev``, ``st_ino``
    and ``st_mode``.  The nearest existing parent is captured through a
    complete ``O_NOFOLLOW`` chain so an interrupted/replayed activation cannot
    be redirected by replacing a parent with a symlink or another directory.
    """
    target = _absolute_path(path)
    if _has_symlink_component(target):
        raise MigrationError(f"activation path contains a symlink component: {target}")
    target_parent = target.parent
    parent = target_parent
    while not os.path.lexists(str(parent)):
        if parent == parent.parent:
            raise MigrationError(f"activation path has no existing parent: {target}")
        parent = parent.parent
    if parent.is_symlink() or not parent.is_dir():
        raise MigrationError(f"activation parent is not an ordinary directory: {parent}")
    # Keep this descriptor open.  Re-opening ``parent`` after a lexical
    # identity check reintroduces the exact rename/symlink TOCTOU this fence
    # is intended to close.  Callers hand the identity to the material
    # activation operation, which consumes the descriptor with *at(2)
    # operations and closes it when the boundary is complete.
    try:
        parent_fd = _open_directory_chain(parent)
        parent_identity = os.fstat(parent_fd)
    except OSError as exc:
        try:
            os.close(parent_fd)
        except (UnboundLocalError, OSError):
            pass
        raise MigrationError(f"activation parent cannot be opened safely: {parent}") from exc
    if not stat.S_ISDIR(parent_identity.st_mode):
        os.close(parent_fd)
        raise MigrationError(f"activation parent is not an ordinary directory: {parent}")
    record: dict[str, Any] = _ActivationIdentity({
        "path": str(target),
        "parent": str(parent),
        "target_parent": str(target_parent),
        "parent_was_missing": target_parent != parent,
        "target_absent": not os.path.lexists(str(target)),
        "parent_st_dev": int(parent_identity.st_dev),
        "parent_st_ino": int(parent_identity.st_ino),
        "parent_st_mode": int(parent_identity.st_mode),
    }, parent_fd)
    if record["target_absent"]:
        return record
    try:
        # The target is normally a direct child of the pinned parent.  Open
        # it relative to that descriptor so a concurrent parent swap cannot
        # redirect the identity observation.
        if target.parent == parent:
            target_fd = os.open(
                target.name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
        else:
            target_fd = _open_directory_chain(target)
        target_identity = os.fstat(target_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise MigrationError(f"activation target cannot be opened safely: {target}") from exc
    finally:
        try:
            os.close(target_fd)
        except (UnboundLocalError, OSError):
            pass
    if not stat.S_ISDIR(target_identity.st_mode):
        os.close(parent_fd)
        raise MigrationError(f"activation target is not an ordinary directory: {target}")
    record.update(
        target_st_dev=int(target_identity.st_dev),
        target_st_ino=int(target_identity.st_ino),
        target_st_mode=int(target_identity.st_mode),
    )
    return record


def revalidate_activation_path(path: str | Path, identity: Mapping[str, Any]) -> None:
    """Revalidate a captured activation path immediately before material use."""
    target = _absolute_path(path)
    target_parent = target.parent
    if identity.get("path") != str(target) or identity.get("target_parent") != str(target_parent):
        raise MigrationError(f"activation path identity changed: {target}")
    if _has_symlink_component(target):
        raise MigrationError(f"activation path contains a symlink component: {target}")
    if bool(identity.get("parent_was_missing")):
        if os.path.lexists(str(target_parent)):
            raise MigrationError(f"activation parent appeared before material write: {target_parent}")
    elif not os.path.lexists(str(target_parent)):
        raise MigrationError(f"activation parent disappeared before material write: {target_parent}")
    parent = Path(str(identity["parent"]))
    parent_fd = identity.get("_parent_fd")
    try:
        if parent_fd is None:
            # A material operation must never fall back to reopening a path
            # after validation.  Older serialized identities are therefore
            # intentionally rejected; the caller must capture a fresh one.
            raise MigrationError("activation boundary has no retained parent descriptor")
        current_parent = os.fstat(int(parent_fd))
    except MigrationError:
        raise
    except OSError as exc:
        raise MigrationError(f"activation parent changed before material write: {parent}") from exc
    if not stat.S_ISDIR(current_parent.st_mode) or any(
        int(getattr(current_parent, key)) != int(identity[f"parent_{key}"])
        for key in ("st_dev", "st_ino", "st_mode")
    ):
        raise MigrationError(f"activation parent identity changed before material write: {parent}")
    # The descriptor proves which inode the *at(2) operation will use.  Also
    # compare the lexical name so a same-type replacement is rejected before
    # publication (a symlink check alone would miss that case).
    try:
        named_parent = os.stat(target_parent, follow_symlinks=False)
    except OSError as exc:
        raise MigrationError(f"activation parent changed before material write: {target_parent}") from exc
    if not stat.S_ISDIR(named_parent.st_mode) or any(
        int(getattr(named_parent, key)) != int(identity[f"parent_{key}"])
        for key in ("st_dev", "st_ino", "st_mode")
    ):
        raise MigrationError(f"activation parent identity changed before material write: {target_parent}")
    # For the ordinary (and material activation) shape, inspect the target
    # relative to the retained parent FD.  This observation and the eventual
    # rename therefore address the same directory inode.
    if target.parent == parent:
        try:
            os.stat(target.name, dir_fd=int(parent_fd), follow_symlinks=False)
            target_absent = False
        except FileNotFoundError:
            target_absent = True
        except OSError as exc:
            raise MigrationError(f"activation target changed before material write: {target}") from exc
    else:
        target_absent = not os.path.lexists(str(target))
    if target_absent != bool(identity.get("target_absent")):
        raise MigrationError(f"activation target presence changed before material write: {target}")
    if target_absent:
        return
    try:
        if target.parent == parent:
            target_fd = os.open(
                target.name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=int(parent_fd),
            )
        else:
            target_fd = _open_directory_chain(target)
        current_target = os.fstat(target_fd)
    except OSError as exc:
        raise MigrationError(f"activation target changed before material write: {target}") from exc
    finally:
        try:
            os.close(target_fd)
        except (UnboundLocalError, OSError):
            pass
    if not stat.S_ISDIR(current_target.st_mode) or any(
        int(getattr(current_target, key)) != int(identity[f"target_{key}"])
        for key in ("st_dev", "st_ino", "st_mode")
    ):
        raise MigrationError(f"activation target identity changed before material write: {target}")


def revalidate_activation_parent(path: str | Path, identity: Mapping[str, Any]) -> int:
    """Validate and return the retained parent FD after target publication.

    The target inode is intentionally *not* checked here: a successful
    activation has replaced it.  The parent identity still must match both
    lexically and by descriptor, otherwise a subsequent service reopen could
    follow an attacker-provided symlinked parent.
    """
    target = _absolute_path(path)
    target_parent = target.parent
    if identity.get("path") != str(target) or identity.get("target_parent") != str(target_parent):
        raise MigrationError(f"activation path identity changed: {target}")
    parent = Path(str(identity["parent"]))
    if bool(identity.get("parent_was_missing")) or parent != target_parent:
        raise MigrationError(f"activation parent shape changed before publication: {target}")
    if _has_symlink_component(target_parent) or not os.path.lexists(str(target_parent)):
        raise MigrationError(f"activation parent changed before publication: {target_parent}")
    parent_fd = identity.get("_parent_fd")
    if parent_fd is None:
        raise MigrationError("activation boundary has no retained parent descriptor")
    try:
        current = os.fstat(int(parent_fd))
    except OSError as exc:
        raise MigrationError(f"activation parent descriptor is unavailable: {parent}") from exc
    if not stat.S_ISDIR(current.st_mode) or any(
        int(getattr(current, key)) != int(identity[f"parent_{key}"])
        for key in ("st_dev", "st_ino", "st_mode")
    ):
        raise MigrationError(f"activation parent identity changed before publication: {parent}")
    try:
        named_parent = os.stat(target_parent, follow_symlinks=False)
    except OSError as exc:
        raise MigrationError(f"activation parent changed before publication: {target_parent}") from exc
    if not stat.S_ISDIR(named_parent.st_mode) or any(
        int(getattr(named_parent, key)) != int(identity[f"parent_{key}"])
        for key in ("st_dev", "st_ino", "st_mode")
    ):
        raise MigrationError(f"activation parent identity changed before publication: {target_parent}")
    return int(parent_fd)


def close_activation_path(identity: Mapping[str, Any] | None) -> None:
    """Close process-local descriptors carried by an activation identity."""
    if not isinstance(identity, Mapping):
        return
    fd = identity.get("_parent_fd")
    if fd is None:
        return
    try:
        os.close(int(fd))
    except OSError:
        pass
    # Most callers pass a dict; clear it to make accidental reuse fail closed.
    try:
        identity["_parent_fd"] = None  # type: ignore[index]
    except (TypeError, AttributeError):
        pass


def _mount_identity(directory: Path, device: int) -> str:
    """Return a stable mount identity, including the mount boundary."""
    current = directory
    while current.parent != current:
        parent = current.parent
        try:
            if int(os.stat(parent, follow_symlinks=False).st_dev) != device:
                break
        except OSError:
            break
        current = parent
    try:
        statvfs = os.statvfs(directory)
        fsid = int(getattr(statvfs, "f_fsid", 0))
    except OSError as exc:
        raise MigrationError(f"capacity filesystem identity unavailable: {directory}") from exc
    return f"dev:{device}:fsid:{fsid}:mount:{current}"


@dataclass
class StorageDomain:
    key: str
    device: int
    mount: str
    probe_path: Path
    roots: dict[str, int] = field(default_factory=dict)
    required_bytes: int = 0
    lock_path: Path | None = None

    @classmethod
    def identify(cls, path: str | Path) -> "StorageDomain":
        probe = _existing_directory(_absolute_path(path))
        try:
            identity = os.stat(probe, follow_symlinks=False)
        except OSError as exc:
            raise MigrationError(f"capacity filesystem identity unavailable: {probe}") from exc
        device = int(identity.st_dev)
        mount = _mount_identity(probe, device)
        key = hashlib.sha256(mount.encode("utf-8")).hexdigest()
        return cls(key=key, device=device, mount=mount, probe_path=probe)

    def available_bytes(self, fd: int | None = None) -> int:
        try:
            value = os.fstatvfs(fd) if fd is not None else os.statvfs(self.probe_path)
            return int(value.f_bavail) * int(value.f_frsize or value.f_bsize)
        except OSError as exc:
            raise MigrationError(f"capacity free-space check failed: {self.probe_path}") from exc


@dataclass
class CapacityPlan:
    domains: dict[str, StorageDomain]
    margin_bytes: int

    @classmethod
    def from_allocations(cls, allocations: Iterable[tuple[str, str | Path, int]], *, margin_bytes: int = 0) -> "CapacityPlan":
        domains: dict[str, StorageDomain] = {}
        for label, path, amount in allocations:
            amount = int(amount)
            if amount < 0:
                raise MigrationError(f"capacity estimate for {label} is negative")
            domain = StorageDomain.identify(path)
            existing = domains.get(domain.key)
            if existing is None:
                domains[domain.key] = domain
                existing = domain
            existing.roots[str(label)] = existing.roots.get(str(label), 0) + amount
            existing.required_bytes += amount
        margin = int(margin_bytes)
        if margin < 0:
            raise MigrationError("capacity safety margin must not be negative")
        for domain in domains.values():
            # One margin per independent pool, not one margin per output path.
            domain.required_bytes += margin
        return cls(domains=domains, margin_bytes=margin)

    def receipt(self, *, packet: str, components: Mapping[str, int] | None = None) -> dict[str, Any]:
        records = []
        available_total = 0
        required_total = 0
        for key in sorted(self.domains):
            domain = self.domains[key]
            available = domain.available_bytes()
            available_total += available
            required_total += domain.required_bytes
            records.append({"domain_id": domain.key, "device": domain.device, "mount": domain.mount, "probe_path": str(domain.probe_path), "roots": dict(sorted(domain.roots.items())), "required_bytes": domain.required_bytes, "available_bytes": available, "reserved": available >= domain.required_bytes})
        return {"packet": packet, "domains": records, "required_bytes": required_total, "available_bytes": available_total, "reserved": all(item["reserved"] for item in records), "margin_bytes": self.margin_bytes, **(dict(components or {}))}


class CapacityReservation:
    """Acquire all domain locks in key order and recheck under those locks."""

    def __init__(self, domains: list[StorageDomain], handles: list[tuple[int, int]], reservation_id: str):
        self.domains = domains
        self.handles = handles
        self.reservation_id = reservation_id
        self.path = domains[0].lock_path if domains else None
        self.handle = handles[0][0] if handles else None

    @property
    def required_bytes(self) -> int:
        """Compatibility aggregate for the former single-domain lease."""
        return sum(domain.required_bytes for domain in self.domains)

    @classmethod
    def acquire(cls, *, plan: CapacityPlan | None = None, path: Path | None = None, reservation_id: str, required_bytes: int = 0, minimum_free_bytes: int = 0) -> "CapacityReservation":
        if plan is None:
            if path is None:
                raise MigrationError("capacity reservation requires a storage plan")
            domain = StorageDomain.identify(path)
            domain.required_bytes = int(required_bytes)
            plan = CapacityPlan({domain.key: domain}, 0)
        domains = [plan.domains[key] for key in sorted(plan.domains)]
        # Canonicalize only this private lock registry.  User roots remain
        # lexical and are rejected when they contain symlink components.
        lock_root = Path(tempfile.gettempdir()).resolve() / "banodoco-capacity-domains"
        if _has_symlink_component(lock_root):
            raise MigrationError("capacity lock registry contains a symlink component")
        lock_root.mkdir(parents=True, exist_ok=True)
        if _has_symlink_component(lock_root):
            raise MigrationError("capacity lock registry changed to a symlink")
        handles: list[tuple[int, int]] = []
        try:
            for domain in domains:
                lock_path = lock_root / f"{domain.key}.lock"
                domain.lock_path = lock_path
                flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                fd: int | None = None
                probe_fd: int | None = None
                try:
                    fd = os.open(str(lock_path), flags, 0o600)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except (BlockingIOError, OSError) as exc:
                        raise MigrationError("B12.1 capacity reservation is already held") from exc
                    try:
                        probe_fd = _open_directory_chain(domain.probe_path)
                    except OSError as exc:
                        raise MigrationError("capacity probe path changed or escaped during reservation") from exc
                    actual = os.fstat(probe_fd)
                    if int(actual.st_dev) != domain.device:
                        raise MigrationError("capacity storage domain changed during reservation")
                    # Do not append until both descriptors have been fully
                    # verified.  This local guard releases the just-acquired
                    # lock if probe opening/fstat fails, so an immediate
                    # retry cannot be blocked by a leaked descriptor.
                    handles.append((fd, probe_fd))
                    fd = None
                    probe_fd = None
                except Exception:
                    if probe_fd is not None:
                        try:
                            os.close(probe_fd)
                        except OSError:
                            pass
                    if fd is not None:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_UN)
                        finally:
                            os.close(fd)
                    raise
            reservation = cls(domains, handles, reservation_id)
            reservation.recheck(minimum_free_bytes=minimum_free_bytes or None)
            return reservation
        except Exception:
            # The current iteration's descriptors are cleaned in its local
            # guard; ``handles`` contains only completed pairs.
            for lock_fd, probe_fd in reversed(handles):
                try:
                    os.close(probe_fd)
                finally:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    os.close(lock_fd)
            raise

    def recheck(self, *, minimum_free_bytes: int | None = None) -> int:
        values = []
        for domain, (_, probe_fd) in zip(self.domains, self.handles):
            free = domain.available_bytes(probe_fd)
            required = domain.required_bytes
            if minimum_free_bytes is not None and len(self.domains) == 1:
                required = int(minimum_free_bytes)
            if free < required:
                raise MigrationError(f"B12.1 capacity reservation failed immediate recheck: free={free}, required={required}, domain={domain.key}")
            values.append(free)
        return min(values) if values else 0

    def release(self) -> None:
        if not self.handles:
            return
        handles, self.handles = self.handles, []
        for lock_fd, probe_fd in reversed(handles):
            try:
                os.close(probe_fd)
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
        self.handle = None

    def __del__(self):  # pragma: no cover - crash cleanup is exercised by OS
        try:
            self.release()
        except Exception:
            pass


__all__ = ["CapacityPlan", "CapacityReservation", "StorageDomain", "capture_write_path", "revalidate_write_path", "capture_activation_path", "revalidate_activation_path", "revalidate_activation_parent", "close_activation_path"]
