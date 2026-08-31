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


__all__ = ["CapacityPlan", "CapacityReservation", "StorageDomain", "capture_write_path", "revalidate_write_path"]
