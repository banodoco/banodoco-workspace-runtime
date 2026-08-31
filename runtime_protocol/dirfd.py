"""Small descriptor-relative filesystem primitives used by lifecycle code.

The lifecycle protocol performs a lot of ``validate(path); write(path)`` work.
That shape is unsafe when an untrusted process can rename a parent between the
two operations.  These helpers retain the validated parent directory and do
all subsequent operations relative to that descriptor.  Paths are kept only
for human-readable receipts and for the lexical identity check; they are never
re-opened as the authority for a material write.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import time
import hashlib
import json
from typing import Any, Mapping

from .errors import ConflictError


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def absolute_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def has_symlink_component(value: str | Path) -> bool:
    path = absolute_path(value)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            if current.is_symlink():
                return True
        except OSError as exc:
            raise ConflictError(f"filesystem path cannot be inspected safely: {path}") from exc
    return False


def open_directory_chain(value: str | Path) -> int:
    """Open every lexical component with O_NOFOLLOW, retaining the leaf fd."""
    path = absolute_path(value)
    fd = os.open(path.anchor, _DIR_FLAGS)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


class PinnedParent(dict):
    """Mapping-compatible identity which owns a retained parent descriptor."""

    __slots__ = ("_parent_fd",)

    def __init__(self, value: Mapping[str, Any], parent_fd: int):
        super().__init__(value)
        self._parent_fd = parent_fd

    def get(self, key, default=None):
        if key == "_parent_fd":
            return self._parent_fd
        return super().get(key, default)

    def __getitem__(self, key):
        if key == "_parent_fd":
            return self._parent_fd
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        if key == "_parent_fd":
            self._parent_fd = value
        else:
            super().__setitem__(key, value)

    def __del__(self):  # pragma: no cover - interpreter cleanup
        fd = getattr(self, "_parent_fd", None)
        if fd is not None:
            try:
                os.close(int(fd))
            except OSError:
                pass


def close_pinned(identity: Mapping[str, Any] | None) -> None:
    if not isinstance(identity, Mapping):
        return
    fd = identity.get("_parent_fd")
    if fd is None:
        return
    try:
        os.close(int(fd))
    except OSError:
        pass
    try:
        identity["_parent_fd"] = None  # type: ignore[index]
    except (TypeError, AttributeError):
        pass


def _relative_parts(value: str | Path, *, allow_dot: bool = False) -> tuple[str, ...]:
    path = Path(value)
    if path.is_absolute():
        raise ConflictError("relative filesystem path must not be absolute")
    parts = tuple(path.parts)
    if not parts and not allow_dot:
        raise ConflictError("relative filesystem path is empty")
    if any(part in ("..", os.curdir) for part in parts):
        raise ConflictError("relative filesystem path escapes its pinned parent")
    return parts


def _leaf_name(value: str | Path) -> str:
    text = os.fspath(value)
    if not text or Path(text).name != text or text in (".", ".."):
        raise ConflictError("filesystem entry name must be one direct child")
    return text


def read_bytes_at(directory_fd: int, name: str | Path) -> bytes:
    """Read one regular file below a retained directory descriptor."""
    fd = os.open(_leaf_name(name), os.O_RDONLY | _NOFOLLOW, dir_fd=int(directory_fd))
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise ConflictError(f"filesystem entry is not a regular file: {name}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_json_at(directory_fd: int, name: str | Path) -> Any:
    """Decode JSON from a descriptor-relative regular file."""
    try:
        value = json.loads(read_bytes_at(directory_fd, name).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ConflictError(f"filesystem JSON artifact is invalid: {name}") from exc
    return value


def sha256_at(directory_fd: int, name: str | Path) -> tuple[str, int]:
    """Hash one descriptor-relative regular file and return digest and size."""
    fd = os.open(_leaf_name(name), os.O_RDONLY | _NOFOLLOW, dir_fd=int(directory_fd))
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise ConflictError(f"filesystem entry is not a regular file: {name}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest(), int(value.st_size)
    finally:
        os.close(fd)


def _nearest_existing(path: Path) -> tuple[Path, bool]:
    parent = path
    while not os.path.lexists(str(parent)):
        if parent == parent.parent:
            raise ConflictError(f"filesystem path has no existing parent: {path}")
        parent = parent.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ConflictError(f"filesystem path parent is not an ordinary directory: {parent}")
    return parent, parent != path


def capture_parent(path: str | Path, *, require_fresh_target: bool = False) -> PinnedParent:
    """Capture the nearest existing parent and retain its descriptor."""
    target = absolute_path(path)
    if has_symlink_component(target):
        raise ConflictError(f"filesystem path contains a symlink component: {target}")
    if require_fresh_target and os.path.lexists(str(target)):
        raise ConflictError(f"filesystem target must be fresh: {target}")
    parent, was_missing = _nearest_existing(target.parent)
    fd = open_directory_chain(parent)
    try:
        identity = os.fstat(fd)
    except Exception:
        os.close(fd)
        raise
    if not stat.S_ISDIR(identity.st_mode):
        os.close(fd)
        raise ConflictError(f"filesystem parent is not an ordinary directory: {parent}")
    return PinnedParent({
        "path": str(target),
        "parent": str(parent),
        "target_parent": str(target.parent),
        "parent_was_missing": bool(was_missing),
        "parent_st_dev": int(identity.st_dev),
        "parent_st_ino": int(identity.st_ino),
        "parent_st_mode": int(identity.st_mode),
    }, fd)


def pin_directory(path: str | Path) -> tuple[PinnedParent, int, os.stat_result]:
    """Retain a directory's parent and directory fd for verified source reads."""
    target = absolute_path(path)
    identity = capture_parent(target)
    parent_fd = int(identity.get("_parent_fd"))
    try:
        if target.parent == Path(str(identity["parent"])):
            root_fd = os.open(target.name, _DIR_FLAGS, dir_fd=parent_fd)
        else:
            # The path shape is unusual (missing ancestors), but capture_parent
            # has retained the nearest ancestor and O_NOFOLLOW remains in force
            # for every component.
            relative = target.relative_to(Path(str(identity["parent"])))
            root_fd = os.open(str(relative), _DIR_FLAGS, dir_fd=parent_fd)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            os.close(root_fd)
            raise ConflictError(f"filesystem target is not an ordinary directory: {target}")
        return identity, root_fd, root_stat
    except Exception:
        close_pinned(identity)
        raise


def _identity_tuple(value: os.stat_result) -> tuple[int, int, int]:
    return int(value.st_dev), int(value.st_ino), int(value.st_mode)


def validate_parent(path: str | Path, identity: Mapping[str, Any], *, allow_parent_appeared: bool = False) -> int:
    """Validate both retained and lexical parent identity; return retained fd."""
    target = absolute_path(path)
    if identity.get("path") != str(target) or identity.get("target_parent") != str(target.parent):
        raise ConflictError(f"filesystem path identity changed: {target}")
    if has_symlink_component(target):
        raise ConflictError(f"filesystem path contains a symlink component: {target}")
    parent_fd = identity.get("_parent_fd")
    if parent_fd is None:
        raise ConflictError(f"filesystem path has no retained parent descriptor: {target}")
    try:
        retained = os.fstat(int(parent_fd))
    except OSError as exc:
        raise ConflictError(f"filesystem parent descriptor is unavailable: {target.parent}") from exc
    expected_values = []
    for key in ("st_dev", "st_ino", "st_mode"):
        value = identity.get(f"parent_{key}")
        if value is None:
            value = identity.get(key)
        expected_values.append(int(value))
    expected = tuple(expected_values)
    if _identity_tuple(retained) != expected or not stat.S_ISDIR(retained.st_mode):
        raise ConflictError(f"filesystem retained parent identity changed: {target.parent}")
    # This catches an ordinary directory replacement as well as a symlink.
    if not bool(identity.get("parent_was_missing")):
        try:
            named = os.stat(target.parent, follow_symlinks=False)
        except OSError as exc:
            raise ConflictError(f"filesystem lexical parent changed: {target.parent}") from exc
        if _identity_tuple(named) != expected or not stat.S_ISDIR(named.st_mode):
            raise ConflictError(f"filesystem lexical parent identity changed: {target.parent}")
    if bool(identity.get("parent_was_missing")) and os.path.lexists(str(target.parent)) and not allow_parent_appeared:
        raise ConflictError(f"filesystem target parent appeared after capture: {target.parent}")
    if not bool(identity.get("parent_was_missing")) and not os.path.lexists(str(target.parent)):
        raise ConflictError(f"filesystem target parent disappeared after capture: {target.parent}")
    return int(parent_fd)


def validate_created_parent(path: str | Path, identity: Mapping[str, Any], final_parent_fd: int) -> int:
    """Validate a target whose missing parent chain was created below a pin.

    ``validate_parent`` intentionally rejects a newly appeared lexical parent
    unless explicitly allowed.  Writers that intentionally create that chain
    use this stricter variant: it permits the appearance only when the name
    resolves to the exact descriptor returned by ``ensure_parent_at``.
    """
    target = absolute_path(path)
    validate_parent(target, identity, allow_parent_appeared=True)
    if identity.get("parent_was_missing"):
        try:
            named = os.stat(target.parent, follow_symlinks=False)
            retained = os.fstat(int(final_parent_fd))
        except OSError as exc:
            raise ConflictError(f"filesystem created parent cannot be verified: {target.parent}") from exc
        if _identity_tuple(named) != _identity_tuple(retained) or not stat.S_ISDIR(named.st_mode):
            raise ConflictError(f"filesystem created parent identity changed: {target.parent}")
    else:
        validate_parent(target, identity)
    return int(final_parent_fd)


def mkdir_chain_at(parent_fd: int, relative: str | Path, mode: int = 0o700) -> int:
    """Create/open a relative directory chain below ``parent_fd``."""
    parts = _relative_parts(relative, allow_dot=True)
    current_fd = os.dup(parent_fd)
    try:
        for component in parts:
            try:
                os.mkdir(component, mode, dir_fd=current_fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, _DIR_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def ensure_parent_at(path: str | Path, identity: Mapping[str, Any]) -> tuple[int, str]:
    """Return the fd/name pair used for a target, creating missing components."""
    target = absolute_path(path)
    parent_fd = validate_parent(target, identity)
    parent = Path(str(identity["parent"]))
    if target.parent == parent:
        return parent_fd, target.name
    # A missing target parent is created only below the retained nearest
    # ancestor.  The lexical missing-shape check above prevents an attacker
    # from supplying a replacement before this operation.
    relative = target.parent.relative_to(parent)
    child_fd = mkdir_chain_at(parent_fd, relative)
    return child_fd, target.name


def ensure_directory(path: str | Path, *, mode: int = 0o700) -> PinnedParent:
    """Create a directory securely and return a retained identity for it."""
    target = absolute_path(path)
    identity = capture_parent(target)
    parent_fd, name = ensure_parent_at(target, identity)
    try:
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
        child_fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        child_stat = os.fstat(child_fd)
        if not stat.S_ISDIR(child_stat.st_mode):
            raise ConflictError(f"filesystem target is not an ordinary directory: {target}")
        os.fsync(parent_fd)
        # Keep the target descriptor as the retained parent for callers that
        # will write children.  Preserve the lexical identity fields for the
        # target itself.
        result = PinnedParent({
            "path": str(target),
            "parent": str(target.parent),
            "target_parent": str(target.parent),
            "parent_was_missing": False,
            "parent_st_dev": int(child_stat.st_dev),
            "parent_st_ino": int(child_stat.st_ino),
            "parent_st_mode": int(child_stat.st_mode),
        }, child_fd)
        close_pinned(identity)
        return result
    except Exception:
        try:
            if parent_fd != identity.get("_parent_fd"):
                os.close(parent_fd)
        finally:
            close_pinned(identity)
        raise
    finally:
        if parent_fd != identity.get("_parent_fd"):
            try:
                os.close(parent_fd)
            except OSError:
                pass


def mkdir_temp_at(parent_fd: int, prefix: str, *, mode: int = 0o700) -> tuple[str, int]:
    for attempt in range(100):
        name = f"{prefix}{os.getpid()}-{time.time_ns()}-{attempt}"
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            return name, os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        except Exception:
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    raise ConflictError("temporary filesystem directory could not be allocated")


def write_bytes_at(directory_fd: int, name: str, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically publish bytes as a direct child of a pinned directory."""
    name = _leaf_name(name)
    temp_name = f".{name}.{os.getpid()}-{time.time_ns()}.tmp"
    fd = -1
    try:
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, mode, dir_fd=directory_fd)
        view = memoryview(bytes(data))
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.rename(temp_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except OSError:
            pass
        raise


def copy_file_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str, *, replace: bool = False) -> None:
    _relative_parts(source_name)
    destination_name = _leaf_name(destination_name)
    source = os.open(source_name, os.O_RDONLY | _NOFOLLOW, dir_fd=source_fd)
    destination = -1
    try:
        source_stat = os.fstat(source)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ConflictError(f"filesystem source is not a regular file: {source_name}")
        flags = os.O_WRONLY | os.O_CREAT | (_NOFOLLOW if not replace else 0)
        if not replace:
            flags |= os.O_EXCL
        destination = os.open(destination_name, flags, stat.S_IRUSR | stat.S_IWUSR, dir_fd=destination_fd)
        while True:
            chunk = os.read(source, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                view = view[written:]
        os.fchmod(destination, stat.S_IMODE(source_stat.st_mode))
        os.fsync(destination)
    finally:
        try:
            os.close(source)
        finally:
            if destination >= 0:
                os.close(destination)


def copy_tree_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str, *, preserve_symlinks: bool = False) -> None:
    """Copy a directory tree below retained descriptors.

    Runtime backup/restore trees reject symlinks.  The offline source archive
    is the one deliberate exception: it preserves source symlinks as literal
    directory entries, without ever following them.
    """
    _relative_parts(source_name, allow_dot=True)
    destination_name = _leaf_name(destination_name)
    source = os.open(source_name, _DIR_FLAGS, dir_fd=source_fd)
    try:
        os.mkdir(destination_name, 0o700, dir_fd=destination_fd)
        destination = os.open(destination_name, _DIR_FLAGS, dir_fd=destination_fd)
        try:
            for entry in os.scandir(source):
                name = entry.name
                entry_stat = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(entry_stat.st_mode):
                    if not preserve_symlinks:
                        raise ConflictError(f"filesystem source contains a symlink: {source_name}/{name}")
                    os.symlink(os.readlink(name, dir_fd=source), name, dir_fd=destination)
                elif stat.S_ISDIR(entry_stat.st_mode):
                    copy_tree_at(source, name, destination, name, preserve_symlinks=preserve_symlinks)
                elif stat.S_ISREG(entry_stat.st_mode):
                    copy_file_at(source, name, destination, name)
                else:
                    raise ConflictError(f"filesystem source contains unsupported entry: {source_name}/{name}")
            os.fsync(destination)
        finally:
            os.close(destination)
    finally:
        os.close(source)


def remove_tree_at(parent_fd: int, name: str) -> None:
    name = _leaf_name(name)
    try:
        child = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        for entry in os.scandir(child):
            entry_stat = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(entry_stat.st_mode):
                remove_tree_at(child, entry.name)
            elif stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode):
                os.unlink(entry.name, dir_fd=child)
            else:
                raise ConflictError(f"filesystem tree contains unsupported entry: {name}/{entry.name}")
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent_fd)


def atomic_json_write(path: str | Path, encoded: bytes, *, identity: Mapping[str, Any] | None = None) -> None:
    """Write bytes atomically below a retained parent and fsync the directory."""
    target = absolute_path(path)
    own = identity is None
    identity = identity or capture_parent(target)
    child_fd = -1
    temp_name = None
    try:
        parent_fd, name = ensure_parent_at(target, identity)
        child_fd = parent_fd if parent_fd != identity.get("_parent_fd") else -1
        base_fd = parent_fd
        temp_name = f".{name}.{os.getpid()}-{time.time_ns()}.tmp"
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=base_fd)
        try:
            view = memoryview(bytes(encoded))
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        # Parent identity is checked immediately before publication.  The
        # rename remains relative even if a concurrent swap occurs in the
        # monkeypatched syscall itself.
        validate_created_parent(target, identity, base_fd)
        os.rename(temp_name, name, src_dir_fd=base_fd, dst_dir_fd=base_fd)
        os.fsync(base_fd)
        try:
            # A last lexical check turns an in-flight ordinary replacement into
            # a typed failure while the actual rename remains in the pinned
            # directory and can never land in the replacement tree.
            validate_created_parent(target, identity, base_fd)
        except Exception:
            raise
    except Exception:
        if temp_name is not None:
            try:
                base_fd = locals().get("base_fd", -1)
                if base_fd >= 0:
                    os.unlink(temp_name, dir_fd=base_fd)
            except OSError:
                pass
        raise
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        if own:
            close_pinned(identity)


__all__ = ["PinnedParent", "absolute_path", "has_symlink_component", "open_directory_chain", "capture_parent", "pin_directory", "close_pinned", "validate_parent", "validate_created_parent", "mkdir_chain_at", "ensure_parent_at", "ensure_directory", "mkdir_temp_at", "write_bytes_at", "copy_file_at", "copy_tree_at", "remove_tree_at", "atomic_json_write"]
