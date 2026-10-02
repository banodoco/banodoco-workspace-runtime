from __future__ import annotations

import hashlib
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from .dirfd import open_directory_chain, mkdir_chain_at
from .errors import ConflictError, NotFoundError, ValidationError

IO_CHUNK_BYTES = 1024 * 1024
DEFAULT_MAX_OBJECT_BYTES = 5 * 1024 ** 3


def file_identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@dataclass
class StagedObject:
    path: Path
    digest: str
    size: int

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.discard()

    def discard(self):
        self.path.unlink(missing_ok=True)


class ContentAddressedStore:
    """Append-only SHA-256 store; transfer/hash precede immutable publication."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValidationError("invalid SHA-256 digest")
        return self.root / digest[:2] / digest[2:]

    def stage(self, chunks, staging_root, *, max_bytes=DEFAULT_MAX_OBJECT_BYTES, expected_digest=None):
        root_fd = open_directory_chain(staging_root)
        uploads_fd = -1
        name = uuid.uuid4().hex + ".upload"
        try:
            uploads_fd = mkdir_chain_at(root_fd, "uploads")
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=uploads_fd)
            size = 0
            hasher = hashlib.sha256()
            try:
                with os.fdopen(fd, "wb") as stream:
                    for chunk in chunks:
                        if not isinstance(chunk, (bytes, bytearray, memoryview)):
                            raise ValidationError("object stream chunks must be bytes")
                        size += len(chunk)
                        if size > max_bytes:
                            raise ValidationError(f"object exceeds {max_bytes} byte limit")
                        # Even an in-process iterator must not cause oversized writes.
                        for offset in range(0, len(chunk), IO_CHUNK_BYTES):
                            part = memoryview(chunk)[offset:offset + IO_CHUNK_BYTES]
                            stream.write(part)
                            hasher.update(part)
                    stream.flush()
                    os.fsync(stream.fileno())
                digest = hasher.hexdigest()
                expected = (expected_digest or "").removeprefix("sha256:") or None
                if expected and expected != digest:
                    raise ConflictError("content hash does not match expected digest", details={"expected": expected, "actual": digest})
                return StagedObject(Path(staging_root) / "uploads" / name, digest, size)
            except BaseException:
                os.unlink(name, dir_fd=uploads_fd)
                raise
        finally:
            if uploads_fd >= 0:
                os.close(uploads_fd)
            os.close(root_fd)

    def open(self, digest):
        self.path_for(digest)
        root_fd = open_directory_chain(self.root)
        prefix_fd = -1
        try:
            prefix_fd = os.open(digest[:2], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_fd)
            fd = os.open(digest[2:], os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), dir_fd=prefix_fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise ConflictError("CAS object must be a regular file")
            return os.fdopen(fd, "rb")
        except FileNotFoundError as exc:
            raise NotFoundError("object not found") from exc
        except OSError as exc:
            raise ConflictError("CAS object must be an accessible ordinary file") from exc
        finally:
            if prefix_fd >= 0:
                os.close(prefix_fd)
            os.close(root_fd)

    def existing_identity(self, digest, size):
        """Verify potential deduplication outside the database critical section."""
        try:
            with self.open(digest) as stream:
                initial = os.fstat(stream.fileno())
                hasher = hashlib.sha256()
                while chunk := stream.read(IO_CHUNK_BYTES):
                    hasher.update(chunk)
                final = os.fstat(stream.fileno())
                if initial.st_size != size or file_identity(initial) != file_identity(final) or hasher.hexdigest() != digest:
                    raise ConflictError("CAS collision or corrupt existing object")
                return file_identity(final)
        except NotFoundError:
            return None

    def publish(self, staged, *, existing_identity=None):
        """No-replace, same-filesystem publication. Caller owns publication journal."""
        digest = staged.digest
        self.path_for(digest)
        root_fd = open_directory_chain(self.root)
        prefix_fd = -1
        try:
            prefix_fd = mkdir_chain_at(root_fd, digest[:2])
            try:
                os.link(staged.path, digest[2:], dst_dir_fd=prefix_fd, follow_symlinks=False)
                deduplicated = False
                os.fsync(prefix_fd)
                os.fsync(root_fd)
            except FileExistsError:
                value = os.stat(digest[2:], dir_fd=prefix_fd, follow_symlinks=False)
                if not stat.S_ISREG(value.st_mode) or existing_identity != file_identity(value):
                    raise ConflictError("CAS destination changed during publication; retry request")
                deduplicated = True
            value = os.stat(digest[2:], dir_fd=prefix_fd, follow_symlinks=False)
            return {"digest": digest, "size": staged.size, "deduplicated": deduplicated, "identity": file_identity(value)}
        finally:
            if prefix_fd >= 0:
                os.close(prefix_fd)
            os.close(root_fd)

    def put(self, data: bytes, *, expected_digest=None) -> dict:
        staged = self.stage((data,), self.root, expected_digest=expected_digest)
        try:
            identity = self.existing_identity(staged.digest, staged.size)
            return self.publish(staged, existing_identity=identity)
        finally:
            staged.discard()

    def read(self, digest: str) -> bytes:
        with self.open(digest) as stream:
            data = stream.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ConflictError("CAS object failed hash verification")
        return data

    def verify(self, digest: str) -> dict:
        with self.open(digest) as stream:
            size = os.fstat(stream.fileno()).st_size
        self.existing_identity(digest, size)
        return {"digest": digest, "size": size, "verified": True}
