from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .errors import ConflictError, NotFoundError, ValidationError
from .util import sha256_bytes


class ContentAddressedStore:
    """Append-only SHA-256 object store owned by the runtime daemon."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValidationError("invalid SHA-256 digest")
        return self.root / digest[:2] / digest[2:]

    def put(self, data: bytes, *, expected_digest=None) -> dict:
        digest = sha256_bytes(data)
        if expected_digest and expected_digest != digest:
            raise ConflictError("content hash does not match expected digest", details={"expected": expected_digest, "actual": digest})
        destination = self.path_for(digest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.is_symlink():
                raise ConflictError("CAS destination must not be a symlink")
            if destination.read_bytes() != data:
                raise ConflictError("CAS collision or corrupt existing object")
            return {"digest": digest, "size": len(data), "deduplicated": True}
        temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
        published = False
        try:
            with open(temporary, "xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            published = True
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            if published:
                try:
                    destination.unlink()
                except FileNotFoundError:
                    pass
                try:
                    directory_fd = os.open(destination.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError:
                    pass
            raise
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return {"digest": digest, "size": len(data), "deduplicated": False}

    def read(self, digest: str) -> bytes:
        path = self.path_for(digest)
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise NotFoundError("object not found") from exc
        if hashlib.sha256(data).hexdigest() != digest:
            raise ConflictError("CAS object failed hash verification")
        return data

    def verify(self, digest: str) -> dict:
        data = self.read(digest)
        return {"digest": digest, "size": len(data), "verified": True}
