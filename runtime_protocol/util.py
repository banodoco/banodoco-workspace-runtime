from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id() -> str:
    return uuid.uuid4().hex


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def durable_json_bytes(value) -> bytes:
    """Return the exact bytes written by :func:`atomic_json_write`.

    Size limits must be applied to the durable representation, not to a
    different compact representation which can undercount escaped/non-ASCII
    content.  Keeping the serializer in one place makes the limit and the
    persisted digest agree byte-for-byte.
    """
    return (json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n")


def atomic_json_write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(durable_json_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
