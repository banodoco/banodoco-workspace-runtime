"""Bounded, opt-in Runtime exception evidence for the local control boundary.

The sink is inert unless ``RUNTIME_EXCEPTION_CAPTURE_SINK`` is explicitly set
by the run owner. Evidence is deliberately limited to request identity,
exception class names, and traceback locations. Exception messages, locals,
profiles, credentials, and subprocess output never enter the record.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import traceback
from typing import Any


SINK_ENV = "RUNTIME_EXCEPTION_CAPTURE_SINK"
MAX_CHAIN = 16
MAX_FRAMES = 64
MAX_PATH_BYTES = 512
MAX_NAME_BYTES = 256
MAX_RECORD_BYTES = 64 * 1024


def _bounded_text(value: object, limit: int) -> str:
    text = str(value)
    return text[:limit]


def _exception_chain(exc: BaseException) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and len(chain) < MAX_CHAIN and id(current) not in seen:
        seen.add(id(current))
        chain.append({
            "module": _bounded_text(type(current).__module__, MAX_NAME_BYTES),
            "class": _bounded_text(type(current).__name__, MAX_NAME_BYTES),
        })
        current = current.__cause__ or current.__context__
    return chain


def _traceback_locations(exc: BaseException) -> list[dict[str, object]]:
    extracted = traceback.extract_tb(exc.__traceback__)
    return [
        {
            "file": _bounded_text(Path(frame.filename).name, MAX_PATH_BYTES),
            "line": int(frame.lineno),
            "function": _bounded_text(frame.name, MAX_NAME_BYTES),
        }
        for frame in extracted[-MAX_FRAMES:]
    ]


def _validate_sink(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("exception evidence sink must be an absolute non-symlink path")
    parent = path.parent
    parent_stat = parent.stat()
    if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid():
        raise ValueError("exception evidence sink parent is not run-owned")
    if stat.S_IMODE(parent_stat.st_mode) & 0o022:
        raise ValueError("exception evidence sink parent is group/world writable")
    if path.exists():
        observed = path.lstat()
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise ValueError("exception evidence sink ownership or mode is unsafe")


def capture_exception(request_id: str, exc: BaseException) -> dict[str, object]:
    """Persist one safe record, returning a status without raising on failure."""

    sink_raw = os.environ.get(SINK_ENV)
    if not sink_raw:
        return {"status": "disabled"}
    try:
        sink = Path(sink_raw)
        _validate_sink(sink)
        record = {
            "version": 1,
            "request_id": _bounded_text(request_id, 128),
            "exception_chain": _exception_chain(exc),
            "traceback_locations": _traceback_locations(exc),
        }
        encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(encoded) > MAX_RECORD_BYTES:
            raise ValueError("exception evidence record exceeds bounded size")
        descriptor = os.open(
            sink,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.getuid()
                or stat.S_IMODE(observed.st_mode) != 0o600
            ):
                raise ValueError("exception evidence sink changed ownership or mode")
            written = 0
            while written < len(encoded):
                progress = os.write(descriptor, encoded[written:])
                if progress <= 0:
                    raise OSError("exception evidence sink made no write progress")
                written += progress
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return {"status": "captured", "bytes": len(encoded)}
    except BaseException as failure:
        return {
            "status": "uncertain",
            "reason": type(failure).__name__,
        }
