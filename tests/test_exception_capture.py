import json
import threading
from types import SimpleNamespace

import runtime_protocol.exception_capture as exception_capture
from runtime_protocol.server import RuntimeHandler


class RecordingHandler(RuntimeHandler):
    def _send(self, status, payload=None, *, headers=None, body=None, error=None, **kwargs):
        self.recorded = {
            "status": status,
            "headers": headers or {},
            "error": error,
            "body": body,
        }

    def _route(self):
        raise ValueError("injected secret sentinel")


def _handler():
    handler = object.__new__(RecordingHandler)
    handler.headers = {"X-Request-ID": "req-safe-92"}
    handler.server = SimpleNamespace(
        runtime=SimpleNamespace(store=SimpleNamespace(_mutex=threading.RLock())),
    )
    handler.command = "GET"
    handler.path = "/v1/injected-failure"
    return handler


def test_opt_in_capture_records_only_safe_exception_shape(tmp_path, monkeypatch):
    sink = tmp_path / "runtime-exceptions.jsonl"
    monkeypatch.setenv("RUNTIME_EXCEPTION_CAPTURE_SINK", str(sink))
    handler = _handler()
    try:
        raise ValueError("secret sentinel must not persist")
    except ValueError as exc:
        handler._dispatch()

    assert handler.recorded["status"] == 500
    assert handler.recorded["headers"] == {"X-Exception-Capture": "captured"}
    assert handler.recorded["error"] == {
        "code": "internal_error",
        "message": "internal runtime error",
        "request_id": "req-safe-92",
    }
    record = json.loads(sink.read_text())
    assert record["request_id"] == "req-safe-92"
    assert record["exception_chain"][-1]["class"] == "ValueError"
    assert record["traceback_locations"]
    assert "secret sentinel" not in sink.read_text()
    assert "locals" not in record
    assert "message" not in record


def test_capture_persistence_failure_keeps_generic_response_and_surfaces_uncertainty(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv(
        "RUNTIME_EXCEPTION_CAPTURE_SINK",
        str(tmp_path / "missing-parent" / "runtime-exceptions.jsonl"),
    )
    handler = _handler()
    handler._dispatch()

    assert handler.recorded["status"] == 500
    assert handler.recorded["headers"] == {"X-Exception-Capture": "uncertain"}
    assert handler.recorded["error"] == {
        "code": "internal_error",
        "message": "internal runtime error",
        "request_id": "req-safe-92",
    }


def test_capture_default_is_inert(monkeypatch):
    monkeypatch.delenv("RUNTIME_EXCEPTION_CAPTURE_SINK", raising=False)
    handler = _handler()
    handler._error(RuntimeError("secret sentinel"))
    assert handler.recorded["headers"] == {}
    assert handler.recorded["error"]["message"] == "internal runtime error"


def test_capture_completes_after_one_short_write(tmp_path, monkeypatch):
    sink = tmp_path / "runtime-exceptions.jsonl"
    monkeypatch.setenv("RUNTIME_EXCEPTION_CAPTURE_SINK", str(sink))
    original_write = exception_capture.os.write
    calls = 0

    def write_once_short(fd, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(fd, data[:1])
        return original_write(fd, data)

    monkeypatch.setattr(exception_capture.os, "write", write_once_short)
    result = exception_capture.capture_exception("req-short-once", ValueError("secret"))

    assert result["status"] == "captured"
    assert calls == 2
    assert json.loads(sink.read_text())["request_id"] == "req-short-once"


def test_capture_completes_after_multiple_short_writes(tmp_path, monkeypatch):
    sink = tmp_path / "runtime-exceptions.jsonl"
    monkeypatch.setenv("RUNTIME_EXCEPTION_CAPTURE_SINK", str(sink))
    original_write = exception_capture.os.write
    calls = 0

    def write_in_short_chunks(fd, data):
        nonlocal calls
        calls += 1
        return original_write(fd, data[:3])

    monkeypatch.setattr(exception_capture.os, "write", write_in_short_chunks)
    result = exception_capture.capture_exception("req-short-many", ValueError("secret"))

    assert result["status"] == "captured"
    assert calls > 2
    assert json.loads(sink.read_text())["request_id"] == "req-short-many"


def test_capture_zero_progress_is_uncertain_without_fsync(tmp_path, monkeypatch):
    sink = tmp_path / "runtime-exceptions.jsonl"
    monkeypatch.setenv("RUNTIME_EXCEPTION_CAPTURE_SINK", str(sink))
    fsync_calls = 0

    def write_without_progress(fd, data):
        return 0

    def record_fsync(fd):
        nonlocal fsync_calls
        fsync_calls += 1

    monkeypatch.setattr(exception_capture.os, "write", write_without_progress)
    monkeypatch.setattr(exception_capture.os, "fsync", record_fsync)
    result = exception_capture.capture_exception("req-zero", ValueError("secret"))

    assert result == {"status": "uncertain", "reason": "OSError"}
    assert fsync_calls == 0
    assert sink.read_bytes() == b""


def test_capture_negative_progress_is_uncertain_without_fsync(tmp_path, monkeypatch):
    sink = tmp_path / "runtime-exceptions.jsonl"
    monkeypatch.setenv("RUNTIME_EXCEPTION_CAPTURE_SINK", str(sink))
    fsync_calls = 0

    def write_without_progress(fd, data):
        return -1

    def record_fsync(fd):
        nonlocal fsync_calls
        fsync_calls += 1

    monkeypatch.setattr(exception_capture.os, "write", write_without_progress)
    monkeypatch.setattr(exception_capture.os, "fsync", record_fsync)
    result = exception_capture.capture_exception("req-negative", ValueError("secret"))

    assert result == {"status": "uncertain", "reason": "OSError"}
    assert fsync_calls == 0
    assert sink.read_bytes() == b""


def test_capture_write_exception_is_uncertain_without_fsync(tmp_path, monkeypatch):
    sink = tmp_path / "runtime-exceptions.jsonl"
    monkeypatch.setenv("RUNTIME_EXCEPTION_CAPTURE_SINK", str(sink))
    fsync_calls = 0

    def write_raises(fd, data):
        raise OSError("injected write failure")

    def record_fsync(fd):
        nonlocal fsync_calls
        fsync_calls += 1

    monkeypatch.setattr(exception_capture.os, "write", write_raises)
    monkeypatch.setattr(exception_capture.os, "fsync", record_fsync)
    result = exception_capture.capture_exception("req-exception", ValueError("secret"))

    assert result == {"status": "uncertain", "reason": "OSError"}
    assert fsync_calls == 0
    assert sink.read_bytes() == b""
