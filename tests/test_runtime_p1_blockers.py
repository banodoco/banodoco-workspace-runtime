from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, LeaseError
from runtime_protocol.service import RuntimeService


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def test_http_object_ingest_requires_key_and_replays_exact_result(tmp_path: Path) -> None:
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        api = Api(daemon.endpoint, daemon.token)
        with pytest.raises(RuntimeError) as missing:
            api.request("POST", "/v1/objects", raw=b"payload", headers={"Content-Type": "application/octet-stream"})
        assert missing.value.status == 400

        headers = {"Content-Type": "application/octet-stream", "Idempotency-Key": "object-ingest"}
        first = api.request("POST", "/v1/objects", raw=b"payload", headers=headers)
        assert api.request("POST", "/v1/objects", raw=b"payload", headers=headers) == first
        with pytest.raises(RuntimeError) as changed:
            api.request("POST", "/v1/objects", raw=b"changed", headers=headers)
        assert changed.value.status == 409
    finally:
        daemon.stop()


def test_task_transitions_and_attempt_settlement_replay_exactly(tmp_path: Path) -> None:
    service = RuntimeService(tmp_path / "realm")
    try:
        service.register_capability({"capability_id": "render.test", "definition_digest": _digest("render.test")})
        service.register_executor({"executor_id": "worker", "capabilities": ["render.test"]})
        project = service.create_project({"slug": "p1", "name": "P1"}, idempotency_key="project")
        task = service.create_task({"capability_id": "render.test", "capability_digest": _digest("render.test"), "project": project["id"], "idempotency_key": "task"})
        epoch = service.health()["runtime_epoch"]
        attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.test"], "runtime_epoch": epoch}, idempotency_key="claim")
        settle = {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "outputs": []}
        first = service.settle_attempt(attempt["attempt_id"], settle, idempotency_key="settle")
        assert service.settle_attempt(attempt["attempt_id"], settle, idempotency_key="settle") == first
        assert service.store.conn.execute("SELECT txn_id, event_ids_json FROM command_idempotency WHERE command_kind='attempt.settle'").fetchone()[0]

        cancelled = service.create_task({"capability_id": "render.test", "capability_digest": _digest("render.test"), "project": project["id"], "idempotency_key": "task-cancel"})
        cancel_first = service.cancel_task_canonical(cancelled["task"]["id"], {}, idempotency_key="cancel")
        assert service.cancel_task_canonical(cancelled["task"]["id"], {}, idempotency_key="cancel") == cancel_first
    finally:
        service.close()


def test_claim_replay_is_fenced_after_runtime_restart(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    first = RuntimeService(root)
    first.register_capability({"capability_id": "render.test", "definition_digest": _digest("render.test")})
    first.register_executor({"executor_id": "worker", "capabilities": ["render.test"]})
    first.create_task({"capability_id": "render.test", "capability_digest": _digest("render.test"), "idempotency_key": "task"})
    body = {"executor_id": "worker", "capability_ids": ["render.test"], "runtime_epoch": first.health()["runtime_epoch"]}
    first.claim_next(body, idempotency_key="claim")
    first.close()

    second = RuntimeService(root)
    try:
        with pytest.raises(LeaseError):
            second.claim_next(body, idempotency_key="claim")
    finally:
        second.close()


def test_settlement_db_failure_removes_published_cas_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = RuntimeService(tmp_path / "realm")
    try:
        service.register_executor({"executor_id": "worker", "capabilities": ["render.test"]})
        task = service.create_task({"capability_id": "render.test", "idempotency_key": "task"})
        attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.test"], "runtime_epoch": 1})
        payload = b"transactional-output"
        output = {"name": "output", "kind": "object", "digest": _digest(payload), "media_type": "application/octet-stream", "size": len(payload), "data_base64": base64.b64encode(payload).decode()}
        monkeypatch.setattr(service, "_command_record", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("ledger failure")))
        with pytest.raises(RuntimeError, match="ledger failure"):
            service.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": 1, "outputs": [output]}, idempotency_key="settle")
        digest = _digest(payload).removeprefix("sha256:")
        assert not service.cas.path_for(digest).exists()
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
        assert service.store.conn.execute("SELECT status FROM tasks WHERE id=?", (task["task"]["id"],)).fetchone()[0] == "running"
    finally:
        service.close()


def test_startup_reconciles_journaled_publication_after_crash_seam(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    payload = b"crash-window-output"
    digest = _digest(payload).removeprefix("sha256:")
    service = RuntimeService(root)
    service._begin_cas_publication_journal("ingest", [{"digest": digest}], project_id="unscoped")
    service.cas.put(payload)
    service.close()

    recovered = RuntimeService(root)
    try:
        assert not recovered.cas.path_for(digest).exists()
        assert list((root / "staging" / "publications").glob("*.json")) == []
    finally:
        recovered.close()
