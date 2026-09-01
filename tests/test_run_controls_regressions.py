from __future__ import annotations

import hashlib
import sqlite3

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import InvalidRequestError, LeaseError
from runtime_protocol.service import RuntimeService


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _task(service: RuntimeService, key: str):
    return service.create_task(
        {
            "capability_id": "render.basic",
            "capability_digest": _digest("render.basic"),
            "input_object_ids": [],
            "spec": {},
            "idempotency_key": key,
        }
    )


def test_run_control_receipt_is_atomic_and_replayable_after_restart(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    project = service.create_project({"slug": "project", "name": "Project", "metadata": {}})
    service.store.conn.execute(
        "CREATE TRIGGER abort_receipt BEFORE INSERT ON command_idempotency "
        "BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        service.store.update_project(project["id"], name="Changed", expected_version=1, idempotency_key="project-update")
    unchanged = service.store.get_project(project["id"])
    assert unchanged["name"] == "Project" and unchanged["version"] == 1
    service.store.conn.execute("DROP TRIGGER abort_receipt")
    service.store.update_project(project["id"], name="Changed", expected_version=1, idempotency_key="project-update")
    service.close()

    service = RuntimeService(tmp_path / "realm")
    assert service.store.update_project(project["id"], name="Changed", expected_version=1, idempotency_key="project-update")["version"] == 2
    cancelled = _task(service, "cancel")
    service.store.conn.execute(
        "CREATE TRIGGER abort_receipt BEFORE INSERT ON command_idempotency "
        "BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        service.store.cancel_run(cancelled["run"]["id"], idempotency_key="run-cancel")
    assert service.store.conn.execute("SELECT status FROM runs WHERE id=?", (cancelled["run"]["id"],)).fetchone()[0] == "queued"
    service.store.conn.execute("DROP TRIGGER abort_receipt")
    service.store.cancel_run(cancelled["run"]["id"], idempotency_key="run-cancel")
    service.close()

    service = RuntimeService(tmp_path / "realm")
    failed = _task(service, "retry")
    service.store.conn.execute("UPDATE runs SET status='failed' WHERE id=?", (failed["run"]["id"],))
    service.store.conn.execute("UPDATE tasks SET status='failed' WHERE id=?", (failed["task"]["id"],))
    service.store.conn.execute(
        "CREATE TRIGGER abort_receipt BEFORE INSERT ON command_idempotency "
        "BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        service.store.retry_run(failed["run"]["id"], idempotency_key="run-retry")
    assert service.store.conn.execute("SELECT status FROM runs WHERE id=?", (failed["run"]["id"],)).fetchone()[0] == "failed"
    service.store.conn.execute("DROP TRIGGER abort_receipt")
    service.store.retry_run(failed["run"]["id"], idempotency_key="run-retry")
    service.close()


def test_cancelled_attempt_cannot_publish_late_outputs(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    service.register_executor(
        {
            "executor_id": "worker",
            "capabilities": ["render.basic"],
            "resource_keys": [],
            "runtime_epoch": service.health()["runtime_epoch"],
        }
    )
    admitted = _task(service, "late-settlement")
    attempt = service.claim_next(
        {
            "executor_id": "worker",
            "capability_ids": ["render.basic"],
            "runtime_epoch": service.health()["runtime_epoch"],
        }
    )
    service.store.cancel_run(admitted["run"]["id"], idempotency_key="cancel-late")
    digest = _digest("late-output")
    with pytest.raises(LeaseError):
        service.settle_attempt(
            attempt["attempt_id"],
            {
                "lease_id": attempt["lease_id"],
                "fence": attempt["fence"],
                "runtime_epoch": attempt["runtime_epoch"],
                "outputs": [{"digest": digest, "data_base64": "bGF0ZS1vdXRwdXQ="}],
            },
            idempotency_key="late-settlement",
        )
    assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest.removeprefix("sha256:"),)).fetchone() is None
    assert not service.cas.path_for(digest.removeprefix("sha256:")).exists()
    service.close()


def test_retry_run_rejects_invalid_selection_as_typed_bad_request(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        admitted = client.admit_task(
            capability_id="render.basic",
            capability_digest=_digest("render.basic"),
            input_object_ids=[],
            idempotency_key="invalid-selection",
        )
        daemon.service.store.conn.execute("UPDATE runs SET status='failed' WHERE id=?", (admitted.run_id,))
        daemon.service.store.conn.execute("UPDATE tasks SET status='failed' WHERE id=?", (admitted.task_id,))
        with pytest.raises(ApiError) as error:
            client.retry_run(admitted.run_id, idempotency_key="invalid-selection-command", selected_task_ids=123)  # type: ignore[arg-type]
        assert error.value.status == 400 and error.value.code == "invalid_request"
        with pytest.raises(InvalidRequestError):
            daemon.service.store.retry_run(admitted.run_id, selected_task_ids={"bad": "shape"}, idempotency_key="invalid-selection-direct")
    finally:
        daemon.stop()
