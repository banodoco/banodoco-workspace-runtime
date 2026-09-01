from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, InvalidRequestError, LeaseError, ValidationError
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


def test_project_task_contract_scopes_inputs_and_outputs(tmp_path: Path) -> None:
    """A project task carries its scope through claim/get and output ingest.

    This is the runtime-side contract that a generic host needs: input
    digests cannot cross project boundaries, while bytes uploaded to the
    project's managed-object endpoint are associated before fenced settlement.
    """
    service = RuntimeService(tmp_path / "realm")
    try:
        capability_digest = _digest("render.project")
        service.register_capability({"capability_id": "render.project", "definition_digest": capability_digest})
        service.register_executor({"executor_id": "worker", "capabilities": ["render.project"]})
        source_project = service.create_project({"slug": "source", "name": "Source"}, idempotency_key="project-source")
        other_project = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="project-other")
        source = service.ingest(source_project["id"], b"project input", idempotency_key="input")
        input_id = source["data"]["digest"]

        with pytest.raises(ConflictError, match="not associated with the task project"):
            service.create_task(
                {
                    "capability_id": "render.project",
                    "capability_digest": capability_digest,
                    "project": other_project["id"],
                    "input_object_ids": [input_id],
                    "idempotency_key": "foreign-input",
                }
            )
        with pytest.raises(ValidationError, match="sha256 object IDs"):
            service.create_task(
                {
                    "capability_id": "render.project",
                    "capability_digest": capability_digest,
                    "project": source_project["id"],
                    "input_object_ids": ["not-an-object-id"],
                    "idempotency_key": "malformed-input",
                }
            )

        admitted = service.create_task(
            {
                "capability_id": "render.project",
                "capability_digest": capability_digest,
                "project": source_project["id"],
                "input_object_ids": [input_id],
                "idempotency_key": "scoped-task",
            }
        )
        task = service._task_resource(admitted)
        assert task["project_id"] == source_project["id"]
        epoch = service.health()["runtime_epoch"]
        claim = service.claim_next(
            {"executor_id": "worker", "capability_ids": ["render.project"], "runtime_epoch": epoch},
            idempotency_key="scoped-claim",
        )
        assert claim["project_id"] == source_project["id"]
        assert service._task_resource(service.store.get_task(task["task_id"]))["project_id"] == source_project["id"]

        output = service.ingest(source_project["id"], b"new project output", idempotency_key="output")
        output_id = output["data"]["digest"]
        settled = service.settle_attempt(
            claim["attempt_id"],
            {
                "lease_id": claim["lease_id"],
                "fence": claim["fence"],
                "runtime_epoch": epoch,
                "outputs": [{"name": "render", "kind": "object", "digest": output_id, "media_type": "application/octet-stream", "size": len(b"new project output")}],
            },
            idempotency_key="scoped-settle",
        )
        assert settled["data"]["project_id"] == source_project["id"]
        assert service.store.conn.execute(
            "SELECT 1 FROM project_objects WHERE project_id=? AND digest=?",
            (source_project["id"], output_id.removeprefix("sha256:")),
        ).fetchone()
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


def test_project_updates_require_idempotency_keys_at_service_boundary(tmp_path: Path) -> None:
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "p1", "name": "P1"}, idempotency_key="project")
        shot = service.create_project_shot(project["id"], {"name": "Shot", "metadata": {}}, idempotency_key="shot")
        media = service.ingest(project["id"], b"reference-media", idempotency_key="media")
        reference = service.create_project_reference(
            project["id"],
            {"kind": "object", "name": "Reference", "media_id": media["data"]["digest"], "metadata": {}},
            idempotency_key="reference",
        )
        with pytest.raises(InvalidRequestError, match="Idempotency-Key is required"):
            service.update_project_shot(project["id"], shot["data"]["shot_id"], {"expected_version": 1, "name": "Updated"})
        with pytest.raises(InvalidRequestError, match="Idempotency-Key is required"):
            service.update_project_reference(
                project["id"], reference["data"]["reference_id"], {"expected_version": 1, "name": "Updated"}
            )
        with pytest.raises(InvalidRequestError, match="at most 256"):
            service.update_project_shot(
                project["id"], shot["data"]["shot_id"], {"expected_version": 1, "name": "Updated"}, idempotency_key="x" * 257
            )
    finally:
        service.close()


def test_publication_journal_is_retained_when_cleanup_fails_then_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "realm"
    payload = b"retryable-cleanup-output"
    digest = _digest(payload).removeprefix("sha256:")
    service = RuntimeService(root)
    service._begin_cas_publication_journal("ingest", [{"digest": digest}], project_id="unscoped")
    service.cas.put(payload)
    destination = service.cas.path_for(digest)
    service.close()

    original_unlink = Path.unlink
    failed = False

    def fail_destination_once(path, *args, **kwargs):
        nonlocal failed
        if path == destination and not failed:
            failed = True
            raise OSError("simulated cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_destination_once)
    interrupted = RuntimeService(root)
    try:
        journal_paths = list((root / "staging" / "publications").glob("*.json"))
        assert failed
        assert destination.exists()
        assert len(journal_paths) == 1
    finally:
        interrupted.close()

    monkeypatch.setattr(Path, "unlink", original_unlink)
    recovered = RuntimeService(root)
    try:
        assert not destination.exists()
        assert list((root / "staging" / "publications").glob("*.json")) == []
    finally:
        recovered.close()
