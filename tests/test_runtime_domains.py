from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.service import RuntimeService


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def test_actor_project_selection_is_runtime_owned_and_persistent(tmp_path):
    realm = tmp_path / "realm"
    support = tmp_path / "support"
    daemon = RuntimeDaemon(realm, support_root=support).start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        first = client.create_project("First", slug="first", idempotency_key="first")
        second = client.create_project("Second", slug="second", idempotency_key="second")
        selected = client.select_project(second.slug, scope="workspace", idempotency_key="select-second")
        assert selected["scope"] == "workspace"
        assert selected["project"]["project_id"] == second.project_id
        assert client.current_project()["project"]["project_id"] == second.project_id
        # A reconnecting client with the same actor credential sees the same
        # selection, while a different actor has no local-file fallback.
        reconnect = WorkspaceClient(daemon.endpoint, daemon.token)
        assert reconnect.current_project()["project"]["project_id"] == second.project_id
        assert first.project_id != second.project_id
        assert selected.receipt["command_kind"] == "project.select"
    finally:
        daemon.stop()


def test_receipts_are_identical_across_concurrent_replay_and_restart(tmp_path):
    realm = tmp_path / "realm"
    support = tmp_path / "support"
    daemon = RuntimeDaemon(realm, support_root=support).start()
    try:
        def create_once():
            client = WorkspaceClient(daemon.endpoint, daemon.token)
            return client.create_project("Concurrent", slug="concurrent", idempotency_key="concurrent-project")

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: create_once(), range(6)))
        assert {json.dumps(result.receipt, sort_keys=True) for result in results} == {json.dumps(results[0].receipt, sort_keys=True)}
        project = results[0]
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        selected = client.select_project(project.project_id, idempotency_key="concurrent-select")
        task = client.admit_task(capability_id="render.basic", capability_digest=_digest("render.basic"), input_object_ids=[], project_id=project.project_id, idempotency_key="concurrent-task", spec={})
        assert selected.receipt["command_kind"] == "project.select"
        assert task.receipt["command_kind"] == "task.create"
        daemon.stop()
        restarted = RuntimeDaemon(realm, support_root=support).start()
        try:
            replay = WorkspaceClient(restarted.endpoint, restarted.token).create_project("Concurrent", slug="concurrent", idempotency_key="concurrent-project")
            assert replay.receipt == project.receipt
            assert restarted.service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 1
            assert restarted.service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0] == 3
        finally:
            restarted.stop()
            daemon = None
    finally:
        if daemon is not None:
            daemon.stop()


def test_task_receipt_binds_committed_admission_event_and_canonical_sequence(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Receipt facts", slug="receipt-facts", idempotency_key="receipt-project")
        task = client.admit_task(
            capability_id="render.basic",
            capability_digest=_digest("render.basic"),
            input_object_ids=[], project_id=project.project_id,
            idempotency_key="receipt-task", spec={},
        )
        events = client.list_run_events(task.run_id)
        admitted = next(event for event in events if event.event_type == "task.admitted")
        assert task.receipt["event_ids"] == [admitted.event_id]
        assert task.receipt["receipt_id"].startswith("txn-")
        assert task.receipt["project_seq"] == [2, 2]
        ledger_rowid = daemon.service.store.conn.execute(
            "SELECT rowid FROM command_idempotency WHERE idempotency_key=?",
            ("receipt-task",),
        ).fetchone()[0]
        assert task.receipt["receipt_id"] != f"runtime-command-{ledger_rowid}"
    finally:
        daemon.stop()


def test_unready_capability_rejected_before_any_ledger_rows(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Ready gate", slug="ready-gate", idempotency_key="ready-gate")
        digest = _digest("gpu-capability")
        client.register_capability("acceptance.gpu", digest, status="unavailable", unavailable_reason="gpu_not_configured")
        before = daemon.service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        with pytest.raises(ApiError) as caught:
            client.admit_task(capability_id="acceptance.gpu", capability_digest=digest, input_object_ids=[], project_id=project.project_id, idempotency_key="blocked")
        assert caught.value.code == "unavailable"
        assert caught.value.details == {
            "capability_id": "acceptance.gpu",
            "status": "unavailable",
            "reason": "gpu_not_configured",
            "next_action": "wait for capability readiness and retry",
        }
        after = daemon.service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        assert before == after == 0
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    finally:
        daemon.stop()


@pytest.mark.parametrize(
    ("method", "route"),
    [
        ("POST", "shots"),
        ("POST", "references"),
        ("PATCH", "shots/does-not-exist"),
        ("PATCH", "references/does-not-exist"),
        ("POST", "shots/does-not-exist/archive"),
        ("POST", "references/does-not-exist/archive"),
    ],
)
def test_project_shot_reference_routes_reject_non_object_json_as_typed_400(tmp_path, route, method):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Malformed", slug="malformed", idempotency_key="malformed-project")
        url = f"{daemon.endpoint}/v1/projects/{project.slug}/{route}"
        request = urllib.request.Request(
            url,
            data=b"[1]",
            method=method,
            headers={
                "Authorization": f"Bearer {daemon.token}",
                "Content-Type": "application/json",
                "Idempotency-Key": f"malformed-{method}-{route}",
            },
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 400
        payload = json.loads(error.value.read())
        assert payload["code"] == "invalid_request"
    finally:
        daemon.stop()


def test_generated_python_client_exercises_versioned_domains_on_real_daemon(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        session = client.handshake("domain-client", "0.1.0", ["projects:read", "projects:write"])
        assert session.actor_id == "owner"
        projects, cursor = client.list_projects()
        assert cursor is None and projects == []
        project = client.create_project("Domain Project", idempotency_key="domain-project")

        document = client.create_document(project.project_id, "doc-1", "notes", {"text": "one"})
        assert document.version == 1
        updated = client.update_document(project.project_id, "doc-1", expected_version=1, content={"text": "two"})
        assert updated.version == 2 and updated.content == {"text": "two"}
        with pytest.raises(ApiError) as stale_document:
            client.update_document(project.project_id, "doc-1", expected_version=1, content={"text": "three"})
        assert stale_document.value.status == 409

        timeline = client.create_timeline(project.project_id, "timeline-1", idempotency_key="timeline-1")
        assert timeline["version"] == 1
        saved = client.update_timeline("timeline-1", expected_version=1, shots=[{"shot_id": "shot-1", "start_ms": 0, "duration_ms": 1000, "reference_ids": []}])
        assert saved["version"] == 2 and saved["shots"][0]["shot_id"] == "shot-1"
        with pytest.raises(ApiError) as stale_timeline:
            client.update_timeline("timeline-1", expected_version=1, shots=[])
        assert stale_timeline.value.status == 409

        object_row = client.ingest_object(b"variant", media_type="application/octet-stream", idempotency_key="variant-object")
        generation = client.create_generation(project.project_id, "generation-1", metadata={"prompt": "neutral"})
        assert generation.project_id == project.project_id
        variant = client.create_variant(generation.generation_id, "variant-1", object_id=object_row.object_id, metadata={"seed": 1})
        assert variant.object_id == object_row.object_id
        variants, _ = client.list_variants(generation.generation_id)
        assert [item.variant_id for item in variants] == ["variant-1"]

        task = client.admit_task(capability_id="render.basic", capability_digest=_digest("render.basic"), input_object_ids=[], idempotency_key="domain-task")
        run = client.get_run(task.run_id)
        assert task.task_id in run["task_ids"]
        events = client.list_run_events(task.run_id)
        assert events[0].event_type == "task.admitted" and events[0].sequence < events[-1].sequence + 1
        client.cancel_task(task.task_id, idempotency_key="domain-cancel")

        client.register_executor({"executor_id": "domain-executor", "max_concurrency": 1, "resource_keys": [], "capabilities": [{"capability_id": "render.basic", "definition_digest": _digest("render.basic"), "status": "ready", "required_resource_keys": [], "estimated_scratch_bytes": 0, "estimated_output_bytes": 1}], "protocol": "workspace.v1"}, idempotency_key="domain-executor")
        worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
        failed_task = client.admit_task(capability_id="render.basic", capability_digest=_digest("render.basic"), input_object_ids=[], idempotency_key="failed-domain-task")
        epoch = worker.health().runtime_epoch
        attempt = worker.claim_task(executor_id="domain-executor", capability_ids=["render.basic"], idempotency_key="failed-domain-claim", runtime_epoch=epoch)
        assert attempt is not None
        failed = worker.fail_attempt(attempt["attempt_id"], lease_id=attempt["lease_id"], fence=attempt["fence"], error={"code": "worker_error"}, runtime_epoch=epoch, idempotency_key="failed-domain-settle")
        assert failed.task_id == failed_task.task_id and failed.state == "failed"
        assert client.list_run_events(failed_task.run_id)[-1].event_type == "task.failed"
    finally:
        daemon.stop()


def test_timeline_document_is_one_atomic_runtime_command(tmp_path, monkeypatch):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Composition", idempotency_key="composition-project")
        result = client.create_timeline_document(
            project.project_id,
            "composition",
            config={"tracks": []},
            registry={"assets": {}},
            idempotency_key="composition-timeline",
            slug=None,
            name=None,
        )
        assert result["slug"] == "composition" and result["name"] == "composition"
        assert result["receipt"]["command_kind"] == "timeline_document.create"
        assert len(result["receipt"]["event_ids"]) == 1
        assert client.get_timeline("composition")["config"] == {"tracks": []}

        # Replaying is served by the runtime ledger, not a client repair loop.
        replay = client.create_timeline_document(
            project.project_id,
            "composition",
            config={"tracks": []},
            registry={"assets": {}},
            idempotency_key="composition-timeline",
        )
        assert replay == result
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id='composition'").fetchone()[0] == 1
        assert len(client.list_timelines(project.project_id)[0]) == 1

        original = daemon.service._command_record
        monkeypatch.setattr(daemon.service, "_command_record", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("receipt write failed")))
        with pytest.raises(ApiError):
            client.create_timeline_document(project.project_id, "faulted", config={}, registry={}, idempotency_key="faulted")
        assert daemon.service.store.conn.execute("SELECT 1 FROM timelines WHERE id='faulted'").fetchone() is None
        assert daemon.service.store.conn.execute("SELECT 1 FROM project_documents WHERE id='timeline:faulted'").fetchone() is None
        monkeypatch.setattr(daemon.service, "_command_record", original)
    finally:
        daemon.stop()


def test_timeline_document_replay_survives_runtime_restart(tmp_path):
    root, support = tmp_path / "realm", tmp_path / "support"
    first = RuntimeDaemon(root, support_root=support).start()
    client = WorkspaceClient(first.endpoint, first.token)
    project = client.create_project("Restart", idempotency_key="restart-project")
    result = client.create_timeline_document(project.project_id, "restart-timeline", config={"tracks": []}, registry={}, idempotency_key="restart-timeline")
    first.stop()
    second = RuntimeDaemon(root, support_root=support).start()
    try:
        replay = WorkspaceClient(second.endpoint, second.token).create_timeline_document(project.project_id, "restart-timeline", config={"tracks": []}, registry={}, idempotency_key="restart-timeline")
        assert replay == result
        assert second.service.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id='restart-timeline'").fetchone()[0] == 1
    finally:
        second.stop()


def test_project_media_mutations_roll_back_before_idempotency_replay(tmp_path, monkeypatch):
    service = RuntimeService(tmp_path / "realm")
    project = service.create_project({"slug": "atomic", "name": "Atomic"})
    service.store.record_object("a" * 64, 1, "application/octet-stream")
    service.store.add_object_ref(project["id"], "a" * 64)
    original = service._command_record

    def fail(*args, **kwargs):
        raise RuntimeError("response serialization failed")

    monkeypatch.setattr(service, "_command_record", fail)
    with pytest.raises(RuntimeError):
        service.create_project_shot(project["id"], {"shot_id": "atomic-shot", "name": "Shot"}, idempotency_key="atomic-shot")
    with pytest.raises(RuntimeError):
        service.create_project_reference(project["id"], {"reference_id": "atomic-ref", "kind": "character", "name": "Ref", "media_id": "sha256:" + "a" * 64}, idempotency_key="atomic-ref")
    assert service.store.conn.execute("SELECT 1 FROM project_shots WHERE id='atomic-shot'").fetchone() is None
    assert service.store.conn.execute("SELECT 1 FROM project_references WHERE id='atomic-ref'").fetchone() is None
    monkeypatch.setattr(service, "_command_record", original)
    shot = service.create_project_shot(project["id"], {"shot_id": "atomic-shot", "name": "Shot"}, idempotency_key="atomic-shot")
    assert service.create_project_shot(project["id"], {"shot_id": "atomic-shot", "name": "Shot"}, idempotency_key="atomic-shot") == shot
    service.close()


def test_generated_domains_preserve_project_media_and_timeline_recovery(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        client.handshake("domain-client", "0.1.0", ["projects:read", "projects:write", "objects:read", "objects:write"])
        project = client.create_project("Settings", idempotency_key="project", slug="settings", metadata={"theme": "dark"})
        assert project.slug == "settings" and project.metadata == {"theme": "dark"}
        object_row = client.ingest_project_object(project.project_id, b"managed", media_type="application/octet-stream", idempotency_key="media", filename="managed.bin")
        objects, cursor = client.list_project_objects(project.project_id)
        assert cursor is None and objects[0].object_id == object_row.object_id and objects[0].relation == "managed"

        client.create_document(project.project_id, "settings", "settings", {"theme": "dark"})
        client.create_document(project.project_id, "review", "review", {"approved": False})
        timeline = client.create_timeline(project.project_id, "timeline", idempotency_key="timeline")
        saved = client.update_timeline("timeline", expected_version=1, shots=[{"shot_id": "shot", "start_ms": 0, "duration_ms": 100}])
        history, _ = client.list_timeline_history("timeline")
        assert [item["version"] for item in history] == [1, 2]
        assert client.diff_timeline("timeline", from_version=1, to_version=2)["changes"]["shots"]["added"]
        archived = client.archive_timeline("timeline", expected_version=saved["version"], idempotency_key="archive")
        recovered = client.recover_timeline("timeline", expected_version=archived["version"], version=saved["version"], idempotency_key="recover")
        assert archived["archived"] is True and recovered["archived"] is False and recovered["shots"] == saved["shots"]

        shot = client.create_shot("timeline", {"shot_id": "shot-mounted", "start_ms": 0, "duration_ms": 100, "reference_ids": []}, idempotency_key="shot")
        reference = client.create_reference("timeline", {"reference_id": "reference-mounted", "object_id": object_row.object_id, "role": "source"}, idempotency_key="reference")
        shots, _ = client.list_project_shots(project.project_id)
        references, _ = client.list_project_references(project.project_id)
        assert all(item["shot_id"] != shot["shot_id"] for item in shots)
        assert all(item["reference_id"] != reference["reference_id"] for item in references)
        shot = client.update_shot("shot-mounted", expected_version=1, duration_ms=200)
        reference = client.update_reference("reference-mounted", expected_version=1, role="hero")
        shot = client.archive_shot("shot-mounted", expected_version=shot["version"], idempotency_key="archive-shot")
        reference = client.archive_reference("reference-mounted", expected_version=reference["version"], idempotency_key="archive-reference")
        assert shot["archived"] is True and reference["archived"] is True
        assert all(item["shot_id"] != "shot-mounted" for item in client.list_project_shots(project.project_id)[0])
        assert all(item["shot_id"] != "shot-mounted" for item in client.list_project_shots(project.project_id, include_archived=True)[0])
        shot = client.recover_shot("shot-mounted", expected_version=shot["version"], idempotency_key="recover-shot")
        reference = client.recover_reference("reference-mounted", expected_version=reference["version"], idempotency_key="recover-reference")
        assert shot["archived"] is False and reference["archived"] is False

        second_object = client.ingest_project_object(project.project_id, b"second-managed", media_type="application/octet-stream", idempotency_key="media-2")
        relation = client.create_media_relation(project.project_id, object_row.object_id, second_object.object_id, "derived_from", idempotency_key="relation")
        relations, _ = client.list_media_relations(project.project_id)
        assert relation["kind"] == "derived_from" and relations[0]["to_object_id"] == second_object.object_id

        generation = client.create_generation(project.project_id, "generation")
        client.create_variant(generation.generation_id, "variant")
        assert client.get_variant("variant").generation_id == generation.generation_id

        client.register_capability("render.basic", _digest("render.basic"), idempotency_key="listed-capability")
        task = client.admit_task(capability_id="render.basic", capability_digest=_digest("render.basic"), input_object_ids=[], idempotency_key="listed-task", project_id=project.project_id, spec={"prompt": "listed"})
        tasks, _ = client.list_project_tasks(project.project_id)
        runs, _ = client.list_project_runs(project.project_id)
        assert [item.task_id for item in tasks] == [task.task_id] and runs[0]["id"] == task.run_id
    finally:
        daemon.stop()
