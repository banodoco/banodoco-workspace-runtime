from __future__ import annotations

import hashlib

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


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
        attempt = worker.claim_task(executor_id="domain-executor", capability_ids=["render.basic"], idempotency_key="failed-domain-claim")
        assert attempt is not None
        failed = worker.fail_attempt(attempt["attempt_id"], lease_id=attempt["lease_id"], fence=attempt["fence"], error={"code": "worker_error"}, idempotency_key="failed-domain-settle")
        assert failed.task_id == failed_task.task_id and failed.state == "failed"
        assert client.list_run_events(failed_task.run_id)[-1].event_type == "task.failed"
    finally:
        daemon.stop()


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
        assert any(item["shot_id"] == shot["shot_id"] for item in shots) and any(item["reference_id"] == reference["reference_id"] for item in references)
        shot = client.update_shot("shot-mounted", expected_version=1, duration_ms=200)
        reference = client.update_reference("reference-mounted", expected_version=1, role="hero")
        shot = client.archive_shot("shot-mounted", expected_version=shot["version"], idempotency_key="archive-shot")
        reference = client.archive_reference("reference-mounted", expected_version=reference["version"], idempotency_key="archive-reference")
        assert shot["archived"] is True and reference["archived"] is True
        assert all(item["shot_id"] != "shot-mounted" for item in client.list_project_shots(project.project_id)[0])
        assert any(item["shot_id"] == "shot-mounted" and item["archived"] is True for item in client.list_project_shots(project.project_id, include_archived=True)[0])
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
