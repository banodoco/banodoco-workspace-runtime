"""Neutral runtime acceptance coverage for invariants formerly tested locally.

These tests intentionally use the generated client or the public HTTP helper.
They exercise the runtime as the sole authority rather than reaching through
its SQLite implementation.
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def test_project_idempotency_mismatch_has_no_second_project(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        first = client.create_project("Authoritative", slug="authoritative", idempotency_key="project")
        with pytest.raises(ApiError) as mismatch:
            client.create_project("Changed", slug="authoritative", idempotency_key="project")
        assert mismatch.value.status == 409
        projects, cursor = client.list_projects()
        assert cursor is None
        assert [(project.slug, project.name) for project in projects] == [("authoritative", "Authoritative")]
        assert client.get_project(first.project_id).version == 1
    finally:
        daemon.stop()


def test_project_media_relation_rejects_foreign_object_without_relation(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        left = client.create_project("Left", slug="left", idempotency_key="left")
        right = client.create_project("Right", slug="right", idempotency_key="right")
        left_object = client.ingest_project_object(left.project_id, b"left", media_type="application/octet-stream", idempotency_key="left-object")
        right_object = client.ingest_project_object(right.project_id, b"right", media_type="application/octet-stream", idempotency_key="right-object")

        with pytest.raises(ApiError) as foreign:
            client.create_media_relation(left.project_id, left_object.object_id, right_object.object_id, "derived_from", idempotency_key="foreign-relation")
        assert foreign.value.status in {400, 404, 409}
        relations, cursor = client.list_media_relations(left.project_id)
        assert relations == [] and cursor is None
        left_objects, _ = client.list_project_objects(left.project_id)
        right_objects, _ = client.list_project_objects(right.project_id)
        assert [item.object_id for item in left_objects] == [left_object.object_id]
        assert [item.object_id for item in right_objects] == [right_object.object_id]
    finally:
        daemon.stop()


def test_concurrent_task_replay_fans_in_to_one_runtime_admission(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Fanout", slug="fanout", idempotency_key="fanout-project")
        digest = _digest("render.basic")

        def admit(_: int):
            return WorkspaceClient(daemon.endpoint, daemon.token).admit_task(
                capability_id="render.basic",
                capability_digest=digest,
                input_object_ids=[],
                project_id=project.project_id,
                spec={"prompt": "same"},
                idempotency_key="fanout-task",
            )

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(admit, range(6)))
        assert {(item.task_id, item.run_id) for item in results} == {(results[0].task_id, results[0].run_id)}
        tasks, cursor = client.list_project_tasks(project.project_id)
        runs, run_cursor = client.list_project_runs(project.project_id)
        assert cursor is None and run_cursor is None
        assert [item.task_id for item in tasks] == [results[0].task_id]
        assert [item["id"] for item in runs] == [results[0].run_id]
    finally:
        daemon.stop()


def test_http_digest_mismatch_fails_before_project_media_publication(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = Api(daemon.endpoint, daemon.token)
        project = client.create_project("Digest", "Digest", idempotency_key="digest-project")
        expected = _digest("different-bytes")
        with pytest.raises(RuntimeError) as mismatch:
            client.ingest(project["project_id"], b"actual-bytes", expected_digest=expected)
        assert "digest" in str(mismatch.value).lower()
        assert client.request("GET", f"/v1/projects/{project['project_id']}/objects")["items"] == []
    finally:
        daemon.stop()
