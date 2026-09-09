from __future__ import annotations

import json
import urllib.request

import pytest

from banodoco_workspace_client import WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, NotFoundError
from runtime_protocol.service import RuntimeService


def _composition(asset_id: str = "old") -> tuple[dict, dict]:
    return (
        {
            "tracks": [{"id": "visual", "kind": "visual"}],
            "clips": [
                {"id": "target", "track": "visual", "clipType": "video", "asset": asset_id, "at": 2, "from": 1, "to": 4, "effects": [{"id": "grade"}]},
                {"id": "untouched", "track": "visual", "clipType": "text", "at": 8, "text": "keep me"},
            ],
            "metadata": {"keep": True},
        },
        {"assets": {asset_id: {"media_id": "sha256:" + "0" * 64, "type": "video/mp4"}}, "metadata": {"keep": True}},
    )


def _service_fixture(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    project = service.create_project({"slug": "replace", "name": "Replace"})
    config, registry = _composition()
    service.create_timeline_document(
        project["id"],
        {"timeline_id": "main", "slug": "main", "name": "Main", "config": config, "registry": registry},
        idempotency_key="timeline-create",
    )
    source = service.ingest(project["id"], b"replacement", media_type="video/mp4", idempotency_key="source")
    return service, project, config, registry, source["data"]["object_id"]


def test_replace_timeline_clip_is_atomic_cas_and_exactly_replayable(tmp_path, monkeypatch):
    service, project, before_config, before_registry, source_id = _service_fixture(tmp_path)
    try:
        body = {"clip_id": "target", "source_object_id": source_id, "expected_version": 1, "timing": "preserve-duration"}
        replaced = service.replace_timeline_clip("main", body, idempotency_key="replace")
        assert replaced["receipt"]["command_kind"] == "timeline.clip.replace"
        assert replaced["receipt"]["event_ids"]
        assert replaced["data"]["config_version"] == 2
        assert replaced["data"]["config"]["clips"][0] == {**before_config["clips"][0], "asset": source_id}
        assert replaced["data"]["config"]["clips"][1] == before_config["clips"][1]
        assert replaced["data"]["registry"]["metadata"] == before_registry["metadata"]
        assert replaced["data"]["registry"]["assets"]["old"] == before_registry["assets"]["old"]
        assert service.replace_timeline_clip("main", body, idempotency_key="replace") == replaced

        with pytest.raises(ConflictError, match="different input"):
            service.replace_timeline_clip("main", {**body, "clip_id": "untouched"}, idempotency_key="replace")
        with pytest.raises(ConflictError, match="version conflict"):
            service.replace_timeline_clip("main", {**body, "expected_version": 1}, idempotency_key="stale")

        original = service._command_record
        monkeypatch.setattr(service, "_command_record", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("receipt failed")))
        with pytest.raises(RuntimeError, match="receipt failed"):
            service.replace_timeline_clip("main", {**body, "expected_version": 2}, idempotency_key="atomic")
        monkeypatch.setattr(service, "_command_record", original)
        assert service._timeline_resource("main")["config_version"] == 2
    finally:
        service.close()


def test_replace_timeline_clip_rejects_cross_project_source(tmp_path):
    service, _, _, _, _ = _service_fixture(tmp_path)
    try:
        other = service.create_project({"slug": "other", "name": "Other"})
        foreign = service.ingest(other["id"], b"foreign", media_type="video/mp4", idempotency_key="foreign")["data"]["object_id"]
        with pytest.raises(NotFoundError, match="timeline project"):
            service.replace_timeline_clip("main", {"clip_id": "target", "source_object_id": foreign, "expected_version": 1}, idempotency_key="cross-project")
        assert service._timeline_resource("main")["config_version"] == 1
    finally:
        service.close()


def test_replace_timeline_clip_public_http_route(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("HTTP", slug="http", idempotency_key="project")
        config, registry = _composition()
        client.create_timeline_document(project.project_id, "main", config=config, registry=registry, idempotency_key="timeline")
        source = client.ingest_project_object(project.project_id, b"http-source", media_type="video/mp4", idempotency_key="source")
        request = urllib.request.Request(
            f"{daemon.endpoint}/v1/timelines/main/replace-clip",
            data=json.dumps({"clip_id": "target", "source_object_id": source.object_id, "expected_version": 1}).encode(),
            method="POST",
            headers={"Authorization": f"Bearer {daemon.token}", "Content-Type": "application/json", "Idempotency-Key": "replace"},
        )
        with urllib.request.urlopen(request) as response:
            value = json.loads(response.read())
        assert value["data"]["config"]["clips"][0]["asset"] == source.object_id
        assert value["receipt"]["command_kind"] == "timeline.clip.replace"
    finally:
        daemon.stop()
