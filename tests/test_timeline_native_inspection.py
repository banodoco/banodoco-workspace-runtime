from __future__ import annotations

import sys
from pathlib import Path

import pytest

from runtime_protocol.errors import NotFoundError, ValidationError
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import WorkspaceClient


def _service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "views", "name": "Views"}, idempotency_key="project")
    service.create_timeline(project["id"], "main", idempotency_key="timeline")
    return service, project["id"], root


def _publication(project, *, revision="parent-1", expected_head=None, offset=0):
    occurrence = lambda suffix, start: {
        "occurrence_id": suffix, "shot_id": "shot-1", "shot_revision_id": "shot-rev-1",
        "placement": {"start_ms": start}, "duration_ms": 1000, "source_offset": 0,
        "speed": 1, "track": "picture", "transform": {}, "gain": 1,
        "mute": False, "provenance": {},
    }
    return {
        "project_id": project, "timeline_id": "main", "expected_head": expected_head,
        "parent_revision_id": revision,
        "internal_timeline_revisions": [{
            "timeline_id": "main", "revision_id": "internal-1",
            "payload": {"tracks": [{"id": "picture"}], "clips": [
                {"id": "caption", "clip_type": "text", "track": "picture", "at_ms": 125,
                 "duration_ms": 500, "text": "A | <B>"}], "effects": [], "audio": [],
                "layout": {}, "registry": {}, "assets": []},
        }],
        "shot_revisions": [{
            "shot_id": "shot-1", "revision_id": "shot-rev-1", "internal_timeline_revision_id": "internal-1",
            "payload": {"metadata": {"title": "opening"}, "items": [], "pools": [],
                        "selected_variants": {}, "provenance": {}, "generation_inputs": {},
                        "audio_bindings": [], "text_bindings": []},
        }],
        "parent_composition": {"config": {}, "registry": {}, "clips": [],
                               "occurrences": [occurrence("first", offset), occurrence("second", offset + 1000),
                                               occurrence("third", offset + 2000)]},
    }


def test_pinned_inspection_and_neighbor_order(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish-1")
        first = service.inspect_timeline(project, "main", {"occurrence": "second", "neighbors": 1})
        assert first["revision_id"] == "parent-1"
        assert [row["occurrence"]["occurrence_id"] for row in first["selected"]] == ["first", "second", "third"]
        assert [row["role"] for row in first["selected"]] == ["neighbor", "target", "neighbor"]
        assert first["selected"][1]["clips"][0]["start"] == [9, 8]
        assert first["selected"][1]["clips"][0]["duration"] == [1, 2]

        later = _publication(project, revision="parent-2", expected_head="parent-1", offset=5000)
        later.pop("internal_timeline_revisions")
        later.pop("shot_revisions")
        service.publish_parent_composition(project, "main", later, idempotency_key="publish-2")
        pinned = service.inspect_timeline(project, "main", {"revision_id": "parent-1", "occurrence": "second"})
        current = service.inspect_timeline(project, "main", {"occurrence": "second"})
        assert pinned["snapshot_digest"] == first["snapshot_digest"]
        assert pinned["selected"][0]["clips"][0]["start"] == [9, 8]
        assert current["selected"][0]["clips"][0]["start"] == [49, 8]
        assert current["snapshot_digest"] != pinned["snapshot_digest"]
    finally:
        service.close()


def test_selector_miss_validation_and_project_scope(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish-1")
        missing = service.inspect_timeline(project, "main", {"occurrence": "missing", "neighbors": 2})
        assert missing["selection_status"] == "selector_miss"
        assert missing["selected"] == []
        assert service.inspect_timeline(project, "main", {"clip": "caption", "range": "1..2"})["target_count"] == 1
        with pytest.raises(ValidationError):
            service.inspect_timeline(project, "main", {"neighbors": 3})
        with pytest.raises(ValidationError):
            service.inspect_timeline(project, "main", {"range": "2..1"})
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign")
        with pytest.raises(NotFoundError):
            service.inspect_timeline(foreign["id"], "main", {})
    finally:
        service.close()


def test_markdown_png_custody_and_dedup(tmp_path):
    service, project, root = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish-1")
        options = {"occurrence": "second", "neighbors": 1, "formats": ["md", "png"]}
        result = service.create_timeline_view(project, "main", options)
        again = service.create_timeline_view(project, "main", options)
        assert result["artifacts"]["md"] == again["artifacts"]["md"]
        assert result["formats"]["png"]["status"] == "available"
        object_id = result["artifacts"]["md"]["object_id"]
        assert service.object_location(project, object_id)["verified"] is True
        _, content = service.object(object_id)
        assert b"Parent revision: parent-1" in content
        assert b"first" in content and b"second" in content and b"third" in content
        assert b"A &#124; &lt;B&gt;" in content
        png_id = result["artifacts"]["png"]["object_id"]
        assert service.object(png_id)[1].startswith(b"\x89PNG\r\n\x1a\n")
        assert "png" in service.create_timeline_view(project, "main", {"formats": ["png"]})["artifacts"]
    finally:
        service.close()
    reopened = RuntimeService(root)
    try:
        assert reopened.object_location(project, object_id)["verified"] is True
        assert reopened.object(object_id)[1] == content
        assert reopened.object_location(project, png_id)["verified"] is True
    finally:
        reopened.close()


def test_daemon_generated_client_without_executor_catalog(tmp_path):
    service, project, root = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish-1")
    finally:
        service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        inspection = client.inspect_timeline(project, "main", {"occurrence": "second", "neighbors": 1})
        assert inspection["revision_id"] == "parent-1"
        view = client.create_timeline_view(project, "main", {"occurrence": "second", "formats": ["md", "png"]})
        assert view["formats"]["png"]["status"] == "available"
        assert b"second" in client.get_object(view["artifacts"]["md"]["object_id"]).data
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    finally:
        daemon.stop()
