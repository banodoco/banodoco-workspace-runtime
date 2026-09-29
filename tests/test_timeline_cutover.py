from __future__ import annotations

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_cutover import audit_active_timeline_heads
from tests.http_helpers import Api


def _publication(project: str) -> dict:
    return {
        "project_id": project,
        "timeline_id": "main",
        "expected_head": None,
        "parent_revision_id": "parent-1",
        "internal_timeline_revisions": [{
            "timeline_id": "main",
            "revision_id": "internal-1",
            "payload": {
                "clips": [{"id": "media-1", "clip_type": "media", "track": "picture", "at_ms": 0, "duration_ms": 1000}],
                "tracks": [{"id": "picture"}], "registry": {}, "audio": [],
            },
        }],
        "shot_revisions": [{
            "shot_id": "shot-1", "revision_id": "shot-rev-1",
            "internal_timeline_revision_id": "internal-1",
            "payload": {"name": "Canonical opening", "assets": [], "audio_bindings": [], "text_bindings": []},
        }],
        "parent_composition": {
            "config": {},
            "registry": {},
            "clips": [{"id": "effect-code", "clip_type": "effect", "track": "effects", "at_ms": 0, "duration_ms": 1000, "parameters": {"opacity": 0.5}}],
            "occurrences": [{
                "occurrence_id": "occ-1", "shot_id": "shot-1", "shot_revision_id": "shot-rev-1",
                "placement": {"start_ms": 0}, "duration_ms": 1000, "source_offset": 0,
                "speed": 1, "track": "picture", "transform": {}, "gain": 1,
                "mute": False, "provenance": {},
            }],
        },
    }


def _service(tmp_path):
    from runtime_protocol.service import RuntimeService

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "cutover", "name": "Cutover"}, idempotency_key="project")
    service.create_timeline_document(
        project["id"],
        {
            "timeline_id": "main", "slug": "main", "name": "Main",
            "config": {"clips": [{"id": "legacy-shell", "clipType": "shot", "at": 0, "hold": 1, "params": {"shot_id": "shot-1", "timeline_document_id": "child-1"}}], "pinnedShotGroups": [{"id": "legacy-group", "clipIds": ["legacy-shell"]}]},
            "registry": {},
        },
        idempotency_key="timeline",
    )
    service.publish_parent_composition(project["id"], "main", _publication(project["id"]), idempotency_key="publish")
    return service, project["id"], root


def test_active_head_audit_reports_canonical_closure_and_legacy_shell(tmp_path):
    service, project_id, _ = _service(tmp_path)
    try:
        report = audit_active_timeline_heads(service.store.conn, project_id=project_id)
        assert report["schema"] == "runtime.timeline.active-head-audit/v1"
        assert report["status"] == "ok"
        assert report["migration_required_count"] == 1
        item = report["items"][0]
        assert item["status"] == "migration_required"
        assert item["canonical_head"]["revision_id"] == "parent-1"
        assert item["closure"]["occurrences"][0]["name"] == "Canonical opening"
        assert item["closure"]["parent_clip_count"] == 1
        assert item["legacy"]["clip_type_shot_count"] == 1
        assert item["legacy"]["pinned_group_count"] == 1
    finally:
        service.close()


def test_active_head_audit_accepts_canonical_cutover_tombstone(tmp_path):
    service, project_id, _ = _service(tmp_path)
    try:
        service.store.conn.execute(
            "UPDATE project_documents SET content_json=?, version=? WHERE id=? AND project_id=?",
            ('{"canonical_cutover":{"head_revision_id":"parent-1","replacement":"inspectTimeline"}}',
             2, "timeline:main", project_id),
        )
        report = audit_active_timeline_heads(service.store.conn, project_id=project_id)
        assert report["status"] == "ok"
        assert report["migration_required_count"] == 0
        item = report["items"][0]
        assert item["status"] == "available"
        assert item["legacy"]["cutover"] == "canonical_head_tombstone"
        assert item["legacy"]["canonical_head_revision_id"] == "parent-1"
    finally:
        service.close()


def test_public_timeline_document_routes_are_retired(tmp_path):
    service, project_id, root = _service(tmp_path)
    service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        api = Api(daemon.endpoint, daemon.token)
        for method, route, body in (
            ("GET", f"/v1/projects/{project_id}/timelines/main", None),
            ("POST", f"/v1/projects/{project_id}/timeline-documents", {"timeline_id": "other", "config": {}, "registry": {}}),
            ("GET", f"/v1/projects/{project_id}/documents/timeline:main", None),
            ("PATCH", f"/v1/projects/{project_id}/documents/timeline:main", {"expected_version": 1, "content": {}}),
        ):
            with pytest.raises(RuntimeError) as error:
                api.request(method, route, body)
            assert error.value.status == 410
    finally:
        daemon.stop()
