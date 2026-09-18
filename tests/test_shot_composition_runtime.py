from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "composition", "name": "Composition"}, idempotency_key="project")
    service.create_timeline(project["id"], "main", idempotency_key="timeline")
    return service, project["id"]


def _publication(project_id, *, expected_head=None, parent_revision_id="parent-1", shot_revision_id="shot-rev-1", config=None):
    return {
        "project_id": project_id,
        "timeline_id": "main",
        "expected_head": expected_head,
        "parent_revision_id": parent_revision_id,
        "internal_timeline_revisions": [{
            "timeline_id": "main",
            "revision_id": "timeline-rev-1",
            "payload": {"tracks": [], "clips": [], "effects": [], "audio": [], "layout": {}, "registry": {}, "assets": []},
        }],
        "shot_revisions": [{
            "shot_id": "shot-1",
            "revision_id": shot_revision_id,
            "internal_timeline_revision_id": "timeline-rev-1",
            "payload": {"metadata": {"title": "opening"}, "items": [], "pools": [], "selected_variants": {}, "provenance": {}, "generation_inputs": {}, "audio_bindings": [], "text_bindings": []},
        }],
        "parent_composition": {
            "config": config or {},
            "registry": {},
            "clips": [],
            "occurrences": [{
                "occurrence_id": "occurrence-1",
                "shot_id": "shot-1",
                "shot_revision_id": shot_revision_id,
                "placement": {"start_ms": 0},
                "source_offset": 0,
                "duration_ms": 1000,
                "speed": 1,
                "track": "video-1",
                "transform": {},
                "gain": 1,
                "mute": False,
                "provenance": {},
            }],
        },
    }


def test_historical_revision_is_exact_after_mutable_edits(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        first = service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="publish-1")
        updated = service.update_project_shot(project_id, "shot-1", {"expected_version": 1, "name": "edited"}, idempotency_key="edit-shot")
        assert updated["data"]["revision_id"] != first["data"]["revision_id"]
        assert service.store.conn.execute("SELECT revision_id FROM shot_revision_heads WHERE shot_id='shot-1'").fetchone()[0] == updated["data"]["revision_id"]
        reread = service.get_project_shot_revision(project_id, "shot-1", "shot-rev-1")
        assert reread["content_digest"] == first["data"]["content_digests"]["shot-rev-1"]
        assert reread["payload"]["metadata"] == {"title": "opening"}
        assert service.get_project_timeline_revision(project_id, "main", "timeline-rev-1")["payload"]["layout"] == {}
    finally:
        service.close()


def test_parent_revision_and_head_reads_and_linked_reuse_do_not_regress_child_head(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        first = service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="publish-1")
        parent = service.get_project_parent_composition_revision(project_id, "main", "parent-1")
        assert parent["content_digest"] == first["data"]["content_digest"]
        assert service._timeline_resource("main")["head_revision_id"] == "parent-1"

        reused = _publication(project_id, expected_head="parent-1", parent_revision_id="parent-2")
        second = service.publish_parent_composition(project_id, "main", reused, idempotency_key="publish-2")
        assert second["data"]["new_head"] == "parent-2"
        assert service.store.conn.execute("SELECT revision_id FROM shot_revision_heads WHERE shot_id='shot-1'").fetchone()[0] == "shot-rev-1"
    finally:
        service.close()


def test_integrity_report_detects_revision_digest_tampering(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="publish-1")
        service.store.conn.execute("UPDATE parent_composition_revisions SET content_digest='sha256:' || printf('%064d', 0) WHERE id='parent-1'")
        report = service.store.integrity_report()
        assert report["ok"] is False
        assert "revisions" in report["issues"]
        assert any(error["reason"] == "content_digest_mismatch" for error in report["checks"]["revisions"]["errors"])
    finally:
        service.close()


def test_stale_publication_rolls_back_and_retry_conflicts(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        first = service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="publish-1")
        before = {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("shot_revisions", "internal_timeline_revisions", "parent_composition_revisions", "timeline_events", "command_idempotency")}
        stale = _publication(project_id, expected_head=None, parent_revision_id="parent-2", shot_revision_id="shot-rev-2", config={"changed": True})
        with pytest.raises(ConflictError, match="stale"):
            service.publish_parent_composition(project_id, "main", stale, idempotency_key="publish-2")
        after = {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in before}
        assert after == before
        assert service.store.conn.execute("SELECT revision_id FROM parent_composition_heads WHERE timeline_id='main'").fetchone()[0] == first["data"]["new_head"]
        with pytest.raises(ConflictError, match="different input"):
            service.publish_parent_composition(project_id, "main", _publication(project_id, parent_revision_id="parent-1", config={"different": True}), idempotency_key="publish-1")
    finally:
        service.close()


def test_same_head_concurrent_publishers_have_one_winner(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        def publish(index):
            body = _publication(project_id, parent_revision_id=f"parent-{index}", shot_revision_id=f"shot-rev-{index}")
            try:
                return service.publish_parent_composition(project_id, "main", body, idempotency_key=f"publish-{index}")
            except ConflictError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(publish, (1, 2)))
        assert sum(value is not None for value in results) == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM parent_composition_revisions").fetchone()[0] == 1
    finally:
        service.close()


def test_dependency_scope_and_nesting_are_rejected(tmp_path):
    service, project_id = _service(tmp_path)
    other_project = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="other-project")["id"]
    service.create_timeline(other_project, "other", idempotency_key="other-timeline")
    try:
        missing = _publication(project_id)
        missing["parent_composition"]["occurrences"][0]["shot_revision_id"] = "does-not-exist"
        with pytest.raises(NotFoundError, match="dependency"):
            service.publish_parent_composition(project_id, "main", missing, idempotency_key="missing")

        nested = _publication(project_id, parent_revision_id="nested")
        nested["internal_timeline_revisions"][0]["payload"]["occurrences"] = []
        with pytest.raises(ValidationError, match="nested"):
            service.publish_parent_composition(project_id, "main", nested, idempotency_key="nested")

        service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="base")
        cross_project = _publication(other_project, parent_revision_id="cross", shot_revision_id="shot-rev-cross")
        cross_project["timeline_id"] = "other"
        cross_project["shot_revisions"][0]["shot_id"] = "shot-1"
        cross_project["parent_composition"]["occurrences"][0]["shot_id"] = "shot-1"
        with pytest.raises(ConflictError, match="different project"):
            service.publish_parent_composition(other_project, "other", cross_project, idempotency_key="cross")
    finally:
        service.close()


def test_failure_injection_rolls_back_every_publication_write(tmp_path, monkeypatch):
    service, project_id = _service(tmp_path)
    try:
        command_count = service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0]
        baseline = {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("shot_revisions", "internal_timeline_revisions", "parent_composition_revisions", "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences", "composition_revision_dependencies")}
        monkeypatch.setattr(service.store, "_append_timeline_event", lambda *args: (_ for _ in ()).throw(RuntimeError("injected")))
        with pytest.raises(RuntimeError, match="injected"):
            service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="injected")
        for table in ("shot_revisions", "internal_timeline_revisions", "parent_composition_revisions", "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences", "composition_revision_dependencies"):
            assert service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == baseline[table]
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0] == command_count
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id='main'").fetchone()[0] == 1
    finally:
        service.close()
