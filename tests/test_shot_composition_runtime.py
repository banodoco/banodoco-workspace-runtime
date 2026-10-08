from __future__ import annotations

import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json


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
            # Integrity/CAS tests need a valid admitted picture closure. Empty
            # children are independently covered by seam rejection tests.
            "payload": {"tracks": [], "clips": [{"id": "picture", "clipType": "media", "at": 0, "hold": 1, "track": "video-1"}], "effects": [], "audio": [], "layout": {}, "registry": {}, "assets": []},
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


def _publish_with_explicit_media(service, project_id, *, parent_revision_id="parent-media"):
    scene = service.ingest(
        project_id, b'{"schema":"live-scene-package/v1"}',
        media_type="application/json", original_name="scene.json",
        idempotency_key="scene-package",
    )["data"]["object_id"]
    audio = service.ingest(
        project_id, b"audio-object", media_type="audio/wav",
        original_name="tone.wav", idempotency_key="audio-object",
    )["data"]["object_id"]
    body = _explicit_media_publication(project_id, scene, audio, parent_revision_id=parent_revision_id)
    result = service.publish_parent_composition(
        project_id, "main", body, idempotency_key=f"publish-{parent_revision_id}"
    )
    return result, scene, audio


def _explicit_media_publication(project_id, scene, audio, *, parent_revision_id="parent-media"):
    body = _publication(project_id, parent_revision_id=parent_revision_id)
    body["parent_composition"]["config"]["clips"] = [{
        "clipType": "com.reigh.astrid.liveScene",
        "app": {"liveScene": {"revision": scene, "source": {"objectId": scene, "revision": scene}}},
    }]
    body["dependency_manifest"] = {"media": [
        {"media_id": scene, "content_digest": scene},
        {"media_id": audio, "content_digest": audio},
    ]}
    return body


def _revision_errors(report):
    return report["checks"]["revisions"]["errors"]


def _rehash_timeline_events(service, timeline_id, *, replacements=None):
    replacements = replacements or {}
    previous = ""
    rows = service.store.conn.execute(
        "SELECT id, kind, payload_json, created_at FROM timeline_events WHERE timeline_id=? ORDER BY id",
        (timeline_id,),
    ).fetchall()
    for row in rows:
        payload = replacements.get(row["id"], json.loads(row["payload_json"]))
        event_hash = hashlib.sha256(canonical_json({
            "timeline_id": timeline_id,
            "kind": row["kind"],
            "payload": payload,
            "previous_hash": previous,
            "created_at": row["created_at"],
        }).encode()).hexdigest()
        service.store.conn.execute(
            "UPDATE timeline_events SET payload_json=?, previous_hash=?, event_hash=? WHERE id=?",
            (canonical_json(payload), previous, event_hash, row["id"]),
        )
        previous = event_hash


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


def test_occurrence_only_linked_reuse_resolves_committed_child_closure(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        first = service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="publish-1")
        reused = _publication(project_id, expected_head="parent-1", parent_revision_id="parent-2")
        reused.pop("shot_revisions")
        reused.pop("internal_timeline_revisions")
        second = service.publish_parent_composition(project_id, "main", reused, idempotency_key="publish-2")

        assert second["data"]["dependency_manifest"] == first["data"]["dependency_manifest"]
        rows = service.store.conn.execute(
            "SELECT dependency_kind, dependency_id FROM composition_revision_dependencies WHERE parent_revision_id=? ORDER BY ordinal",
            ("parent-2",),
        ).fetchall()
        assert [(row["dependency_kind"], row["dependency_id"]) for row in rows] == [
            ("shot_revision", "shot-rev-1"),
            ("internal_timeline_revision", "timeline-rev-1"),
        ]
    finally:
        service.close()


def test_integrity_report_detects_occurrence_order_tampering(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        body = _publication(project_id)
        second = copy.deepcopy(body["parent_composition"]["occurrences"][0])
        second["occurrence_id"] = "occurrence-2"
        second["placement"] = {"start_ms": 1000}
        body["parent_composition"]["occurrences"].append(second)
        service.publish_parent_composition(project_id, "main", body, idempotency_key="publish-1")
        service.store.conn.execute(
            "UPDATE composition_revision_occurrences SET ordinal=CASE occurrence_id WHEN 'occurrence-1' THEN 1 ELSE 0 END WHERE parent_revision_id='parent-1'"
        )
        report = service.store.integrity_report()
        assert report["ok"] is False
        assert any(error["reason"] == "occurrence_sequence_mismatch" for error in report["checks"]["revisions"]["errors"])
    finally:
        service.close()


def test_integrity_report_detects_occurrence_identity_tampering(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="publish-1")
        service.store.conn.execute(
            "UPDATE composition_revision_occurrences SET occurrence_id='tampered' WHERE parent_revision_id='parent-1'"
        )
        report = service.store.integrity_report()
        assert report["ok"] is False
        assert any(error["reason"] in {"occurrence_missing", "occurrence_extra", "occurrence_sequence_mismatch"} for error in report["checks"]["revisions"]["errors"])
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


def test_integrity_report_accepts_media_pinned_by_publication_evidence(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _publish_with_explicit_media(service, project_id)
        report = service.store.integrity_report()
        assert report["ok"] is True, report["checks"]["revisions"]["errors"]
        assert report["checks"]["event_chain"]["ok"] is True
    finally:
        service.close()


def test_integrity_report_rejects_undeclared_media_dependency(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _publish_with_explicit_media(service, project_id)
        extra = service.ingest(
            project_id, b"undeclared-object", media_type="application/octet-stream",
            idempotency_key="undeclared-object",
        )["data"]["object_id"]
        service.store.conn.execute(
            "INSERT INTO composition_revision_dependencies(parent_revision_id, dependency_kind, dependency_id, content_digest, ordinal) VALUES (?, 'media', ?, ?, 2)",
            ("parent-media", extra, extra),
        )
        report = service.store.integrity_report()
        assert any(error["reason"] == "dependency_graph_mismatch" for error in _revision_errors(report)), _revision_errors(report)
    finally:
        service.close()


def test_integrity_report_rejects_missing_manifest_media_dependency(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _, _, audio = _publish_with_explicit_media(service, project_id)
        service.store.conn.execute(
            "DELETE FROM composition_revision_dependencies WHERE parent_revision_id=? AND dependency_id=?",
            ("parent-media", audio),
        )
        report = service.store.integrity_report()
        assert any(error["reason"] == "dependency_graph_mismatch" for error in _revision_errors(report))
    finally:
        service.close()


def test_integrity_report_rejects_wrong_project_media_dependency(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _, _, audio = _publish_with_explicit_media(service, project_id)
        other = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="other-project")
        foreign = service.ingest(
            other["id"], b"foreign-object", media_type="application/octet-stream",
            idempotency_key="foreign-object",
        )["data"]["object_id"]
        service.store.conn.execute(
            "UPDATE composition_revision_dependencies SET dependency_id=?, content_digest=? WHERE parent_revision_id=? AND dependency_id=?",
            (foreign, foreign, "parent-media", audio),
        )
        report = service.store.integrity_report()
        assert any(error["reason"] == "dependency_closure" for error in _revision_errors(report))
    finally:
        service.close()


def test_integrity_report_rejects_dependency_digest_mismatch(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _, scene, _ = _publish_with_explicit_media(service, project_id)
        service.store.conn.execute(
            "UPDATE composition_revision_dependencies SET content_digest=? WHERE parent_revision_id=? AND dependency_id=?",
            ("sha256:" + "0" * 64, "parent-media", scene),
        )
        report = service.store.integrity_report()
        assert any(error["reason"] == "dependency_closure" for error in _revision_errors(report))
    finally:
        service.close()


@pytest.mark.parametrize("tamper", ["duplicate", "noncontiguous"])
def test_integrity_report_rejects_duplicate_or_noncontiguous_dependencies(tmp_path, tamper):
    service, project_id = _service(tmp_path)
    try:
        _, scene, audio = _publish_with_explicit_media(service, project_id)
        if tamper == "duplicate":
            service.store.conn.execute(
                "INSERT INTO composition_revision_dependencies(parent_revision_id, dependency_kind, dependency_id, content_digest, ordinal) VALUES (?, 'media', ?, ?, 2)",
                ("parent-media", scene, scene),
            )
        else:
            service.store.conn.execute(
                "UPDATE composition_revision_dependencies SET ordinal=4 WHERE parent_revision_id=? AND dependency_id=?",
                ("parent-media", audio),
            )
        report = service.store.integrity_report()
        assert any(error["reason"] == "dependency_graph_mismatch" for error in _revision_errors(report)), _revision_errors(report)
    finally:
        service.close()


def test_integrity_report_rejects_inconsistent_publication_evidence(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _publish_with_explicit_media(service, project_id)
        event = service.store.conn.execute(
            "SELECT id, payload_json FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published'",
            ("main",),
        ).fetchone()
        payload = json.loads(event["payload_json"])
        payload["dependency_manifest"]["media"].pop()
        _rehash_timeline_events(service, "main", replacements={event["id"]: payload})
        report = service.store.integrity_report()
        assert report["checks"]["event_chain"]["ok"] is True
        assert any(error["reason"] == "publication_evidence_mismatch" for error in _revision_errors(report))
    finally:
        service.close()


def test_integrity_report_rejects_manifest_receipt_paired_with_manifestless_event(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _publish_with_explicit_media(service, project_id)
        event = service.store.conn.execute(
            "SELECT id, payload_json FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published'",
            ("main",),
        ).fetchone()
        payload = json.loads(event["payload_json"])
        del payload["dependency_manifest"]
        _rehash_timeline_events(service, "main", replacements={event["id"]: payload})
        report = service.store.integrity_report()
        assert report["checks"]["event_chain"]["ok"] is True
        assert any(error["reason"] == "publication_evidence_mismatch" for error in _revision_errors(report)), _revision_errors(report)
    finally:
        service.close()


def test_integrity_report_does_not_trust_manifest_without_publication_event(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _publish_with_explicit_media(service, project_id)
        service.store.conn.execute(
            "DELETE FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published'",
            ("main",),
        )
        report = service.store.integrity_report()
        assert any(error["reason"] == "publication_evidence_mismatch" for error in _revision_errors(report))
    finally:
        service.close()


def test_integrity_report_rejects_receipt_for_missing_event_even_without_manifest_rows(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _, scene, audio = _publish_with_explicit_media(service, project_id)
        service.store.conn.execute(
            "DELETE FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published'",
            ("main",),
        )
        service.store.conn.execute(
            "DELETE FROM composition_revision_dependencies WHERE parent_revision_id=? AND dependency_id IN (?, ?)",
            ("parent-media", scene, audio),
        )
        report = service.store.integrity_report()
        assert any(error["reason"] == "publication_evidence_mismatch" for error in _revision_errors(report)), _revision_errors(report)
        assert not any(error["reason"] == "dependency_graph_mismatch" for error in _revision_errors(report)), _revision_errors(report)
    finally:
        service.close()


def test_integrity_report_keeps_payload_only_legacy_closure_without_event(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="publish-legacy")
        service.store.conn.execute(
            "DELETE FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published'",
            ("main",),
        )
        service.store.conn.execute(
            "DELETE FROM command_idempotency WHERE command_kind=? AND aggregate_id=?",
            ("parent_composition.publish", "main"),
        )
        report = service.store.integrity_report()
        assert report["ok"] is True, report["checks"]["revisions"]["errors"]
    finally:
        service.close()


def test_integrity_report_accepts_identical_parent_republished_with_new_key(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _, scene, audio = _publish_with_explicit_media(service, project_id)
        body = _explicit_media_publication(project_id, scene, audio)
        body["expected_head"] = "parent-media"
        service.publish_parent_composition(
            project_id, "main", body, idempotency_key="publish-parent-media-again"
        )
        report = service.store.integrity_report()
        assert report["ok"] is True, report["checks"]["revisions"]["errors"]
    finally:
        service.close()


def test_integrity_report_rejects_conflicting_repeat_publication_manifests(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        _, scene, audio = _publish_with_explicit_media(service, project_id)
        body = _explicit_media_publication(project_id, scene, audio)
        body["expected_head"] = "parent-media"
        service.publish_parent_composition(
            project_id, "main", body, idempotency_key="publish-parent-media-conflict"
        )
        event = service.store.conn.execute(
            "SELECT id, payload_json FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published' ORDER BY id DESC LIMIT 1",
            ("main",),
        ).fetchone()
        event_payload = json.loads(event["payload_json"])
        event_payload["dependency_manifest"]["media"].pop()
        _rehash_timeline_events(service, "main", replacements={event["id"]: event_payload})
        receipt = service.store.conn.execute(
            "SELECT idempotency_key, result_json FROM command_idempotency WHERE command_kind=? AND idempotency_key=?",
            ("parent_composition.publish", "publish-parent-media-conflict"),
        ).fetchone()
        result = json.loads(receipt["result_json"])
        result["dependency_manifest"] = event_payload["dependency_manifest"]
        service.store.conn.execute(
            "UPDATE command_idempotency SET result_json=? WHERE command_kind=? AND idempotency_key=?",
            (canonical_json(result), "parent_composition.publish", receipt["idempotency_key"]),
        )
        report = service.store.integrity_report()
        assert report["checks"]["event_chain"]["ok"] is True
        assert any(error["reason"] == "publication_evidence_mismatch" for error in _revision_errors(report)), _revision_errors(report)
    finally:
        service.close()


def test_integrity_report_checks_timeline_event_hash_chain(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="publish-chain")
        event_id = service.store.conn.execute(
            "SELECT id FROM timeline_events WHERE timeline_id=? AND kind='parent.composition.published'",
            ("main",),
        ).fetchone()["id"]
        service.store.conn.execute("UPDATE timeline_events SET event_hash='broken' WHERE id=?", (event_id,))
        report = service.store.integrity_report()
        assert report["checks"]["event_chain"]["ok"] is False
        assert any(error.get("stream") == "timeline" and error["reason"] == "hash_mismatch" for error in report["checks"]["event_chain"]["errors"])
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


def test_lost_response_replay_returns_original_head_after_a_newer_publish(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        first_body = _publication(project_id)
        first = service.publish_parent_composition(
            project_id, "main", first_body, idempotency_key="publish-lost-response"
        )
        second_body = _publication(
            project_id,
            expected_head="parent-1",
            parent_revision_id="parent-2",
            shot_revision_id="shot-rev-2",
            config={"writer": 2},
        )
        service.publish_parent_composition(
            project_id, "main", second_body, idempotency_key="publish-second-writer"
        )

        replay = service.publish_parent_composition(
            project_id, "main", copy.deepcopy(first_body), idempotency_key="publish-lost-response"
        )

        assert replay == first
        assert replay["data"]["new_head"] == "parent-1"
        assert replay["receipt"]["result"]["new_head"] == "parent-1"
        assert service._timeline_resource("main")["head_revision_id"] == "parent-2"
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
        baseline = {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("project_shots", "shot_items", "shot_revisions", "internal_timeline_revisions", "parent_composition_revisions", "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences", "composition_revision_dependencies")}
        monkeypatch.setattr(service.store, "_append_timeline_event", lambda *args: (_ for _ in ()).throw(RuntimeError("injected")))
        with pytest.raises(RuntimeError, match="injected"):
            service.publish_parent_composition(project_id, "main", _publication(project_id), idempotency_key="injected")
        for table in ("project_shots", "shot_items", "shot_revisions", "internal_timeline_revisions", "parent_composition_revisions", "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences", "composition_revision_dependencies"):
            assert service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == baseline[table]
        assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0] == command_count
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_events WHERE timeline_id='main'").fetchone()[0] == 1
    finally:
        service.close()


def test_publication_preserves_opaque_parent_and_occurrence_fields(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        body = _publication(project_id)
        body["parent_composition"]["opaque_parent"] = {"future": [1, 2, 3]}
        occurrence = body["parent_composition"]["occurrences"][0]
        occurrence["placement"]["opaque_geometry"] = {"anchor": "center"}
        occurrence["opaque_occurrence"] = {"future_schema": True}

        published = service.publish_parent_composition(
            project_id, "main", body, idempotency_key="opaque-publication"
        )
        reread = service.get_project_parent_composition_revision(
            project_id, "main", published["data"]["new_head"]
        )

        assert reread["payload"]["opaque_parent"] == {"future": [1, 2, 3]}
        stored = reread["payload"]["occurrences"][0]
        assert stored["opaque_occurrence"] == {"future_schema": True}
        assert stored["placement"]["opaque_geometry"] == {"anchor": "center"}
    finally:
        service.close()


def test_publication_preserves_open_shot_payload_without_manufacturing_legacy_audio(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        body = _publication(project_id)
        payload = body["shot_revisions"][0]["payload"]
        payload["name"] = "Open payload"
        payload["metadata"]["future_nested"] = {"values": [1, {"two": True}]}
        payload["future_sibling"] = {"mode": "opaque", "value": None}
        payload.pop("audio_bindings")

        published = service.publish_parent_composition(
            project_id, "main", body, idempotency_key="open-shot-payload"
        )
        reread = service.get_project_shot_revision(
            project_id, "shot-1", "shot-rev-1"
        )

        assert reread["content_digest"] == published["data"]["content_digests"]["shot-rev-1"]
        assert reread["payload"]["name"] == "Open payload"
        assert reread["payload"]["metadata"]["future_nested"] == {"values": [1, {"two": True}]}
        assert reread["payload"]["future_sibling"] == {"mode": "opaque", "value": None}
        assert "audio" not in reread["payload"]
    finally:
        service.close()


def test_missing_selected_media_rejects_publication_without_identity_leak(tmp_path):
    service, project_id = _service(tmp_path)
    try:
        body = _publication(project_id)
        missing = "sha256:" + "f" * 64
        body["shot_revisions"][0]["payload"]["items"] = [
            {"item_id": "missing-item", "media_id": missing, "metadata": {}}
        ]
        before = {
            table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("project_shots", "shot_items", "shot_revisions", "internal_timeline_revisions")
        }

        with pytest.raises(NotFoundError, match="media dependency"):
            service.publish_parent_composition(
                project_id, "main", body, idempotency_key="missing-selected-media"
            )

        after = {
            table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in before
        }
        assert after == before
    finally:
        service.close()
