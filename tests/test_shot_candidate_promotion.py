from __future__ import annotations

import hashlib

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_candidate_promotion_is_atomic_fixed_point_and_byte_stable_on_replay(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Promotion", slug="promotion", idempotency_key="promotion-project")
        shot = client.create_project_shot(project.project_id, {"shot_id": "shot-1", "name": "Shot 1"}, idempotency_key="promotion-shot")
        old = client.ingest_project_object(project.project_id, b"old", media_type="image/png", idempotency_key="promotion-old")
        new = client.ingest_project_object(project.project_id, b"new", media_type="image/png", idempotency_key="promotion-new")
        plate = client.ingest_project_object(project.project_id, b"plate", media_type="image/png", idempotency_key="promotion-plate")
        proxy = client.ingest_project_object(project.project_id, b"proxy", media_type="image/png", idempotency_key="promotion-proxy")
        old_id, new_id = old.digest, new.digest
        old_hash, plate_hash = old.digest, plate.digest
        old_item = client.add_shot_item(project.project_id, shot.shot_id, {"item_id": "old", "media_id": old_id, "metadata": {"role": "primary_visual", "status": "primary"}}, idempotency_key="promotion-old-item")
        plate_item = client.add_shot_item(project.project_id, shot.shot_id, {"item_id": "plate", "media_id": plate.digest, "metadata": {"kind": "plate", "source_item_id": "old", "source_media_id": old_id, "source_content_sha256": old_hash}}, idempotency_key="promotion-plate-item")
        client.add_shot_item(project.project_id, shot.shot_id, {"item_id": "proxy", "media_id": proxy.digest, "metadata": {"kind": "proxy", "source_item_id": "plate", "source_media_id": plate.digest, "source_content_sha256": plate_hash}}, idempotency_key="promotion-proxy-item")
        candidate = client.add_shot_item(project.project_id, shot.shot_id, {"item_id": "new", "media_id": new_id, "metadata": {"role": "primary_visual", "status": "candidate", "recipe": {"project_id": project.project_id, "shot_id": shot.shot_id, "target_role": "primary_visual"}}}, idempotency_key="promotion-new-item")
        expected_head = int(candidate.version)
        timeline = [{"id": "timeline-1", "metadata": {"source_item_id": "old", "source_media_id": old_id, "source_content_sha256": old_hash}}]
        promoted = client.promote_project_shot_candidate(project.project_id, shot.shot_id, "new", expected_head_seq=expected_head, timeline_assets=timeline, idempotency_key="promotion-command")
        assert promoted["promotion"]["superseded_item_id"] == "old"
        assert {entry["item_id"] for entry in promoted["invalidation"]["stale"]} >= {"plate", "proxy"}
        assert "timeline-1" in {entry.get("asset_id") for entry in promoted["invalidation"]["stale"]}
        assert promoted.receipt["result"] == {"promotion": promoted["promotion"], "invalidation": promoted["invalidation"]}
        replay = client.promote_project_shot_candidate(project.project_id, shot.shot_id, "new", expected_head_seq=expected_head, timeline_assets=timeline, idempotency_key="promotion-command")
        assert replay == promoted
        shown = client.get_project_shot(project.project_id, shot.shot_id)
        statuses = [item["metadata"].get("status") for item in shown["items"] if item["metadata"].get("role") == "primary_visual"]
        assert statuses.count("primary") == 1 and "superseded" in statuses
        with pytest.raises(ApiError) as stale:
            client.promote_project_shot_candidate(project.project_id, shot.shot_id, "new", expected_head_seq=expected_head, idempotency_key="promotion-stale")
        assert stale.value.status == 409
    finally:
        daemon.stop()


def test_candidate_provenance_is_verified_before_promotion(tmp_path):
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Provenance", slug="provenance", idempotency_key="provenance-project")
        shot = client.create_project_shot(project.project_id, {"shot_id": "shot-1", "name": "Shot 1"}, idempotency_key="provenance-shot")
        obj = client.ingest_project_object(project.project_id, b"candidate", media_type="image/png", idempotency_key="provenance-object")
        candidate = client.add_shot_item(project.project_id, shot.shot_id, {"item_id": "candidate", "media_id": obj.digest, "metadata": {"role": "primary_visual", "status": "candidate", "provenance": {"project_id": "foreign-project", "shot_id": shot.shot_id}}}, idempotency_key="provenance-item")
        with pytest.raises(ApiError) as failed:
            client.promote_project_shot_candidate(project.project_id, shot.shot_id, "candidate", expected_head_seq=candidate.version, idempotency_key="provenance-promote")
        assert failed.value.status == 422
        assert client.get_project_shot(project.project_id, shot.shot_id)["version"] == candidate.version
    finally:
        daemon.stop()
