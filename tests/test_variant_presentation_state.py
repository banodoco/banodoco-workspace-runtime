from __future__ import annotations

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _service(root):
    RealmStore.initialize(root).close()
    return RuntimeService(root)


def test_variant_thumbnail_and_first_view_state_are_project_scoped_and_idempotent(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "presentation", "name": "Presentation"}, idempotency_key="project")
        source = service.ingest(project["id"], b"video-bytes", media_type="video/mp4", original_name="render.mp4", idempotency_key="source")["data"]["digest"]
        poster = service.ingest(project["id"], b"jpeg-bytes", media_type="image/jpeg", original_name="render.jpg", idempotency_key="poster")["data"]["digest"]
        service.store.conn.execute(
            "INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, NULL, ?, ?, ?, 1, datetime('now'), datetime('now'))",
            ("generation-presentation", project["id"], "video", "succeeded", "{}"),
        )
        service.store.conn.execute(
            "INSERT INTO generation_variants(id, generation_id, object_id, variant_type, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
            ("variant-presentation", "generation-presentation", source.removeprefix("sha256:"), "generated", '{"media_type":"video/mp4"}'),
        )
        service.store.conn.commit()

        initial = service.list_variants("generation-presentation")["items"][0]
        assert initial["thumbnail"] is None
        assert initial["viewed_at"] is None

        descriptor = {
            "thumbnail_object_id": poster,
            "source_object_id": source,
            "recipe_version": 1,
        }
        attached = service.attach_variant_thumbnail(
            "variant-presentation", descriptor, idempotency_key="attach-poster"
        )
        assert attached["data"]["thumbnail"] == {
            "object_id": poster,
            "source_object_id": source,
            "recipe_version": 1,
        }
        assert service.attach_variant_thumbnail(
            "variant-presentation", descriptor, idempotency_key="attach-poster"
        ) == attached

        with pytest.raises(ConflictError, match="source changed"):
            service.attach_variant_thumbnail(
                "variant-presentation",
                {**descriptor, "source_object_id": "sha256:" + "0" * 64},
                idempotency_key="attach-wrong-source",
            )

        first = service.mark_variant_viewed("variant-presentation", idempotency_key="view-one")["data"]
        second = service.mark_variant_viewed("variant-presentation", idempotency_key="view-two")["data"]
        assert first["viewed_at"]
        assert second["viewed_at"] == first["viewed_at"]
    finally:
        service.close()


def test_bulk_variant_view_state_only_fills_missing_first_view_timestamps(tmp_path):
    service = _service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "bulk", "name": "Bulk"}, idempotency_key="project")
        service.store.conn.execute(
            "INSERT INTO generations(id, project_id, source_task_id, type, status, metadata_json, version, created_at, updated_at) VALUES (?, ?, NULL, ?, ?, ?, 1, datetime('now'), datetime('now'))",
            ("generation-bulk", project["id"], "video", "succeeded", "{}"),
        )
        service.store.conn.executemany(
            "INSERT INTO generation_variants(id, generation_id, object_id, variant_type, metadata_json, created_at, viewed_at) VALUES (?, ?, NULL, ?, ?, datetime('now'), ?)",
            [
                ("variant-bulk-a", "generation-bulk", "generated", "{}", None),
                ("variant-bulk-b", "generation-bulk", "generated", "{}", "2026-09-22T00:00:00Z"),
            ],
        )
        service.store.conn.commit()

        result = service.mark_generation_variants_viewed("generation-bulk", idempotency_key="view-all")["data"]
        values = {item["variant_id"]: item["viewed_at"] for item in result["variants"]}
        assert values["variant-bulk-a"] == result["viewed_at"]
        assert values["variant-bulk-b"] == "2026-09-22T00:00:00Z"
    finally:
        service.close()
