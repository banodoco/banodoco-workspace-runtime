from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from banodoco_workspace_client import WorkspaceClient


def _service(tmp_path):
    root = tmp_path / "runtime"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "thumbs", "name": "Thumbs"}, idempotency_key="project")
    other = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="other-project")
    source = service.ingest(project["id"], b"source-video", media_type="video/mp4", idempotency_key="source")
    thumbnail = service.ingest(project["id"], b"jpeg-thumbnail", media_type="image/jpeg", idempotency_key="thumbnail")
    png = service.ingest(project["id"], b"not-jpeg", media_type="image/png", idempotency_key="png")
    foreign = service.ingest(other["id"], b"foreign-jpeg", media_type="image/jpeg", idempotency_key="foreign")
    return service, project["id"], other["id"], source["data"]["digest"], thumbnail["data"]["digest"], png["data"]["digest"], foreign["data"]["digest"]


def _descriptor(source, thumbnail, time=79.995):
    return {
        "object_id": thumbnail,
        "source_object_id": source,
        "recipe_version": 1,
        "selection": {"kind": "source_frame", "source_time_seconds": time},
    }


def test_source_frame_thumbnail_ensure_lookup_and_repeat_are_idempotent(tmp_path):
    service, project, _other, source, thumbnail, _png, _foreign = _service(tmp_path)
    try:
        assert service.get_source_frame_thumbnail(
            project, source_object_id=source, source_time_seconds=79.995,
        ) == {"thumbnail": None}
        first = service.ensure_source_frame_thumbnail(
            project, _descriptor(source, thumbnail), idempotency_key="ensure-one",
        )
        second = service.ensure_source_frame_thumbnail(
            project, _descriptor(source, thumbnail), idempotency_key="ensure-two",
        )
        assert first["data"] == second["data"] == _descriptor(source, thumbnail)
        assert service.get_source_frame_thumbnail(
            project, source_object_id=source, source_time_seconds=79.995,
        ) == {"thumbnail": _descriptor(source, thumbnail)}
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM media_relations WHERE project_id=?", (project,),
        ).fetchone()[0] == 1
    finally:
        service.close()


def test_source_frame_thumbnail_concurrent_ensure_creates_one_relation(tmp_path):
    service, project, _other, source, thumbnail, _png, _foreign = _service(tmp_path)
    try:
        def ensure(index):
            return service.ensure_source_frame_thumbnail(
                project, _descriptor(source, thumbnail), idempotency_key=f"concurrent-{index}",
            )["data"]

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(ensure, range(16)))
        assert results == [_descriptor(source, thumbnail)] * 16
        assert service.store.conn.execute("SELECT COUNT(*) FROM media_relations").fetchone()[0] == 1
    finally:
        service.close()


def test_source_frame_thumbnail_rejects_foreign_objects_non_jpeg_and_bad_time(tmp_path):
    service, project, other, source, thumbnail, png, foreign = _service(tmp_path)
    try:
        with pytest.raises(NotFoundError, match="outside the project"):
            service.ensure_source_frame_thumbnail(
                project, _descriptor(source, foreign), idempotency_key="foreign-image",
            )
        with pytest.raises(NotFoundError, match="outside the project"):
            service.ensure_source_frame_thumbnail(
                project, _descriptor(foreign, thumbnail), idempotency_key="foreign-source",
            )
        with pytest.raises(ConflictError, match="image/jpeg"):
            service.ensure_source_frame_thumbnail(
                project, _descriptor(source, png), idempotency_key="not-jpeg",
            )
        with pytest.raises(ValidationError, match="normalized"):
            service.ensure_source_frame_thumbnail(
                project, _descriptor(source, thumbnail, 79.9950004), idempotency_key="bad-time",
            )
        with pytest.raises(NotFoundError, match="outside the project"):
            service.get_source_frame_thumbnail(
                other, source_object_id=source, source_time_seconds=79.995,
            )
    finally:
        service.close()


def test_source_frame_thumbnail_structured_export_preserves_relation(tmp_path):
    service, project, _other, source, thumbnail, _png, _foreign = _service(tmp_path)
    try:
        service.ensure_source_frame_thumbnail(
            project, _descriptor(source, thumbnail), idempotency_key="export-association",
        )
        exported = service.export_structured()
        assert len(exported["media_relations"]) == 1
        relation = exported["media_relations"][0]
        assert relation["from_object_id"] == thumbnail
        assert relation["to_object_id"] == source
        assert relation["kind"] == "derived_from"
        assert relation["metadata"]["thumbnail"] == _descriptor(source, thumbnail)
    finally:
        service.close()


def test_generated_client_uses_source_frame_thumbnail_api(tmp_path):
    root = tmp_path / "http-runtime"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("HTTP thumbnails", slug="http-thumbnails", idempotency_key="http-project")
        source = client.ingest_project_object(project.project_id, b"http-source", media_type="video/mp4", idempotency_key="http-source")
        thumbnail = client.ingest_project_object(project.project_id, b"http-jpeg", media_type="image/jpeg", idempotency_key="http-thumbnail")
        descriptor = _descriptor(source["object_id"], thumbnail["object_id"], 12.5)
        created = client.ensure_source_frame_thumbnail(project.project_id, descriptor, idempotency_key="http-ensure")
        assert {key: created[key] for key in descriptor} == descriptor
        assert client.get_source_frame_thumbnail(project.project_id, source["object_id"], 12.5) == descriptor
    finally:
        daemon.stop()
