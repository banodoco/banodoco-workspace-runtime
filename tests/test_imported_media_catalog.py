from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.python.banodoco_workspace_client.generated import ApiError, WorkspaceClient
from runtime_protocol.errors import AuthorizationError, ConflictError, NotFoundError, RuntimeErrorBase, ValidationError
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.service import OBJECT_MAX_BYTES, RuntimeService
from runtime_protocol.store import RealmStore


@pytest.fixture()
def service(tmp_path: Path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    value = RuntimeService(root)
    try:
        yield value
    finally:
        value.close()


def _project(service: RuntimeService, slug: str = "imports") -> dict:
    return service.create_project(
        {"slug": slug, "name": slug.title()}, idempotency_key=f"project-{slug}"
    )


@pytest.mark.parametrize(
    ("payload", "media_type", "filename", "dimensions", "duration"),
    [
        (b"image-bytes", "image/png", "still.png", (1280, 720), None),
        (b"video-bytes", "video/mp4", "clip.mp4", (1920, 1080), 2.5),
    ],
)
def test_service_import_settles_one_generation_and_primary_variant(
    service: RuntimeService, payload, media_type, filename, dimensions, duration
) -> None:
    project = _project(service, media_type.split("/")[0])
    result = service.import_media(
        project["id"], payload,
        media_type=media_type,
        original_name=filename,
        actor_id="product-user",
        width=dimensions[0],
        height=dimensions[1],
        duration_seconds=duration,
        idempotency_key=f"import-{media_type.split('/')[0]}",
    )
    imported = result["data"]

    assert imported["provider"] == "runtime"
    assert imported["status"] == "completed"
    assert imported["import_operation_id"] == f"import-{media_type.split('/')[0]}"
    assert imported["generation_id"].startswith("generation-task-")
    assert imported["entry"] == {
        "object_id": imported["asset_id"],
        "media_type": media_type,
        "size": len(payload),
        "filename": filename,
    }
    assert imported["provenance"]["source"] == "external_upload"
    assert imported["provenance"]["origin"] == "imported"
    assert imported["actor_id"] == "product-user"

    generation = service.get_generation(imported["generation_id"])
    variants = service.list_variants(imported["generation_id"])["items"]
    assert generation["project_id"] == project["id"]
    assert generation["source_task_id"] == imported["task_id"]
    assert generation["status"] == "completed"
    assert generation["metadata"]["provenance"] == imported["provenance"]
    assert len(variants) == 1
    assert variants[0]["variant_id"] == imported["variant_id"]
    assert variants[0]["object_id"] == imported["asset_id"]
    assert variants[0]["variant_type"] == "original"
    assert variants[0]["metadata"]["is_primary"] is True
    assert service.managed_outputs(imported["task_id"])[0]["durability"] == "durable"
    assert service.get_media_import(project["id"], imported["import_operation_id"]) == imported


def test_same_key_replays_across_reopen_and_different_input_conflicts(tmp_path: Path) -> None:
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = _project(service)
    kwargs = {
        "media_type": "image/webp",
        "original_name": "same.webp",
        "actor_id": "owner",
        "idempotency_key": "caller-known-operation",
    }
    first = service.import_media(project["id"], b"same", **kwargs)
    service.close()

    reopened = RuntimeService(root)
    try:
        replay = reopened.import_media(project["id"], b"same", **kwargs)
        assert replay == first
        assert reopened.get_media_import(project["id"], "caller-known-operation") == first["data"]
        with pytest.raises(ConflictError, match="different input"):
            reopened.import_media(project["id"], b"changed", **kwargs)
        assert reopened.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
        assert reopened.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 1
    finally:
        reopened.close()


def test_concurrent_same_key_fans_in_and_changed_input_has_one_winner(service: RuntimeService) -> None:
    project = _project(service, "concurrent")

    def import_same():
        return service.import_media(
            project["id"], b"same", media_type="image/jpeg",
            original_name="same.jpg", actor_id="owner", idempotency_key="same-key",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: import_same(), range(16)))
    assert all(value == results[0] for value in results)

    def import_race(payload: bytes):
        try:
            return service.import_media(
                project["id"], payload, media_type="video/mp4",
                original_name="race.mp4", actor_id="owner", idempotency_key="race-key",
            )
        except ConflictError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        raced = list(pool.map(import_race, (b"left", b"right")))
    assert sum(isinstance(value, ConflictError) for value in raced) == 1
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 2
    assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 2


def test_partial_settlement_failure_exposes_pending_object_but_no_catalog_pair(
    service: RuntimeService, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(service, "partial")
    with monkeypatch.context() as scoped:
        scoped.setattr(
            service.store,
            "_associate_managed_outputs",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("injected association failure")),
        )
        with pytest.raises(RuntimeError, match="injected association failure"):
            service.import_media(
                project["id"], b"partial", media_type="image/png",
                original_name="partial.png", actor_id="owner", idempotency_key="partial-op",
            )

    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
    assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 0
    assert service.list_generations(project["id"])["items"] == []
    pending = service.get_media_import(project["id"], "partial-op")
    assert pending["status"] == "pending"
    assert pending["generation_id"] is None and pending["variant_id"] is None

    completed = service.import_media(
        project["id"], b"partial", media_type="image/png",
        original_name="partial.png", actor_id="owner", idempotency_key="partial-op",
    )["data"]
    assert completed["status"] == "completed"
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
    assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 1


def test_project_media_permission_and_size_rejections_have_no_catalog_side_effects(
    service: RuntimeService,
) -> None:
    owner = _project(service, "owner")
    other = _project(service, "other")
    imported = service.import_media(
        owner["id"], b"owned", media_type="image/png",
        original_name="owned.png", actor_id="owner", idempotency_key="owned-op",
    )["data"]
    with pytest.raises(NotFoundError, match="operation"):
        service.get_media_import(other["id"], imported["import_operation_id"])
    with pytest.raises(NotFoundError):
        service.import_media(
            "missing-project", b"missing", media_type="image/png",
            actor_id="owner", idempotency_key="missing-op",
        )
    with pytest.raises(AuthorizationError, match="host-owned"):
        service.create_task({
            "capability_id": "runtime.media.import.v1",
            "project": owner["id"],
            "input_object_ids": [imported["asset_id"]],
            "idempotency_key": "browser-import-task",
        })
    with pytest.raises(ValidationError, match=r"image/\* or video/\*"):
        service.import_media(
            owner["id"], b"text", media_type="text/plain",
            actor_id="owner", idempotency_key="bad-type",
        )
    with pytest.raises(ConflictError, match="digest"):
        service.import_media(
            owner["id"], b"digest-mismatch", media_type="image/png",
            expected_digest="sha256:" + "0" * 64,
            actor_id="owner", idempotency_key="bad-digest",
        )
    with pytest.raises(ConflictError, match="metadata does not match existing object"):
        service.import_media(
            owner["id"], b"owned", media_type="video/mp4",
            original_name="same-bytes.mp4", actor_id="owner",
            idempotency_key="cas-metadata-conflict",
        )
    assert service.get_media_import(owner["id"], "cas-metadata-conflict")["status"] == "pending"

    class Oversized(bytes):
        def __len__(self):
            return OBJECT_MAX_BYTES + 1

    with pytest.raises(ValidationError, match="64 MiB"):
        service.import_media(
            owner["id"], Oversized(b"small"), media_type="video/mp4",
            actor_id="owner", idempotency_key="too-large",
        )
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
    assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 1


def _handler_transport(service: RuntimeService):
    identities = {
        "owner-token": {"actor": "owner", "scopes": ["projects:read", "projects:write"]},
        "reader-token": {"actor": "reader", "scopes": ["projects:read"]},
    }

    class Credentials:
        @staticmethod
        def require(token, scope):
            identity = identities.get(token)
            if identity is None:
                raise AuthorizationError("bearer credential required")
            if scope not in identity["scopes"]:
                raise AuthorizationError("credential lacks required scope", details={"scope": scope})
            return identity

    def transport(method, path, headers, body=None):
        handler = object.__new__(RuntimeHandler)
        handler.server = SimpleNamespace(runtime=service, credentials=Credentials())
        handler.path = path
        handler.command = method
        handler.headers = dict(headers)
        payload = bytes(body or b"")
        handler.headers.setdefault("Content-Length", str(len(payload)))
        handler.rfile = io.BytesIO(payload)
        response = {}

        def send(status, value=None, **kwargs):
            response["status"] = status
            response["payload"] = kwargs.get("error", value)

        handler._send = send
        try:
            handler._route()
        except RuntimeErrorBase as exc:
            response["status"] = exc.status
            response["payload"] = exc.as_dict()
        return response["status"], {"Content-Type": "application/json"}, json.dumps(response["payload"]).encode()

    return transport


def test_http_generated_client_imports_image_video_and_enforces_scopes(service: RuntimeService) -> None:
    transport = _handler_transport(service)
    owner = WorkspaceClient("http://runtime.test", "owner-token", transport=transport)
    project = owner.create_project("HTTP imports", idempotency_key="http-project")
    image = owner.import_project_media(
        project.project_id, b"http-image", media_type="image/png",
        filename="http.png", width=640, height=480, idempotency_key="http-image",
    )
    video = owner.import_project_media(
        project.project_id, b"http-video", media_type="video/mp4",
        filename="http.mp4", width=1920, height=1080,
        duration_seconds=3.0, idempotency_key="http-video",
    )
    assert owner.get_project_media_import(project.project_id, "http-image")["generation_id"] == image["generation_id"]
    assert owner.get_project_media_import(project.project_id, "http-video")["variant_id"] == video["variant_id"]
    assert len(owner.list_generations(project.project_id)[0]) == 2

    reader = WorkspaceClient("http://runtime.test", "reader-token", transport=transport)
    assert reader.get_project_media_import(project.project_id, "http-image")["asset_id"] == image["asset_id"]
    with pytest.raises(ApiError) as forbidden:
        reader.import_project_media(
            project.project_id, b"forbidden", media_type="image/png",
            idempotency_key="forbidden",
        )
    assert forbidden.value.status == 401

    status, _headers, body = transport(
        "POST",
        f"/v1/projects/{project.project_id}/media-imports",
        {
            "Authorization": "Bearer owner-token",
            "Content-Type": "video/mp4",
            "Idempotency-Key": "http-too-large",
            "Content-Length": str(OBJECT_MAX_BYTES + 1),
        },
        b"",
    )
    assert status == 400
    assert "64 MiB" in json.loads(body)["message"]
