from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def test_object_location_is_project_scoped_and_verified_without_copy(tmp_path: Path) -> None:
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        owner = service.create_project({"slug": "owner", "name": "Owner"}, idempotency_key="project-owner")
        other = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="project-other")
        payload = b"canonical bytes"
        result = service.ingest(owner["id"], payload, original_name="render.mp4", idempotency_key="object")
        digest = result["data"]["digest"]
        location = service.object_location(owner["id"], digest)
        path = Path(location["local_path"])
        assert location["storage"] == "runtime_cas"
        assert location["verified"] is True
        assert path.read_bytes() == payload
        assert path == service.cas.path_for(digest.removeprefix("sha256:"))
        assert not (tmp_path / "renders").exists()
        with pytest.raises(NotFoundError, match="owned by project"):
            service.object_location(other["id"], digest)
        with pytest.raises(ValidationError, match="SHA-256"):
            service.object_location(owner["id"], "../object")
    finally:
        service.close()


def test_object_location_rejects_tampered_cas_and_http_requires_auth(tmp_path: Path) -> None:
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        api = Api(daemon.endpoint, daemon.token)
        project = api.create_project("owner", "Owner")
        payload = b"runtime bytes"
        result = api.ingest(project["project_id"], payload, original_name="render.mp4", idempotency_key="object")
        digest = result["data"]["digest"]
        location = api.request("GET", f"/v1/projects/{project['project_id']}/objects/{digest}/location")
        assert WorkspaceClient(daemon.endpoint, daemon.token).get_project_object_location(
            project["project_id"], digest
        ).verified is True
        with pytest.raises(ApiError) as unauthenticated:
            WorkspaceClient(daemon.endpoint).get_project_object_location(project["project_id"], digest)
        assert unauthenticated.value.status == 401
        assert location["local_path"].endswith(digest.removeprefix("sha256:")[2:])
        path = Path(location["local_path"])
        path.write_bytes(b"tampered")
        with pytest.raises(RuntimeError) as error:
            api.request("GET", f"/v1/projects/{project['project_id']}/objects/{digest}/location")
        assert error.value.status == 409
    finally:
        daemon.stop()


def test_completed_task_resource_remains_portable_without_location_lookup(tmp_path: Path) -> None:
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        capability = "render.location"
        service.register_capability({"capability_id": capability, "definition_digest": _digest(capability.encode())})
        service.register_executor({"executor_id": "worker", "capabilities": [capability]})
        project = service.create_project({"slug": "render", "name": "Render"}, idempotency_key="project")
        task = service.create_task({"capability_id": capability, "capability_digest": _digest(capability.encode()), "project": project["id"], "idempotency_key": "task"})
        epoch = service.health()["runtime_epoch"]
        attempt = service.claim_next({"executor_id": "worker", "capability_ids": [capability], "runtime_epoch": epoch}, idempotency_key="claim")
        data = b"rendered output"
        digest = _digest(data)
        service.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": epoch, "outputs": [{"name": "video", "digest": digest, "media_type": "video/mp4", "data_base64": __import__("base64").b64encode(data).decode()}]}, idempotency_key="settle")
        service.cas.verify = lambda _digest: (_ for _ in ()).throw(AssertionError("task polling must not rehash CAS output"))
        resource = service._task_resource(service.task(task["task"]["id"]))
        output = resource["result"]["outputs"][0]
        assert "local_path" not in output
        assert output["digest"] == digest
    finally:
        service.close()


@pytest.mark.parametrize("symlink_parent", [False, True])
def test_object_location_rejects_symlinks_even_to_identical_bytes(tmp_path, symlink_parent):
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "links", "name": "Links"})
        digest = service.ingest(project["id"], b"identical", idempotency_key="bytes")["data"]["digest"]
        path = service.cas.path_for(digest.removeprefix("sha256:"))
        if symlink_parent:
            relocated = tmp_path / "prefix"
            path.parent.rename(relocated)
            path.parent.symlink_to(relocated, target_is_directory=True)
        else:
            relocated = tmp_path / "bytes"
            path.rename(relocated)
            path.symlink_to(relocated)
        with pytest.raises(ConflictError):
            service.object_location(project["id"], digest)
    finally:
        service.close()
