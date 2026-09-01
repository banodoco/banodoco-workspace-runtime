from __future__ import annotations

import json
from pathlib import Path
import urllib.error
import urllib.request

import pytest

from banodoco_local.bootstrap import BootstrapConfig, BootstrapError, SourceProfile, bootstrap
from banodoco_local.paths import RuntimePaths
from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError
from runtime_protocol.service import RuntimeService
from runtime_protocol.daemon import RuntimeDaemon
from banodoco_workspace_client import WorkspaceClient


def test_targeted_mutations_replay_the_same_committed_receipt(tmp_path: Path) -> None:
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "contract", "name": "Contract"})
        document_body = {"document_id": "doc", "kind": "notes", "content": {"v": 1}}
        document = service.create_document(project["id"], document_body, idempotency_key="doc-create")
        assert document["receipt"]["command_kind"] == "document.create"
        assert service.create_document(project["id"], document_body, idempotency_key="doc-create") == document
        with pytest.raises(ConflictError):
            service.create_document(project["id"], {**document_body, "content": {"v": 2}}, idempotency_key="doc-create")

        generation = service.create_generation(project["id"], {"generation_id": "generation", "metadata": {"seed": 1}}, idempotency_key="generation-create")
        assert generation["receipt"]["project_id"] == project["id"]
        variant = service.create_variant("generation", {"variant_id": "variant", "metadata": {}}, idempotency_key="variant-create")
        assert variant["receipt"]["command_kind"] == "variant.create"

        left = service.ingest(project["id"], b"left")["digest"]
        right = service.ingest(project["id"], b"right")["digest"]
        relation_body = {"from_object_id": left, "to_object_id": right, "kind": "derived_from", "ordinal": 1}
        relation = service.create_media_relation(project["id"], relation_body, idempotency_key="relation-create")
        assert relation["receipt"]["command_kind"] == "media_relation.create"
        assert service.create_media_relation(project["id"], relation_body, idempotency_key="relation-create") == relation

        timeline = service.create_timeline(project["id"], "timeline", idempotency_key="timeline-create")
        updated = service.update_timeline("timeline", {"expected_version": 1, "shots": []}, idempotency_key="timeline-update")
        assert updated["receipt"]["event_ids"]
        assert service.update_timeline("timeline", {"expected_version": 1, "shots": []}, idempotency_key="timeline-update") == updated
        archived = service.archive_timeline("timeline", {"expected_version": 2}, idempotency_key="timeline-archive")
        recovered = service.recover_timeline("timeline", {"expected_version": 3, "version": 2}, idempotency_key="timeline-recover")
        assert archived["receipt"]["project_seq"][0] <= recovered["receipt"]["project_seq"][1]
    finally:
        service.close()


def test_executor_reregistration_is_identity_and_epoch_fenced(tmp_path: Path) -> None:
    service = RuntimeService(tmp_path / "realm")
    identity = {"actor": "executor-a", "scopes": ["worker:register"]}
    try:
        service.register_executor({"executor_id": "executor-a", "capabilities": ["render.basic"]}, idempotency_key="executor-initial", identity=identity)
        epoch = service.health()["runtime_epoch"]
        refreshed = service.register_executor(
            {"executor_id": "executor-a", "capabilities": ["render.basic"], "readiness": "not_ready", "readiness_reason": "warming", "runtime_epoch": epoch},
            idempotency_key="executor-refresh", identity=identity,
        )
        assert refreshed["readiness"] == "not_ready"
        with pytest.raises(AuthorizationError):
            service.register_executor(
                {"executor_id": "executor-a", "capabilities": ["render.basic"], "runtime_epoch": epoch},
                idempotency_key="executor-hijack", identity={"actor": "other", "scopes": ["worker:register"]},
            )
        with pytest.raises(LeaseError):
            service.register_executor(
                {"executor_id": "executor-a", "capabilities": ["render.basic"]},
                idempotency_key="executor-no-epoch", identity=identity,
            )
    finally:
        service.close()


def test_source_profile_requires_pinned_runtime_and_rejects_authority_fields() -> None:
    with pytest.raises(BootstrapError, match="runtime_checkout"):
        SourceProfile.from_mapping({"profile": "astrid", "source_checkout": "/source"})
    with pytest.raises(BootstrapError, match="runtime authority"):
        SourceProfile.from_mapping({"profile": "astrid", "runtime_checkout": "/runtime", "source_checkout": "/source", "realm_root": "/attacker"})
    with pytest.raises(BootstrapError, match="runtime_command"):
        SourceProfile.from_mapping({"profile": "astrid", "runtime_checkout": "/runtime", "source_checkout": "/source", "runtime_command": ["sh", "-c", "evil"]})


def test_bootstrap_rolls_back_new_realm_after_handoff_failure(tmp_path: Path) -> None:
    paths = RuntimePaths.sandbox(tmp_path)
    profile = SourceProfile("astrid", "/runtime", "/source")

    class FailingBoundary:
        stopped = False

        def start(self, **kwargs):
            kwargs["realm_root"].mkdir(parents=True)
            return {"endpoint": "http://127.0.0.1:43100", "pid": 101, "runtime_instance_id": "instance", "protocol_version": "workspace.v1", "schema_version": "workspace-schema-v1"}

        def health(self, **kwargs):
            return True

        def connect(self, **kwargs):
            raise RuntimeError("handoff failed")

        def stop(self):
            self.stopped = True

    boundary = FailingBoundary()
    with pytest.raises(RuntimeError, match="handoff failed"):
        bootstrap(paths, boundary, BootstrapConfig(source_profile=profile))
    assert boundary.stopped
    assert not list(paths.realms_dir.iterdir()) if paths.realms_dir.exists() else True
    assert not paths.catalog_path.exists()
    assert not paths.discovery_path.exists()
    assert not paths.instance_lock_path.exists()


def test_http_target_mutations_require_idempotency_key(tmp_path: Path) -> None:
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project("Strict mutation", idempotency_key="strict-project")
        client.create_timeline(project.project_id, "strict-timeline", idempotency_key="strict-timeline")
        request = urllib.request.Request(
            f"{daemon.endpoint}/v1/timelines/strict-timeline",
            data=json.dumps({"expected_version": 1, "shots": []}).encode(),
            method="PATCH",
            headers={"Authorization": f"Bearer {daemon.token}", "Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 400
        assert json.loads(error.value.read())["code"] == "protocol_error"
    finally:
        daemon.stop()
