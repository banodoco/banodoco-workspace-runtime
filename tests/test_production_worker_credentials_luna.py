from __future__ import annotations

import json
import hashlib
import stat

import pytest

from http_helpers import Api
from runtime_protocol.auth import AuthorizationError, CredentialStore
from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES
from runtime_protocol.store import RealmStore


def test_pack_host_credential_is_scoped_distinct_and_persistent(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    first = RuntimeDaemon(
        root,
        support_root=support,
        production_worker_credentials=True,
    ).start()
    try:
        worker_path = first.worker_credential_path
        assert worker_path is not None
        assert worker_path == support / "credentials" / "astrid-pack-host.token"
        assert first.worker_token != first.token
        assert stat.S_IMODE(worker_path.stat().st_mode) == 0o600
        metadata_path = worker_path.with_suffix(".json")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        assert metadata == {"actor": WORKER_ACTOR, "scopes": sorted(WORKER_SCOPES)}
        worker_token = worker_path.read_text(encoding="utf-8").strip()

        # A pack host can perform worker work but cannot inherit owner/admin
        # project authority merely because it was launched by the runtime.
        with pytest.raises(RuntimeError) as forbidden:
            Api(first.endpoint, worker_token).create_project("not-owner", "Not Owner")
        assert forbidden.value.status == 401
    finally:
        first.stop()

    second = RuntimeDaemon(
        root,
        support_root=support,
        production_worker_credentials=True,
    ).start()
    try:
        assert second.worker_credential_path == worker_path
        assert second.worker_token == worker_token
        assert json.loads(second.worker_credential_path.with_suffix(".json").read_text(encoding="utf-8")) == metadata
    finally:
        second.stop()


def test_pack_host_cannot_mutate_control_plane_or_forge_settlement_effects(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(
        tmp_path / "realm",
        support_root=tmp_path / "support",
        production_worker_credentials=True,
    ).start()
    try:
        owner = Api(daemon.endpoint, daemon.token)
        worker = Api(daemon.endpoint, daemon.worker_token)
        capability = "render.worker-boundary"
        definition = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
        project = owner.create_project("worker-boundary", "Before")
        project_id = project["project_id"]
        owner.request(
            "POST",
            "/v1/capabilities",
            {"capability_id": capability, "definition_digest": definition},
        )
        owner.register_executor("astrid-pack-host", [capability])
        task = owner.create_task(
            capability,
            {},
            project=project_id,
            idempotency_key="worker-boundary-task",
            expected_effect={
                "effect_type": "project.update",
                "target_id": project_id,
                "expected_version": 1,
                "payload": {"name": "Allowed", "metadata": {}},
            },
        )

        for method, path, body, key in (
            (
                "POST",
                "/v1/tasks",
                {"capability_id": capability, "capability_digest": definition, "input_object_ids": []},
                "worker-admit",
            ),
            ("POST", f"/v1/tasks/{task['task_id']}/cancel", {}, "worker-cancel"),
            ("POST", f"/v1/tasks/{task['task_id']}/retry", {}, "worker-retry"),
        ):
            with pytest.raises(RuntimeError) as forbidden:
                worker.request(method, path, body, headers={"Idempotency-Key": key})
            assert forbidden.value.status == 401

        # Worker execution remains allowed, but a worker cannot replace the
        # effect the owner predeclared for this attempt.
        attempt = worker.request(
            "POST",
            "/v1/tasks/claim",
            {
                "executor_id": "astrid-pack-host",
                "capability_ids": [capability],
                "runtime_epoch": owner.health()["runtime_epoch"],
            },
            headers={"Idempotency-Key": "worker-boundary-claim"},
        )
        forged = {
            "effect_type": "project.update",
            "target_id": project_id,
            "expected_version": 1,
            "payload": {"name": "Forged", "metadata": {}},
        }
        with pytest.raises(RuntimeError) as rejected:
            worker.request(
                "POST",
                f"/v1/attempts/{attempt['attempt_id']}/settle",
                {
                    "lease_id": attempt["lease_id"],
                    "fence": attempt["fence"],
                    "runtime_epoch": attempt["runtime_epoch"],
                    "outputs": [],
                    "effect": forged,
                },
                headers={"Idempotency-Key": "worker-boundary-forged-settle"},
            )
        assert rejected.value.status == 422
        assert owner.get_project(project_id)["name"] == "Before"

        # Project-scoped object attachment is also control-plane mutation;
        # worker output publication uses the unscoped CAS endpoint instead.
        with pytest.raises(RuntimeError) as object_forbidden:
            worker.request(
                "POST",
                f"/v1/projects/{project_id}/objects",
                raw=b"worker-must-not-attach",
                headers={
                    "Content-Type": "application/octet-stream",
                    "Idempotency-Key": "worker-project-object",
                },
            )
        assert object_forbidden.value.status == 401
    finally:
        daemon.stop()


def test_credential_reuse_compares_placement_and_replaces_without_touching_attempt_state(tmp_path):
    store = CredentialStore(tmp_path / "credentials")
    scopes = ["handshake", "worker:execute"]
    placement_a = {
        "execution_binding": {
            "actual": {
                "kind": "runpod",
                "pod_id": "pod-a",
                "provider_account_ref": "account-a",
                "profile_revision": "profile-a",
            },
            "verification": {
                "method": "credential_claim",
                "evidence_digest": "sha256:" + "a" * 64,
                "verified": True,
            },
            "executor_incarnation": "incarnation-a",
        }
    }
    token_a, path_a = store.provision(WORKER_ACTOR, scopes, metadata=placement_a)

    # Canonical metadata comparison preserves the same executor incarnation on
    # reconnects even when a producer serializes object keys in another order.
    token_reconnect, path_reconnect = store.provision(
        WORKER_ACTOR,
        list(reversed(scopes)),
        metadata={"execution_binding": dict(placement_a["execution_binding"])},
    )
    assert (token_reconnect, path_reconnect) == (token_a, path_a)

    placement_b = {
        "execution_binding": {
            **placement_a["execution_binding"],
            "actual": {**placement_a["execution_binding"]["actual"], "pod_id": "pod-b"},
            "executor_incarnation": "incarnation-b",
        }
    }
    token_b, path_b = store.provision(WORKER_ACTOR, scopes, metadata=placement_b)
    assert path_b == path_a
    assert token_b != token_a
    with pytest.raises(AuthorizationError, match="invalid bearer credential"):
        store.load(token_a)
    assert store.load(token_b)["execution_binding"] == placement_b["execution_binding"]

    # No Runtime attempt/binding rows are opened, settled, or reset by
    # credential replacement; the existing Runtime recovery path owns them.
    assert sorted(path_a.parent.glob("*.token")) == [path_a]
