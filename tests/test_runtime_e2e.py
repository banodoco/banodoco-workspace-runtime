from __future__ import annotations

import hashlib
import json
import os
import threading
import urllib.error
import subprocess
from pathlib import Path

import pytest

from runtime_protocol.cas import ContentAddressedStore
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, OwnerBusyError, ValidationError
from http_helpers import Api


@pytest.fixture()
def daemon(tmp_path):
    instance = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        yield instance
    finally:
        instance.stop()


def test_project_managed_object_and_fake_worker_end_to_end(daemon):
    client = Api(daemon.endpoint, daemon.token)
    health = client.health()
    assert health["status"] == "ok"
    handshake = client.handshake()
    assert handshake["actor_id"] == "owner"
    project = client.create_project("demo", "Demo", {"theme": "neutral"}, idempotency_key="project-1")
    assert project["name"] == "Demo" and project["version"] == 1
    same = client.create_project("demo", "Demo", {"theme": "neutral"}, idempotency_key="project-1")
    assert same["project_id"] == project["project_id"]
    source = b"managed bytes\x00"
    obj = client.ingest("demo", source, media_type="application/octet-stream", original_name="source.bin")
    digest = "sha256:" + hashlib.sha256(source).hexdigest()
    assert obj["digest"] == digest
    received, headers = client.read_object(digest)
    assert received == source
    assert headers["ETag"] == f'"{digest}"'
    ranged, range_headers = client.read_object(digest, range_header="bytes=0-6")
    assert ranged == source[:7]
    assert range_headers["Content-Range"] == f"bytes 0-6/{len(source)}"
    task = client.create_task("render.basic", {"text": "hello"}, project="demo", idempotency_key="task-1")
    task_id = task["task_id"]
    lease = "lease-1"
    client.register_worker("fake", ["render.basic"], resource_keys=["cpu"])
    worker = Api(daemon.endpoint, daemon.worker_token)
    claimed = worker.claim(task_id, worker_id="fake", lease_token=lease)
    assert claimed["state"] == "running"
    settled = worker.settle(task_id, lease, {"text": "hello", "digest": digest})
    assert settled["state"] == "succeeded"
    events = client.events(task["run_id"])
    assert [event["event_type"] for event in events["items"]] == ["task.admitted", "task.claimed", "task.completed"]


def test_restart_reconnect_and_catalog_discovery(daemon, tmp_path):
    client = Api(daemon.endpoint, daemon.token)
    project = client.create_project("persist", "Persistent")
    realm_id = client.get_project(project["project_id"])["realm_id"]
    discovery = json.loads((tmp_path / "support" / "discovery.json").read_text())
    catalog = json.loads((tmp_path / "support" / "catalog.json").read_text())
    assert discovery["realm_id"] == realm_id
    assert "database" not in json.dumps(discovery).lower()
    assert catalog["selected_realm_id"] == realm_id
    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        second = Api(restarted.endpoint, restarted.token)
        assert second.get_project(project["project_id"])["realm_id"] == realm_id
        assert second.get_project(project["project_id"])["name"] == "Persistent"
    finally:
        restarted.stop()


def test_doctor_can_run_while_daemon_owns_realm(daemon, tmp_path):
    completed = subprocess.run(["python3", "-m", "runtime_protocol", "doctor", "--root", str(tmp_path / "realm"), "--json"], capture_output=True, text=True, check=True, cwd=str(Path(__file__).parents[1]), env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])})
    assert json.loads(completed.stdout)["ok"] is True


def test_concurrent_owner_refusal_and_reconnect(tmp_path):
    first = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        with pytest.raises(OwnerBusyError):
            RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    finally:
        first.stop()
    second = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    second.stop()


def test_cas_hash_and_path_safety(tmp_path):
    cas = ContentAddressedStore(tmp_path / "cas")
    stored = cas.put(b"abc")
    assert cas.read(stored["digest"]) == b"abc"
    with pytest.raises(ValidationError):
        cas.path_for("../etc/passwd")
    path = cas.path_for(stored["digest"])
    path.write_bytes(b"tampered")
    with pytest.raises(ConflictError):
        cas.read(stored["digest"])


def test_offline_core_store_and_read_only_doctor(tmp_path):
    root = tmp_path / "realm"
    from runtime_protocol.service import RuntimeService
    service = RuntimeService(root)
    project = service.create_project({"slug": "offline", "name": "Offline", "metadata": {}})
    service.close()
    completed = subprocess.run(["python3", "-m", "runtime_protocol", "doctor", "--root", str(root), "--json"], capture_output=True, text=True, check=True, cwd=str(Path(__file__).parents[1]), env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])})
    report = json.loads(completed.stdout)
    assert report["state"] == "ready" and report["ok"] is True
    assert project["slug"] == "offline"


def test_non_health_routes_require_scoped_credential(daemon):
    import urllib.request
    request = urllib.request.Request(daemon.endpoint + "/v1/projects", method="GET")
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request)
    assert error.value.code == 401


def test_astrid_scoped_actor_can_discover_capability_for_task_admission(daemon):
    """Product admission may read the catalog without worker authority."""
    import secrets

    token = secrets.token_hex(32)
    daemon.credentials.provision_static(
        "astrid",
        token,
        ["handshake", "projects:read", "projects:write", "tasks:read", "tasks:write"],
    )
    owner = Api(daemon.endpoint, daemon.token)
    owner.request(
        "POST",
        "/v1/capabilities",
        {"capability_id": "render.basic", "definition_digest": "sha256:" + "a" * 64},
    )
    product = Api(daemon.endpoint, token)
    catalog = product.request("GET", "/v1/capabilities")
    assert catalog["items"][0]["capability_id"] == "render.basic"


def test_stale_lease_and_undeclared_effect_are_rejected(daemon):
    client = Api(daemon.endpoint, daemon.token)
    project = client.create_project("effect-target", "Effect Target")
    effect = {"kind": "project.update", "target": project["project_id"], "expected_version": 1, "payload": {"name": "Settled Effect"}}
    task = client.create_task("render.basic", {}, project=project["project_id"], expected_effect=effect)
    task_id = task["task_id"]
    client.register_worker("effect-worker", ["render.basic"])
    worker = Api(daemon.endpoint, daemon.worker_token)
    worker.claim(task_id, worker_id="effect-worker", lease_token="good")
    with pytest.raises(RuntimeError):
        worker.settle(task_id, "bad", {})
    with pytest.raises(RuntimeError):
        worker.settle(task_id, "good", {}, effect={"kind": "other"})
    settled = worker.settle(task_id, "good", {}, effect=effect)
    assert settled["state"] == "succeeded"
    updated = client.get_project(project["project_id"])
    assert updated["name"] == "Settled Effect" and updated["version"] == 2
