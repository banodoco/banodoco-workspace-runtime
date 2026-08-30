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
    assert health["ok"] is True
    handshake = client.handshake()
    assert handshake["protocol_version"] == "core-v1"
    project = client.create_project("demo", "Demo", {"theme": "neutral"}, idempotency_key="project-1")
    assert project["slug"] == "demo" and project["version"] == 1
    same = client.create_project("demo", "Demo", {"theme": "neutral"}, idempotency_key="project-1")
    assert same["id"] == project["id"]
    source = b"managed bytes\x00"
    obj = client.ingest("demo", source, media_type="application/octet-stream", original_name="source.bin")
    digest = hashlib.sha256(source).hexdigest()
    assert obj["digest"] == digest
    received, headers = client.read_object(digest)
    assert received == source
    assert headers["ETag"] == f'"{digest}"'
    ranged, range_headers = client.read_object(digest, range_header="bytes=0-6")
    assert ranged == source[:7]
    assert range_headers["Content-Range"] == f"bytes 0-6/{len(source)}"
    task = client.create_task("testing.echo", {"text": "hello"}, project="demo", idempotency_key="task-1")
    task_id = task["task"]["id"]
    lease = "lease-1"
    client.register_worker("fake", ["testing.echo"], resource_keys=["cpu"])
    worker = Api(daemon.endpoint, daemon.worker_token)
    claimed = worker.claim(task_id, worker_id="fake", lease_token=lease)
    assert claimed["task"]["status"] == "running"
    settled = worker.settle(task_id, lease, {"text": "hello", "digest": digest})
    assert settled["task"]["status"] == "completed"
    assert client.task(task_id)["task"]["result_json"] == json.dumps({"digest": digest, "text": "hello"}, sort_keys=True, separators=(",", ":"))
    events = client.events(task["run"]["id"])
    assert [event["kind"] for event in events] == ["task.admitted", "task.claimed", "task.completed"]


def test_restart_reconnect_and_catalog_discovery(daemon, tmp_path):
    client = Api(daemon.endpoint, daemon.token)
    project = client.create_project("persist", "Persistent")
    realm_id = client.health()["realm_id"]
    discovery = json.loads((tmp_path / "support" / "discovery.json").read_text())
    catalog = json.loads((tmp_path / "support" / "catalog.json").read_text())
    assert discovery["realm_id"] == realm_id
    assert "database" not in json.dumps(discovery).lower()
    assert catalog["selected_realm_id"] == realm_id
    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        second = Api(restarted.endpoint, restarted.token)
        assert second.health()["realm_id"] == realm_id
        assert second.get_project(project["id"])["name"] == "Persistent"
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


def test_stale_lease_and_undeclared_effect_are_rejected(daemon):
    client = Api(daemon.endpoint, daemon.token)
    task = client.create_task("testing.echo", {}, expected_effect={"kind": "project.update", "target": "p", "expected_version": 1})
    task_id = task["task"]["id"]
    client.register_worker("effect-worker", ["testing.echo"])
    worker = Api(daemon.endpoint, daemon.worker_token)
    worker.claim(task_id, worker_id="effect-worker", lease_token="good")
    with pytest.raises(RuntimeError):
        worker.settle(task_id, "bad", {})
    with pytest.raises(RuntimeError):
        worker.settle(task_id, "good", {}, effect={"kind": "other"})
    settled = worker.settle(task_id, "good", {}, effect={"kind": "project.update", "target": "p", "expected_version": 1})
    assert settled["task"]["status"] == "completed"
