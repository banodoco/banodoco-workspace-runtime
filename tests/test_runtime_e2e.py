from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import urllib.error
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from runtime_protocol.cas import ContentAddressedStore
from runtime_protocol.daemon import RuntimeDaemon, handoff_registration_admission
from runtime_protocol.lifecycle import interruption_fence
from runtime_protocol.server import registration_body_digest
from runtime_protocol.store import RealmStore
from runtime_protocol.errors import ConflictError, OwnerBusyError, ValidationError
from banodoco_workspace_client import ApiError, WorkspaceClient
from http_helpers import Api


@pytest.fixture()
def daemon(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    instance = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        yield instance
    finally:
        instance.stop()


def test_project_managed_object_and_fake_executor_end_to_end(daemon):
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
    obj = client.ingest("demo", source, media_type="application/octet-stream", original_name="source.bin", idempotency_key="source-object")
    digest = "sha256:" + hashlib.sha256(source).hexdigest()
    assert obj["data"]["digest"] == digest
    received, headers = client.read_object(digest)
    assert received == source
    assert headers["ETag"] == f'"{digest}"'
    ranged, range_headers = client.read_object(digest, range_header="bytes=0-6")
    assert ranged == source[:7]
    assert range_headers["Content-Range"] == f"bytes 0-6/{len(source)}"
    task = client.create_task("render.basic", {"text": "hello"}, project="demo", idempotency_key="task-1")
    task_id = task["task_id"]
    client.register_executor("fake", ["render.basic"], resource_keys=["cpu"], idempotency_key="executor-fake")
    worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
    claimed = worker.claim_task(executor_id="fake", capability_ids=["render.basic"], idempotency_key="claim-1", runtime_epoch=worker.health().runtime_epoch)
    assert claimed is not None and claimed["task_id"] == task_id
    settled = worker.settle_attempt(
        claimed["attempt_id"],
        {"lease_id": claimed["lease_id"], "fence": claimed["fence"], "runtime_epoch": claimed["runtime_epoch"], "outputs": [{"digest": digest}]},
        idempotency_key="settle-1",
    )
    assert settled.state == "succeeded"
    events = client.events(task["run_id"])
    assert [event["event_type"] for event in events["items"]] == ["task.admitted", "task.claimed", "task.completed"]


def test_threaded_http_dispatch_serializes_shared_runtime(daemon, monkeypatch):
    active = 0
    maximum = 0
    guard = threading.Lock()

    def slow_health():
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.03)
        with guard:
            active -= 1
        return {"status": "ok"}

    monkeypatch.setattr(daemon.service, "health", slow_health)

    def request_health():
        with urllib.request.urlopen(f"{daemon.endpoint}/v1/health", timeout=2) as response:
            assert response.status == 200

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: request_health(), range(4)))

    assert maximum == 1


def test_handoff_pending_admission_allows_only_exact_worker_registration(daemon):
    capability = "handoff.capability"
    digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
    body = {
        "executor_id": "handoff-worker",
        "capabilities": [
            {
                "capability_id": capability,
                "definition_digest": digest,
                "status": "ready",
                "required_resource_keys": [],
                "estimated_scratch_bytes": 0,
                "estimated_output_bytes": 1,
            }
        ],
        "max_concurrency": 1,
        "resource_keys": [],
        "protocol": "workspace.v1",
    }
    worker_token, _ = daemon.credentials.provision(
        "handoff-worker", ["worker:register", "worker:execute"]
    )
    daemon.httpd.set_admission_mode(
        "handoff_pending",
        registration_actor="handoff-worker",
        registration_bodies={"/v1/executors": [body]},
    )

    worker = Api(daemon.endpoint, worker_token)
    owner = Api(daemon.endpoint, daemon.token)
    assert worker.health()["status"] == "ok"
    for actor, method, path, value, headers in (
        (owner, "GET", "/v1/projects", None, None),
        (owner, "POST", "/v1/executors", body, {"Idempotency-Key": "owner-register"}),
        (worker, "POST", "/v1/executors", {**body, "max_concurrency": 2}, {"Idempotency-Key": "changed-register"}),
        (worker, "POST", "/v1/capabilities", {"capability_id": capability, "definition_digest": digest}, {"Idempotency-Key": "unconfigured-route"}),
        (worker, "POST", "/v1/tasks/claim", {"executor_id": "handoff-worker"}, {"Idempotency-Key": "pending-claim"}),
    ):
        with pytest.raises(RuntimeError) as rejected:
            actor.request(method, path, value, headers=headers)
        assert rejected.value.status == 401

    registered = worker.request(
        "POST",
        "/v1/executors",
        body,
        headers={"Idempotency-Key": "exact-register"},
    )
    assert registered["executor_id"] == "handoff-worker"

    daemon.httpd.set_admission_mode("ready")
    assert owner.request("GET", "/v1/projects")["items"] == []


def test_admission_close_drains_authenticated_mutation_before_return(daemon, monkeypatch):
    mutation_entered = threading.Event()
    release_mutation = threading.Event()
    close_returned = threading.Event()
    original_create_project = daemon.service.create_project

    def paused_create_project(*args, **kwargs):
        mutation_entered.set()
        assert release_mutation.wait(2)
        return original_create_project(*args, **kwargs)

    monkeypatch.setattr(daemon.service, "create_project", paused_create_project)
    owner = Api(daemon.endpoint, daemon.token)
    request_result = {}

    def create_project():
        try:
            request_result["value"] = owner.create_project(
                "close-fence",
                "Close fence",
                idempotency_key="close-fence",
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            request_result["error"] = exc

    request_thread = threading.Thread(target=create_project)
    close_thread = threading.Thread(
        target=lambda: (
            daemon.httpd.set_admission_mode("closed"),
            close_returned.set(),
        )
    )
    request_thread.start()
    try:
        assert mutation_entered.wait(1)
        close_thread.start()
        assert not close_returned.wait(0.1), "close returned while admitted mutation was active"
    finally:
        release_mutation.set()
        request_thread.join(2)
        if close_thread.ident is not None:
            close_thread.join(2)

    assert not request_thread.is_alive()
    assert not close_thread.is_alive()
    assert "error" not in request_result
    assert request_result["value"]["name"] == "Close fence"
    assert close_returned.is_set()
    with pytest.raises(RuntimeError) as rejected:
        owner.create_project("after-close", "After close", idempotency_key="after-close")
    assert rejected.value.status == 401
    assert daemon.service.store.conn.execute(
        "SELECT COUNT(*) FROM projects WHERE slug='after-close'"
    ).fetchone()[0] == 0


def test_request_waiting_behind_interruption_fence_rechecks_closed_admission(
    daemon, monkeypatch
):
    transaction_attempted = threading.Event()
    original_transaction = daemon.service.store._transaction

    @contextmanager
    def observed_transaction():
        transaction_attempted.set()
        with original_transaction():
            yield

    monkeypatch.setattr(daemon.service.store, "_transaction", observed_transaction)
    owner = Api(daemon.endpoint, daemon.token)
    request_result = {}

    def create_project():
        try:
            request_result["value"] = owner.create_project(
                "interruption-race",
                "Interruption race",
                idempotency_key="interruption-race",
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            request_result["error"] = exc

    request_thread = threading.Thread(target=create_project)
    with interruption_fence(daemon.root):
        request_thread.start()
        assert transaction_attempted.wait(1)
        daemon.httpd.set_admission_mode("closed")

    request_thread.join(2)
    assert not request_thread.is_alive()
    assert "value" not in request_result
    assert request_result["error"].status == 401
    assert daemon.service.store.conn.execute(
        "SELECT COUNT(*) FROM projects WHERE slug='interruption-race'"
    ).fetchone()[0] == 0


def test_handoff_registration_actor_path_and_body_share_one_admission_snapshot(
    daemon, monkeypatch
):
    actor_a = "handoff-generation-a"
    actor_b = "handoff-generation-b"
    token_a, _ = daemon.credentials.provision(actor_a, ["worker:register"])
    token_b, _ = daemon.credentials.provision(actor_b, ["worker:register"])
    body_a = {
        "capability_id": "handoff.generation.a",
        "definition_digest": "sha256:" + "a" * 64,
    }
    body_b = {
        "capability_id": "handoff.generation.b",
        "definition_digest": "sha256:" + "b" * 64,
    }
    daemon.httpd.set_admission_mode(
        "handoff_pending",
        registration_actor=actor_a,
        registration_bodies={"/v1/capabilities": [body_a]},
    )

    identity_checked = threading.Event()
    release_identity = threading.Event()
    transition_returned = threading.Event()
    original_require = daemon.credentials.require

    def paused_require(token, scope):
        identity = original_require(token, scope)
        if identity.get("actor") == actor_a and scope == "worker:register":
            identity_checked.set()
            assert release_identity.wait(2)
        return identity

    monkeypatch.setattr(daemon.credentials, "require", paused_require)
    request_result = {}

    def mixed_generation_request():
        try:
            request_result["value"] = Api(daemon.endpoint, token_a).request(
                "POST", "/v1/capabilities", body_b
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            request_result["error"] = exc

    request_thread = threading.Thread(target=mixed_generation_request)

    def transition_generation():
        daemon.httpd.set_admission_mode(
            "handoff_pending",
            registration_actor=actor_b,
            registration_bodies={"/v1/capabilities": [body_b]},
        )
        transition_returned.set()

    transition_thread = threading.Thread(target=transition_generation)
    request_thread.start()
    try:
        assert identity_checked.wait(1)
        transition_thread.start()
        assert not transition_returned.wait(0.1), (
            "admission generation changed between identity and body authorization"
        )
    finally:
        release_identity.set()
        request_thread.join(2)
        if transition_thread.ident is not None:
            transition_thread.join(2)

    assert not request_thread.is_alive()
    assert not transition_thread.is_alive()
    assert transition_returned.is_set()
    assert "value" not in request_result
    assert request_result["error"].status == 401

    registered = Api(daemon.endpoint, token_b).request(
        "POST", "/v1/capabilities", body_b
    )
    assert registered["capability_id"] == body_b["capability_id"]


def test_handoff_registration_preview_rederives_exact_actor_path_and_body_digests():
    body = {"executor_id": "astrid-pack-host", "runtime_epoch": 2}
    bodies = {
        "/v1/capabilities": [],
        "/v1/executors": [body],
    }
    state = {
        "registration_actor": "astrid-pack-host",
        "registration_bodies": bodies,
        "registration_allowlist": [
            {
                "method": "POST",
                "path": path,
                "actor": "astrid-pack-host",
                "body_sha256": sorted(registration_body_digest(item) for item in items),
            }
            for path, items in sorted(bodies.items())
        ],
    }
    actor, observed = handoff_registration_admission(state)
    assert actor == "astrid-pack-host"
    assert observed == bodies
    for mutation in (
        {**state, "registration_actor": "owner"},
        {**state, "registration_bodies": {"/v1/executors": [body]}},
        {
            **state,
            "registration_bodies": {
                **bodies,
                "/v1/executors": [{**body, "runtime_epoch": 3}],
            },
        },
        {
            **state,
            "registration_allowlist": [
                *state["registration_allowlist"][:-1],
                {
                    **state["registration_allowlist"][-1],
                    "body_sha256": ["sha256:" + "0" * 64],
                },
            ],
        },
    ):
        with pytest.raises(ConflictError):
            handoff_registration_admission(mutation)


def test_cleanup_uncertain_marker_blocks_replacement_runtime_launch(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    support.mkdir()
    (support / "orderly-handoff-cleanup-uncertain.json").write_text(
        json.dumps({"version": 1, "state": "cleanup_uncertain"}),
        encoding="utf-8",
    )
    with pytest.raises(ConflictError, match="operator recovery"):
        RuntimeDaemon(root, support_root=support).start()


def test_pending_handoff_pointer_blocks_ordinary_replacement_runtime_launch(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    owner_lock_before = (root / "owner.lock").read_bytes()
    support.mkdir(mode=0o700)
    (support / "orderly-handoff-request.json").write_text(
        json.dumps({
            "version": "runtime.local-worker-handoff-transfer/v1",
            "record_path": str(support / "orderly-handoff-record-retained.json"),
        }),
        encoding="utf-8",
    )
    stale_discovery = b'{"pid":999999,"runtime_instance_id":"stale"}\n'
    (support / "discovery.json").write_bytes(stale_discovery)
    with pytest.raises(ConflictError, match="pending audit"):
        RuntimeDaemon(root, support_root=support).start()
    assert (support / "discovery.json").read_bytes() == stale_discovery
    assert (root / "owner.lock").read_bytes() == owner_lock_before


@pytest.mark.parametrize("handoff_state", ["COMMITTED_ORPHAN", "FINALIZING"])
def test_retained_gate_after_actual_owner_b_process_loss_blocks_replacement_before_mutation(
    tmp_path, handoff_state
):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    support.mkdir(mode=0o700)
    record_path = support / "orderly-handoff-record-loss.json"
    record_path.write_text(
        json.dumps({
            "version": 1,
            "state": handoff_state,
            "handoff_id": "handoff-loss",
            "record_digest": "sha256:" + "4" * 64,
        }),
        encoding="utf-8",
    )
    record_path.chmod(0o600)
    pointer_path = support / "orderly-handoff-request.json"
    pointer_path.write_text(
        json.dumps({
            "version": "runtime.local-worker-handoff-transfer/v1",
            "handoff_id": "handoff-loss",
            "record_path": str(record_path),
        }),
        encoding="utf-8",
    )
    pointer_path.chmod(0o600)
    stale_discovery = b'{"pid":999999,"runtime_instance_id":"stale"}\n'
    (support / "discovery.json").write_bytes(stale_discovery)
    owner_lock_before = (root / "owner.lock").read_bytes()

    owner_b = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    owner_b.kill()
    owner_b.wait(timeout=5)
    assert owner_b.returncode is not None

    with pytest.raises(ConflictError, match="pending audit"):
        RuntimeDaemon(root, support_root=support).start()
    assert record_path.exists()
    assert pointer_path.exists()
    assert (support / "discovery.json").read_bytes() == stale_discovery
    assert (root / "owner.lock").read_bytes() == owner_lock_before


@pytest.mark.parametrize("gate_kind", ["malformed", "symlink"])
def test_malformed_or_symlink_handoff_gate_fails_closed_before_startup_mutation(
    tmp_path, gate_kind
):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    support.mkdir(mode=0o700)
    pointer = support / "orderly-handoff-request.json"
    if gate_kind == "malformed":
        pointer.write_bytes(b"not-json\n")
    else:
        pointer.symlink_to(support / "missing-gate-target")
    owner_lock_before = (root / "owner.lock").read_bytes()
    with pytest.raises(ConflictError, match="pending audit"):
        RuntimeDaemon(root, support_root=support).start()
    assert (root / "owner.lock").read_bytes() == owner_lock_before
    assert pointer.exists() or pointer.is_symlink()


def test_post_adopted_operator_audit_marker_preserves_record_and_blocks_replacement(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    support.mkdir(mode=0o700)
    record_path = support / "orderly-handoff-record-handoff-1.json"
    record = {
        "state": "ADOPTED",
        "handoff_id": "handoff-1",
        "record_digest": "sha256:" + "4" * 64,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    daemon = RuntimeDaemon(root, support_root=support)
    marker = daemon.latch_orderly_handoff_operator_audit(
        record_path=str(record_path),
        record=record,
        reason="injected_claim_gate_mismatch",
    )
    assert marker["handoff_state"] == "ADOPTED"
    assert marker["record_digest"] == record["record_digest"]
    assert record_path.exists()
    with pytest.raises(ConflictError, match="operator recovery"):
        RuntimeDaemon(root, support_root=support).start()
    assert record_path.exists()
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; from pathlib import Path; "
                "from runtime_protocol.daemon import RuntimeDaemon; "
                "from runtime_protocol.errors import ConflictError; "
                "root,support=map(Path,sys.argv[1:]); "
                "\ntry: RuntimeDaemon(root,support_root=support).start()"
                "\nexcept ConflictError: raise SystemExit(23)"
                "\nraise SystemExit(24)"
            ),
            str(root),
            str(support),
        ],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 23, completed.stderr
    assert record_path.exists()


def test_runtime_stop_exposes_complete_authority_cleanup_proof(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=support).start()
    daemon.stop()
    proof = daemon.last_handoff_cleanup_proof()
    assert proof == {
        "version": 1,
        "runtime_instance_id": daemon.instance_id,
        "graph_and_engine_listener_absent": True,
        "authority_descriptors_closed": True,
        "worker_credential_revoked": True,
        "catalog_neutral": True,
        "discovery_absent": True,
        "replacement_graph_not_launched": True,
        "final_census": {
            "http_server_present": False,
            "local_worker_launcher_present": False,
            "inherited_listener_fd_present": False,
            "worker_credential_enabled": False,
            "catalog_ready": False,
            "discovery_present": False,
        },
        "complete": True,
    }


def _fake_cleanup_launcher(*, pid, birth_id, port):
    receipt = {
        "evidence_digest": "sha256:" + "9" * 64,
        "engine_binding": {"endpoint": f"http://127.0.0.1:{port}"},
    }
    for role in ("worker", "host", "engine", "engine_listener"):
        receipt[role] = {"pid": pid, "birth_id": birth_id, "role": role}

    class Launcher:
        def cleanup_receipt_snapshot(self):
            return receipt

        def begin_shutdown(self):
            return []

        def finish_shutdown(self, _handles):
            return None

    return Launcher()


def test_aborted_cleanup_census_treats_live_pid_with_unavailable_birth_as_uncertain(
    tmp_path, monkeypatch
):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=support)
    daemon.local_worker_launcher = _fake_cleanup_launcher(
        pid=os.getpid(), birth_id="expected-birth", port=port
    )
    monkeypatch.setattr("runtime_protocol.daemon.process_birth_identity", lambda _pid=None: None)
    with pytest.raises(ConflictError, match="cleanup is uncertain"):
        daemon.stop()
    proof = daemon.last_handoff_cleanup_proof()
    assert sorted(proof["final_census"]["uncertainties"]) == [
        "birth_identity_unavailable:engine",
        "birth_identity_unavailable:engine_listener",
        "birth_identity_unavailable:host",
        "birth_identity_unavailable:worker",
    ]
    assert all(row["absent"] is False for row in proof["final_census"]["process_rows"])


def test_aborted_cleanup_census_does_not_call_bound_non_listening_port_free(tmp_path):
    support = tmp_path / "support"
    support.mkdir(mode=0o700)
    bound = socket.socket()
    bound.bind(("127.0.0.1", 0))
    port = bound.getsockname()[1]
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=support)
    daemon.local_worker_launcher = _fake_cleanup_launcher(
        pid=999999, birth_id="absent-birth", port=port
    )
    try:
        with pytest.raises(ConflictError, match="cleanup is uncertain"):
            daemon.stop()
        listener = daemon.last_handoff_cleanup_proof()["final_census"]["listener"]
        assert listener["port_free"] is False
        assert listener["owner_absent"] is False
        assert listener["observed_owner_pid"] == -1
    finally:
        bound.close()


def test_broken_post_admission_stdout_does_not_stop_healthy_runtime(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    metadata = tmp_path / "metadata.json"
    emitted = tmp_path / "emitted"
    script = (
        "import json,sys,time; from pathlib import Path; "
        "from runtime_protocol.store import RealmStore; "
        "from runtime_protocol.daemon import RuntimeDaemon; "
        "from runtime_protocol.cli import _emit_post_admission_report; "
        "root,support,metadata,emitted=map(Path,sys.argv[1:]); "
        "RealmStore.initialize(root).close(); "
        "daemon=RuntimeDaemon(root,support_root=support).start(); "
        "metadata.write_text(json.dumps({'endpoint':daemon.endpoint,'token':daemon.token})); "
        "time.sleep(0.5); "
        "_emit_post_admission_report({'endpoint':daemon.endpoint,'status':'ready'}); "
        "emitted.write_text('ok'); time.sleep(30)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(root), str(support), str(metadata), str(emitted)],
        cwd=Path(__file__).parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not metadata.exists():
            assert process.poll() is None
            time.sleep(0.02)
        assert metadata.exists()
        assert process.stdout is not None
        process.stdout.close()
        while time.monotonic() < deadline and not emitted.exists():
            assert process.poll() is None
            time.sleep(0.02)
        assert emitted.exists()
        observed = json.loads(metadata.read_text())
        request = urllib.request.Request(
            observed["endpoint"] + "/v1/doctor",
            headers={"Authorization": f"Bearer {observed['token']}"},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
        assert process.poll() is None
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def test_inherited_listener_without_exact_adopter_tuple_fails_before_publication(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    RealmStore.initialize(root).close()
    owner_a = RuntimeDaemon(root, support_root=support).start()
    endpoint = owner_a.endpoint
    listener_fd = os.dup(owner_a.httpd.socket.fileno())
    os.set_inheritable(listener_fd, False)
    worker_token = owner_a.credentials.path_for("astrid-pack-host").read_text(
        encoding="utf-8"
    )
    owner_a.stop()

    capability = "handoff.inherited"
    digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
    body = {
        "executor_id": "astrid-pack-host",
        "capabilities": [
            {
                "capability_id": capability,
                "definition_digest": digest,
                "status": "ready",
                "required_resource_keys": [],
                "estimated_scratch_bytes": 0,
                "estimated_output_bytes": 1,
            }
        ],
        "max_concurrency": 1,
        "resource_keys": [],
        "protocol": "workspace.v1",
    }
    try:
        with pytest.raises(ConflictError, match="binding tuple is incomplete"):
            RuntimeDaemon(
                root,
                support_root=support,
                inherited_listener_fd=listener_fd,
                handoff_registration_actor="astrid-pack-host",
                handoff_registration_bodies={"/v1/executors": [body]},
            ).start()
        assert not (support / "discovery.json").exists()
    finally:
        os.close(listener_fd)


def test_timeline_create_replays_receipt_and_conflicts_on_changed_request(daemon, tmp_path):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = client.create_project("timeline-idempotency", idempotency_key="timeline-project")
    first = client.create_timeline(project.project_id, "timeline-a", idempotency_key="timeline-create")
    replay = client.create_timeline(project.project_id, "timeline-a", idempotency_key="timeline-create")
    assert first == replay
    assert first.receipt["command_kind"] == "timeline.create"
    with pytest.raises(ApiError) as changed:
        client.create_timeline(project.project_id, "timeline-b", idempotency_key="timeline-create")
    assert changed.value.status == 409
    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        after_restart = WorkspaceClient(restarted.endpoint, restarted.token).create_timeline(project.project_id, "timeline-a", idempotency_key="timeline-create")
        assert after_restart == first
        assert restarted.service.store.conn.execute("SELECT COUNT(*) FROM timelines").fetchone()[0] == 1
    finally:
        restarted.stop()


def test_claim_requires_key_and_duplicate_or_changed_requests_replay_or_conflict(daemon):
    client = Api(daemon.endpoint, daemon.token)
    project = client.create_project("claim-idempotency", "Claim Idempotency", idempotency_key="claim-project")
    task = client.create_task("render.basic", {"text": "claim"}, project=project["project_id"], idempotency_key="claim-task")
    client.register_executor("claim-executor", ["render.basic"], idempotency_key="claim-executor")
    epoch = client.health()["runtime_epoch"]
    body = {"executor_id": "claim-executor", "capability_ids": ["render.basic"], "runtime_epoch": epoch}
    with pytest.raises(RuntimeError) as missing:
        client.request("POST", "/v1/tasks/claim", body)
    assert missing.value.status == 400
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: client.request("POST", "/v1/tasks/claim", body, headers={"Idempotency-Key": "claim-command"}), range(2)))
    first, replay = results
    assert replay == first
    claimed_task_id = first["task_id"] if "task_id" in first else first["task"]["task_id"]
    assert claimed_task_id == task["task_id"]
    with pytest.raises(RuntimeError) as changed:
        client.request("POST", "/v1/tasks/claim", {**body, "capability_ids": []}, headers={"Idempotency-Key": "claim-command"})
    assert changed.value.status == 409
    assert client.request("GET", f"/v1/tasks/{task['task_id']}")["state"] == "running"


def test_project_patch_and_run_cancel_retry_are_durable_and_idempotent(daemon, tmp_path):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = client.create_project("mutations", idempotency_key="mutation-project")
    updated = client.update_project(project.project_id, idempotency_key="project-update", expected_version=1, name="Mutated")
    assert updated.version == 2 and updated.name == "Mutated"
    assert client.update_project(project.project_id, idempotency_key="project-update", expected_version=1, name="Mutated").version == 2
    with pytest.raises(ApiError) as stale:
        client.update_project(project.project_id, idempotency_key="project-stale", expected_version=1, name="stale")
    assert stale.value.status == 409

    digest = "sha256:" + hashlib.sha256(b"render.basic").hexdigest()
    cancelled = client.admit_task(capability_id="render.basic", capability_digest=digest, input_object_ids=[], project_id=project.project_id, idempotency_key="cancel-child")
    run = client.cancel_run(cancelled.run_id, idempotency_key="run-cancel")
    assert run["status"] == "cancelled"
    assert client.get_task(cancelled.task_id).state == "cancelled"
    assert client.cancel_run(cancelled.run_id, idempotency_key="run-cancel")["status"] == "cancelled"
    with pytest.raises(ApiError) as conflict:
        client.cancel_run(cancelled.run_id, idempotency_key="run-cancel-conflict")
    assert conflict.value.status == 409

    failed = client.admit_task(capability_id="render.basic", capability_digest=digest, input_object_ids=[], project_id=project.project_id, idempotency_key="retry-child")
    client.register_executor({"executor_id": "mutation-worker", "max_concurrency": 1, "resource_keys": [], "capabilities": [{"capability_id": "render.basic", "definition_digest": digest, "status": "ready", "required_resource_keys": [], "estimated_scratch_bytes": 0, "estimated_output_bytes": 1}], "protocol": "workspace.v1"}, idempotency_key="mutation-worker")
    worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
    first = worker.claim_task(executor_id="mutation-worker", capability_ids=["render.basic"], idempotency_key="mutation-claim-1", runtime_epoch=worker.health().runtime_epoch)
    assert first is not None
    worker.fail_attempt(first["attempt_id"], lease_id=first["lease_id"], fence=first["fence"], error={"reason": "probe"}, runtime_epoch=first["runtime_epoch"], idempotency_key="mutation-fail")
    retried = client.retry_run(failed.run_id, idempotency_key="run-retry")
    assert retried["status"] == "queued"
    assert client.retry_run(failed.run_id, idempotency_key="run-retry")["status"] == "queued"
    events, _cursor = client.list_run_events(failed.run_id)
    assert [event.event_type for event in events][-2:] == ["task.retried", "run.retried"]
    second = worker.claim_task(executor_id="mutation-worker", capability_ids=["render.basic"], idempotency_key="mutation-claim-2", runtime_epoch=worker.health().runtime_epoch)
    assert second["fence"] > first["fence"] and second["attempt_id"] != first["attempt_id"]
    with pytest.raises(ApiError) as stale_fence:
        worker.settle_attempt(
            second["attempt_id"],
            {
                "lease_id": second["lease_id"],
                "fence": first["fence"],
                "runtime_epoch": second["runtime_epoch"],
                "outputs": [],
            },
            idempotency_key="mutation-stale-f1-fence",
        )
    assert stale_fence.value.status == 409
    assert stale_fence.value.code == "lease_fenced"
    assert stale_fence.value.message == "attempt fence is stale"
    assert stale_fence.value.details == {
        "expected": second["fence"],
        "actual": first["fence"],
    }
    after_stale_fence = client.get_task(failed.task_id)
    assert after_stale_fence.state == "running"
    assert after_stale_fence.attempt_id == second["attempt_id"]
    assert worker.settle_attempt(
        second["attempt_id"],
        {
            "lease_id": second["lease_id"],
            "fence": second["fence"],
            "runtime_epoch": second["runtime_epoch"],
            "outputs": [],
        },
        idempotency_key="mutation-current-f2-settle",
    ).state == "succeeded"

    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        replay = WorkspaceClient(restarted.endpoint, restarted.token)
        assert replay.retry_run(failed.run_id, idempotency_key="run-retry")["status"] == "queued"
        assert replay.get_project(project.project_id).name == "Mutated"
    finally:
        restarted.stop()


def test_project_shot_reference_crud_isolated_idempotent_and_restart_durable(daemon, tmp_path):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    first = client.create_project("shots-a", idempotency_key="shots-project-a")
    second = client.create_project("shots-b", idempotency_key="shots-project-b")
    media = client.ingest_project_object(first.project_id, b"reference-media", media_type="application/octet-stream", idempotency_key="shots-media")
    shot_body = {"shot_id": "project-shot", "name": "Project Shot", "metadata": {"scene": 1}}
    reference_body = {"reference_id": "project-reference", "kind": "character", "name": "Aria", "media_id": media.object_id}
    shot = client.create_project_shot(first.project_id, shot_body, idempotency_key="project-shot-create")
    reference = client.create_project_reference(first.project_id, reference_body, idempotency_key="project-reference-create")
    assert shot["project_id"] == first.project_id and reference["project_id"] == first.project_id
    assert client.create_project_shot(first.project_id, shot_body, idempotency_key="project-shot-create") == shot
    assert client.create_project_reference(first.project_id, reference_body, idempotency_key="project-reference-create") == reference
    with pytest.raises(ApiError) as mismatch:
        client.create_project_shot(first.project_id, {**shot_body, "name": "Changed"}, idempotency_key="project-shot-create")
    assert mismatch.value.status == 409
    assert client.list_project_shots(first.project_id)[0][0]["shot_id"] == "project-shot"
    assert client.list_project_shots(second.project_id)[0] == []
    assert client.list_project_references(second.project_id)[0] == []

    updated = client.update_project_shot(first.project_id, "project-shot", expected_version=1, name="Updated Shot", idempotency_key="project-shot-update")
    assert updated["version"] == 2 and updated["name"] == "Updated Shot"
    assert client.update_project_shot(first.project_id, "project-shot", expected_version=1, name="Updated Shot", idempotency_key="project-shot-update") == updated
    with pytest.raises(ApiError) as stale:
        client.update_project_shot(first.project_id, "project-shot", expected_version=1, name="stale", idempotency_key="project-shot-stale")
    assert stale.value.status == 409
    archived = client.archive_project_shot(first.project_id, "project-shot", expected_version=updated["version"], idempotency_key="project-shot-archive")
    assert archived["archived"] is True
    assert client.list_project_shots(first.project_id)[0] == []
    recovered = client.recover_project_shot(first.project_id, "project-shot", expected_version=archived["version"], idempotency_key="project-shot-recover")
    assert recovered["archived"] is False
    ref_updated = client.update_project_reference(first.project_id, "project-reference", expected_version=1, name="Aria Prime", idempotency_key="project-reference-update")
    ref_archived = client.archive_project_reference(first.project_id, "project-reference", expected_version=ref_updated["version"], idempotency_key="project-reference-archive")
    ref_recovered = client.recover_project_reference(first.project_id, "project-reference", expected_version=ref_archived["version"], idempotency_key="project-reference-recover")
    assert ref_recovered["name"] == "Aria Prime" and ref_recovered["archived"] is False
    second_media = client.ingest_project_object(first.project_id, b"second-media", media_type="application/octet-stream", idempotency_key="shots-media-2")
    with_item = client.add_shot_item(first.project_id, "project-shot", {"item_id": "item-a", "media_id": media.object_id, "position": 0}, idempotency_key="shot-item-a")
    with_two = client.add_shot_item(first.project_id, "project-shot", {"item_id": "item-b", "media_id": second_media.object_id, "position": 1}, idempotency_key="shot-item-b")
    reordered = client.reorder_shot_items(first.project_id, "project-shot", ["item-b", "item-a"], expected_version=with_two["version"], idempotency_key="shot-reorder")
    removed = client.remove_shot_item(first.project_id, "project-shot", "item-a", expected_version=reordered["version"], idempotency_key="shot-item-remove")
    assert [item["item_id"] for item in removed["items"]] == ["item-b"]
    associated = client.associate_reference(first.project_id, "project-reference", {"association_id": "assoc-b", "media_id": second_media.object_id, "role": "depicts"}, idempotency_key="reference-associate")
    primary = client.set_primary_reference(first.project_id, "project-reference", "assoc-b", expected_version=associated["version"], idempotency_key="reference-primary")
    linked_ref = client.create_project_reference(first.project_id, {"reference_id": "project-reference-2", "kind": "object", "name": "Prop", "media_id": media.object_id}, idempotency_key="reference-2")
    link = client.link_references(first.project_id, {"from_reference_id": "project-reference", "to_reference_id": linked_ref["reference_id"], "kind": "associated_with"}, idempotency_key="reference-link")
    assert primary["media_references"][-1]["is_primary"] is True and link["kind"] == "associated_with"

    daemon.stop()
    restarted = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        replay = WorkspaceClient(restarted.endpoint, restarted.token)
        assert replay.create_project_shot(first.project_id, shot_body, idempotency_key="project-shot-create") == shot
        assert replay.get_project_shot(first.project_id, "project-shot")["name"] == "Updated Shot"
        assert replay.get_project_reference(first.project_id, "project-reference")["archived"] is False
    finally:
        restarted.stop()


def test_restart_reconnect_and_catalog_discovery(daemon, tmp_path):
    client = Api(daemon.endpoint, daemon.token)
    project = client.create_project("persist", "Persistent")
    realm_id = client.get_project(project["project_id"])["realm_id"]
    discovery = json.loads((tmp_path / "support" / "discovery.json").read_text())
    catalog = json.loads((tmp_path / "support" / "catalog.json").read_text())
    assert discovery["active_realm"] == realm_id
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
    RealmStore.initialize(tmp_path / "realm").close()
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
    RealmStore.initialize(root).close()
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
    effect = {"effect_type": "project.update", "target_id": project["project_id"], "expected_version": 1, "payload": {"name": "Settled Effect"}}
    task = client.create_task("render.basic", {}, project=project["project_id"], expected_effect=effect)
    task_id = task["task_id"]
    client.register_executor("effect-worker", ["render.basic"], idempotency_key="executor-effect")
    worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
    attempt = worker.claim_task(executor_id="effect-worker", capability_ids=["render.basic"], idempotency_key="effect-claim", runtime_epoch=worker.health().runtime_epoch)
    assert attempt is not None
    with pytest.raises(ApiError):
        worker.settle_attempt(attempt["attempt_id"], {"lease_id": "bad", "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": []}, idempotency_key="effect-bad-lease")
    with pytest.raises(ApiError):
        worker.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [], "effect": {"kind": "other"}}, idempotency_key="effect-bad-effect")
    settled = worker.settle_attempt(attempt["attempt_id"], {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"], "outputs": [], "effect": effect}, idempotency_key="effect-settle")
    assert settled.state == "succeeded"
    updated = client.get_project(project["project_id"])
    assert updated["name"] == "Settled Effect" and updated["version"] == 2
