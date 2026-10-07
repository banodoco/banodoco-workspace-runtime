from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import ApiError, Capability, ClaimWaiting, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore


class _AcquisitionStream(io.BytesIO):
    def __init__(self, body, chunk=None):
        super().__init__(body)
        self.status = 200
        self.headers = {}
        self.chunk = chunk
        self.read_sizes = []
        self.acquired = 0

    def read(self, size=-1):
        self.read_sizes.append(size)
        data = super().read(min(size, self.chunk) if self.chunk and size >= 0 else size)
        self.acquired += len(data)
        return data


@pytest.mark.parametrize("error", [False, True])
@pytest.mark.parametrize("chunk", [None, 1, 3])
@pytest.mark.parametrize("extra", [-1, 0, 1, 1000])
def test_acquisition_reader_stream_bounds_and_closure(monkeypatch, error, chunk, extra):
    cap = 8
    stream = _AcquisitionStream(b"x" * (cap + extra), chunk)
    def open_response(request, timeout):
        assert request.get_header("Authorization") == "Bearer token"
        assert request.get_header("X-request-id") == "selected-request"
        assert timeout == 7
        if error:
            raise urllib.error.HTTPError(request.full_url, 409, "Conflict", {}, stream)
        return stream
    monkeypatch.setattr(urllib.request, "urlopen", open_response)
    def reader(response):
        result = bytearray()
        while True:
            data = response.read(cap + 1 - len(result))
            result.extend(data)
            if len(result) > cap:
                raise ValueError("overflow")
            if not data:
                return bytes(result)
    client = WorkspaceClient("http://runtime", "token", timeout=7)
    if extra > 0:
        with pytest.raises(ValueError, match="overflow"):
            client._request("GET", "/probe", headers={"X-Request-ID": "selected-request"}, response_reader=reader)
        assert stream.acquired == cap + 1
    elif error:
        with pytest.raises(ApiError) as caught:
            client._request("GET", "/probe", headers={"X-Request-ID": "selected-request"}, response_reader=reader)
        assert caught.value.status == 409
    else:
        assert client._request("GET", "/probe", headers={"X-Request-ID": "selected-request"}, response_reader=reader)[2] == b"x" * (cap + extra)
    assert stream.closed
    assert all(0 < size <= cap + 1 for size in stream.read_sizes)
    assert stream.acquired <= cap + 1


@pytest.mark.parametrize("http_error", [False, True])
@pytest.mark.parametrize("failure", [ValueError("reader"), TimeoutError("reader"), urllib.error.URLError("reader")])
def test_acquisition_reader_policy_exception_propagates_and_closes(monkeypatch, http_error, failure):
    stream = _AcquisitionStream(b"private-body")
    def open_response(request, timeout):
        if http_error:
            raise urllib.error.HTTPError(request.full_url, 400, "Bad", {}, stream)
        return stream
    monkeypatch.setattr(urllib.request, "urlopen", open_response)
    def reader(response):
        raise failure
    with pytest.raises(type(failure)) as caught:
        WorkspaceClient("http://runtime")._request("GET", "/probe", response_reader=reader)
    assert caught.value is failure
    assert stream.closed and not stream.read_sizes


def test_acquisition_reader_default_behavior_and_four_argument_transport(monkeypatch):
    stream = _AcquisitionStream(b"{}")
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout: stream)
    assert WorkspaceClient("http://runtime")._request("GET", "/probe")[2] == b"{}"
    assert stream.read_sizes == [-1] and stream.closed
    calls = []
    def transport(method, path, headers, body):
        calls.append((method, path, headers, body))
        return 200, {}, b"{}"
    client = WorkspaceClient("http://runtime", "token", transport=transport)
    assert client._request("GET", "/probe")[2] == b"{}"
    assert client._request("GET", "/probe", response_reader=lambda response: response.read(3))[2] == b"{}"
    assert len(calls) == 2 and all(len(call) == 4 for call in calls)
    assert all(call[2]["Authorization"] == "Bearer token" for call in calls)


def test_acquisition_selected_python_renderer_parity(tmp_path):
    import importlib.util
    root = Path(__file__).parents[1]
    spec = importlib.util.spec_from_file_location("selected_python_renderer", root / "generators/generate.py")
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    isolated = tmp_path / "selected-generated.py"
    isolated.write_text(renderer.render_python_client())
    assert f'SCHEMA_DIGEST = "{renderer.contract_digest()}"' in isolated.read_text()
    assert isolated.read_bytes() == (root / "packages/python/banodoco_workspace_client/generated.py").read_bytes()


def test_generated_client_smoke_and_scoped_handshake() -> None:
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, body))
        if path == "/v1/health":
            return 200, {}, json.dumps({"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "runtime_epoch": 1, "runtime_session_id": "runtime-session-1", "runtime_instance_id": "runtime-instance-1"}).encode()
        if path == "/v1/handshake":
            return 200, {}, json.dumps({"protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "session_id": "session-1", "actor_id": "actor-1", "realm_id": "realm-1", "scopes": ["realm:read", "project:write"]}).encode()
        if path == "/v1/projects" and method == "POST":
            return 201, {}, json.dumps({"data": {"project_id": "project-1", "realm_id": "realm-1", "name": "Neutral", "version": 1, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}, "receipt": {"receipt_id": "runtime-command-1", "command_kind": "project.create", "idempotency_key": "create-1", "request_hash": "sha256:" + "a" * 64, "project_id": "project-1", "project_seq": [1, 1], "event_ids": [], "result": {}, "created_at": "2026-01-01T00:00:00Z"}}).encode()
        raise AssertionError((method, path))

    client = WorkspaceClient("http://runtime", "token", transport=transport)
    health = client.health()
    assert health["protocol"] == "workspace.v1"
    assert health.runtime_session_id == "runtime-session-1"
    assert health.runtime_instance_id == "runtime-instance-1"
    session = client.handshake("second-product", "0.1.0", ["realm:read", "project:write"])
    assert session.realm_id == "realm-1"
    project = client.create_project("Neutral", idempotency_key="create-1")
    assert project.project_id == "project-1"
    assert project.receipt["command_kind"] == "project.create"
    assert calls[-1][2]["Authorization"] == "Bearer token"
    assert calls[-1][2]["Idempotency-Key"] == "create-1"


def test_connected_register_executor_response_uses_generated_capability_parser(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        registered = client.register_executor(
            {
                "executor_id": "ordinary-worker",
                "max_concurrency": 1,
                "resource_keys": [],
                # Runtime keeps the existing ID-list registration input
                # compatibility; the response must still satisfy the
                # canonical generated Executor parser.
                "capabilities": ["render.basic"],
                "protocol": "workspace.v1",
            },
            idempotency_key="register-ordinary-worker",
        )
        capability = registered.capabilities[0]
        assert isinstance(capability, Capability)
        assert capability.capability_id == "render.basic"
        assert capability.definition_digest.startswith("sha256:")
        task = client.admit_task(
            capability_id=capability.capability_id,
            capability_digest=capability.definition_digest,
            input_object_ids=[],
            idempotency_key="admit-after-register",
        )
        assert task["capability_id"] == capability.capability_id
    finally:
        daemon.stop()


def test_generation_intent_round_trips_through_admission_claim_and_terminal_readback(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    intent = {
        "version": 1,
        "modality": "video",
        "partial_success_policy": "allow",
        "groups": [
            {
                "group_key": "main",
                "selectors": [
                    {"selector": "video", "ordinal": 0, "variant_key": "original"},
                ],
            },
        ],
    }
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        registered = client.register_executor(
            {
                "executor_id": "generation-intent-worker",
                "max_concurrency": 1,
                "resource_keys": [],
                "capabilities": ["generation.intent"],
                "protocol": "workspace.v1",
            },
            idempotency_key="generation-intent-register",
        )
        capability = registered.capabilities[0]
        admitted = client.admit_task(
            capability_id=capability.capability_id,
            capability_digest=capability.definition_digest,
            input_object_ids=[],
            idempotency_key="generation-intent-admit",
            generation_intent=intent,
        )
        assert admitted["generation_intent"] == intent
        assert "generation_intent" not in admitted["spec"]

        task = client.get_task(admitted["task_id"])
        assert task.generation_intent == intent
        assert "generation_intent" not in task.spec
        worker = WorkspaceClient(daemon.endpoint, daemon.worker_token)
        attempt = worker.claim_task(
            executor_id="generation-intent-worker",
            capability_ids=[capability.capability_id],
            idempotency_key="generation-intent-claim",
            runtime_epoch=worker.health().runtime_epoch,
        )
        assert attempt.generation_intent == intent
        assert "generation_intent" not in attempt.spec
        settled = worker.settle_attempt(
            attempt.attempt_id,
            {
                "lease_id": attempt.lease_id,
                "fence": attempt.fence,
                "runtime_epoch": attempt.runtime_epoch,
                "outputs": [],
                "effect": None,
            },
            idempotency_key="generation-intent-settle",
        )
        assert settled["state"] == "succeeded"
        terminal = client.get_task(task.task_id)
        assert terminal.state == "succeeded"
        assert terminal.generation_intent == intent
        assert "generation_intent" not in terminal.spec

        # Read a row written by the pre-fix Runtime shape: the legacy key is
        # accepted for compatibility but never leaks into public spec.
        row = daemon.service.store.conn.execute(
            "SELECT spec_json FROM tasks WHERE id=?", (task.task_id,)
        ).fetchone()
        legacy_spec = json.loads(row["spec_json"])
        legacy_spec["generation_intent"] = legacy_spec.pop("__runtime_generation_intent")
        daemon.service.store.conn.execute(
            "UPDATE tasks SET spec_json=? WHERE id=?",
            (json.dumps(legacy_spec, sort_keys=True, separators=(",", ":")), task.task_id),
        )
        daemon.service.store.conn.commit()
        legacy = client.get_task(task.task_id)
        assert legacy.generation_intent == intent
        assert "generation_intent" not in legacy.spec

        generic = client.admit_task(
            capability_id=capability.capability_id,
            capability_digest=capability.definition_digest,
            input_object_ids=[],
            idempotency_key="generation-intent-generic-admit",
        )
        assert "generation_intent" not in generic
        assert client.get_task(generic["task_id"]).generation_intent is None
    finally:
        daemon.stop()


def test_object_byte_range_etag_and_head_are_preserved() -> None:
    payload = b"0123456789"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers))
        assert headers["Range"] == "bytes=2-5"
        result = {"ETag": f'"{digest}"', "Content-Range": "bytes 2-5/10", "Accept-Ranges": "bytes"}
        return 206, result, payload[2:6] if method == "GET" else b""

    client = WorkspaceClient("http://runtime", transport=transport)
    result = client.get_object("obj-1", byte_range=(2, 5))
    assert result.status == 206 and result.data == b"2345"
    assert result.etag == f'"{digest}"' and result.content_range == "bytes 2-5/10"
    head = client.head_object("obj-1", byte_range=(2, 5))
    assert head.status == 206 and calls[-1][0] == "HEAD"


def test_invalid_range_is_rejected_before_transport() -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: (_ for _ in ()).throw(AssertionError("called")))
    try:
        client.get_object("obj", byte_range=(5, 2))
    except ValueError as exc:
        assert "range" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_generated_run_events_preserve_event_page_contract() -> None:
    event = {
        "event_id": "1", "sequence": 1, "cursor": "1",
        "event_type": "task.admitted", "aggregate_type": "run",
        "aggregate_id": "run-1", "payload": {},
        "occurred_at": "2026-01-01T00:00:00Z",
    }

    def transport(method, path, headers, body):
        assert method == "GET" and path == "/v1/runs/run-1/events"
        return 200, {}, json.dumps({"items": [event], "next_cursor": None}).encode()

    items, cursor = WorkspaceClient("http://runtime", transport=transport).list_run_events("run-1")
    assert items[0].event_id == "1"
    assert cursor is None


def test_api_error_preserves_conflict_and_version_details() -> None:
    def transport(*args):
        return 409, {}, json.dumps({"code": "version_conflict", "message": "stale", "request_id": "req-1", "details": {"expected": 2, "actual": 3}}).encode()

    try:
        WorkspaceClient("http://runtime", transport=transport).get_project("p")
    except ApiError as exc:
        assert exc.status == 409 and exc.code == "version_conflict" and exc.details["actual"] == 3
    else:
        raise AssertionError("expected ApiError")


def test_client_correlates_transport_timeout_and_http_failure() -> None:
    observed_request_ids = []

    def timed_out(_method, _path, headers, _body):
        observed_request_ids.append(headers["X-Request-ID"])
        raise TimeoutError("late")

    with pytest.raises(ApiError) as timeout_error:
        WorkspaceClient("http://runtime", transport=timed_out, timeout=0.25).health()
    assert timeout_error.value.code == "transport_timeout"
    assert timeout_error.value.request_id == observed_request_ids[0]

    def rejected(_method, _path, headers, _body):
        observed_request_ids.append(headers["X-Request-ID"])
        return 503, {}, json.dumps({"code": "registration_failed", "message": "terminal"}).encode()

    with pytest.raises(ApiError) as rejected_error:
        WorkspaceClient("http://runtime", transport=rejected).health()
    assert rejected_error.value.code == "registration_failed"
    assert rejected_error.value.request_id == observed_request_ids[1]


def test_client_applies_bounded_timeout_to_stdlib_transport(monkeypatch) -> None:
    observed = {}

    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "runtime_epoch": 1, "runtime_session_id": "runtime-session-1", "runtime_instance_id": "runtime-instance-1"}).encode()

    def urlopen(request, *, timeout):
        observed["timeout"] = timeout
        observed["request_id"] = request.headers["X-request-id"]
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    client = WorkspaceClient("http://runtime", timeout=1.5)
    assert client.health().status == "ok"
    assert client.health().runtime_instance_id == "runtime-instance-1"
    assert observed["timeout"] == 1.5
    assert observed["request_id"].startswith("request-")
    with pytest.raises(ValueError, match="finite and positive"):
        WorkspaceClient("http://runtime", timeout=0)


def test_claim_capability_unavailable_is_typed_waiting_result() -> None:
    digest = "sha256:" + "a" * 64
    task = {
        "task_id": "task-1", "run_id": "run-1", "state": "queued", "version": 1,
        "capability_id": "render.gpu", "capability_digest": digest,
        "idempotency_key": "admit-1", "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z", "runtime_epoch": 1,
        "waiting_reason": "capability_unavailable",
    }

    def transport(method, path, headers, body):
        assert method == "POST" and path == "/v1/tasks/claim"
        return 200, {}, json.dumps({"task": task, "waiting_reason": "capability_unavailable"}).encode()

    result = WorkspaceClient("http://runtime", transport=transport).claim_task(
        executor_id="worker-1", capability_ids=["render.gpu"],
        idempotency_key="claim-1", runtime_epoch=1,
    )
    assert isinstance(result, ClaimWaiting)
    assert result.waiting_reason == "capability_unavailable"
    assert result.task.task_id == "task-1"


def test_generated_task_lease_fields_decode_from_get_and_project_list() -> None:
    digest = "sha256:" + "a" * 64
    expired = "2026-01-01T00:00:00+00:00"
    deadline = "2026-01-02T00:00:00+00:00"

    def task(task_id: str, **lease_fields):
        return {
            "task_id": task_id,
            "run_id": "run-1",
            "project_id": "project-1",
            "state": "running",
            "version": 2,
            "capability_id": "render.basic",
            "capability_digest": digest,
            "idempotency_key": f"admit-{task_id}",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "runtime_epoch": 3,
            "input_object_ids": [],
            "spec": {},
            **lease_fields,
        }

    listed = [
        task("listed-task", lease_fence=8, lease_expires_at=deadline),
        task("missing-lease-task"),
        task("null-lease-task", lease_fence=None, lease_expires_at=None),
    ]

    def transport(method, path, headers, body):
        assert method == "GET"
        if path == "/v1/tasks/get-task":
            return 200, {}, json.dumps(task("get-task", lease_fence=7, lease_expires_at=expired)).encode()
        if path == "/v1/projects/project-1/tasks?limit=50":
            return 200, {}, json.dumps({"items": listed, "next_cursor": None}).encode()
        raise AssertionError((method, path))

    client = WorkspaceClient("http://runtime", transport=transport)
    fetched = client.get_task("get-task")
    tasks, next_cursor = client.list_project_tasks("project-1")

    assert (fetched.lease_fence, fetched.lease_expires_at) == (7, expired)
    assert next_cursor is None
    assert [(item.task_id, item.lease_fence, item.lease_expires_at) for item in tasks] == [
        ("listed-task", 8, deadline),
        ("missing-lease-task", None, None),
        ("null-lease-task", None, None),
    ]


def test_distinct_tasks_reader_reads_expired_running_task_lease_fields(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(
        realm,
        support_root=tmp_path / "support",
    ).start()
    try:
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        executor_spec = {
            "executor_id": "executor-a",
            "max_concurrency": 1,
            "resource_keys": [],
            "capabilities": ["lease-projection"],
            "protocol": "workspace.v1",
        }
        registered = owner.register_executor(
            executor_spec,
            idempotency_key="lease-projection-register",
        )
        owner.register_executor(
            {**executor_spec, "executor_id": "executor-b"},
            idempotency_key="lease-projection-register-b",
        )
        capability = registered.capabilities[0]
        admitted = owner.admit_task(
            capability_id=capability.capability_id,
            capability_digest=capability.definition_digest,
            input_object_ids=[],
            idempotency_key="lease-projection-admit",
        )
        executor_a_token, _ = daemon.credentials.provision(
            "executor-a", ["handshake", "worker:execute", "tasks:read"]
        )
        executor_a = WorkspaceClient(daemon.endpoint, executor_a_token)
        claimed = executor_a.claim_task(
            executor_id="executor-a",
            capability_ids=[capability.capability_id],
            idempotency_key="lease-projection-claim",
            runtime_epoch=executor_a.health().runtime_epoch,
        )
        assert claimed is not None and not isinstance(claimed, ClaimWaiting)

        expired = "2000-01-01T00:00:00+00:00"
        daemon.service.store.conn.execute(
            "UPDATE tasks SET lease_expires_at=? WHERE id=?",
            (expired, admitted["task_id"]),
        )
        daemon.service.store.conn.execute(
            "UPDATE attempts SET lease_expires_at=? WHERE id=?",
            (expired, claimed.attempt_id),
        )
        daemon.service.store.conn.commit()

        reader_token, _ = daemon.credentials.provision("executor-b", ["tasks:read"])
        reader_identity = daemon.credentials.actor_metadata("executor-b")
        assert reader_identity["actor"] == "executor-b"
        assert "tasks:read" in reader_identity["scopes"]
        assert "admin" not in reader_identity["scopes"]
        assert reader_identity["actor"] != "executor-a"

        readback = WorkspaceClient(daemon.endpoint, reader_token).get_task(admitted["task_id"])
        assert readback.state == "running"
        assert readback.lease_fence == claimed.fence
        assert readback.lease_expires_at == expired
    finally:
        daemon.stop()


def test_generated_child_authority_client_preserves_legacy_shape_and_forwards_d18_descriptors() -> None:
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, json.loads(body)))
        return 200, {}, b"{}"

    client = WorkspaceClient("http://runtime", transport=transport)
    client.issue_child_authority("attempt-1", lease_id="lease-1", fence=2, runtime_epoch=7)
    assert calls[-1][3] == {"lease_id": "lease-1", "fence": 2, "runtime_epoch": 7}

    child = {
        "child_id": "child-1",
        "capability_id": "render.child",
        "capability_digest": "sha256:" + "a" * 64,
    }
    derived_inputs = [{
        "name": "source-frame",
        "output_port": "frame",
        "filename": "source-frame.bin",
        "object_id": "sha256:" + "b" * 64,
        "size": 4096,
        "media_type": "application/octet-stream",
    }]
    client.issue_child_authority(
        "attempt-1",
        lease_id="lease-1",
        fence=2,
        runtime_epoch=7,
        child=child,
        derived_inputs=derived_inputs,
    )
    assert calls[-1][3] == {
        "lease_id": "lease-1",
        "fence": 2,
        "runtime_epoch": 7,
        "child": child,
        "derived_inputs": derived_inputs,
    }


def test_generator_is_reproducible() -> None:
    root = Path(__file__).parents[1]
    subprocess.run([sys.executable, str(root / "generators" / "generate.py")], check=True, cwd=root)
    subprocess.run([sys.executable, str(root / "generators" / "generate.py"), "--check"], check=True, cwd=root)


def test_python_client_source_is_tracked_and_generated_check_is_not_self_referential(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    component = json.loads((root / "contract" / "component-manifest.json").read_text())
    python_component = next(item for item in component["clients"] if item["generator"] == "GENERATOR-PYTHON-INREPO")
    template = root / "generators" / "python_client_template.py"
    output = root / "packages" / "python" / "banodoco_workspace_client" / "generated.py"
    assert (root / python_component["source"]).is_file()
    assert (root / python_component["output"]).resolve() == output.resolve()
    assert template.is_file()
    assert "__SCHEMA_DIGEST__" in template.read_text()
    original = output.read_bytes()
    isolated = tmp_path / "generated.py"
    isolated.write_bytes(original + b"\n# mutation\n")
    check = subprocess.run(
        [sys.executable, str(root / "generators" / "generate.py"), "--check", "--python-output", str(isolated)],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert check.returncode != 0
    subprocess.run([sys.executable, str(root / "generators" / "generate.py"), "--python-output", str(isolated)], check=True, cwd=root)
    assert isolated.read_bytes() == output.read_bytes() == original


def test_generated_recoverable_snapshot_client_and_server_route_shape() -> None:
    from types import SimpleNamespace
    from runtime_protocol.server import RuntimeHandler

    calls = []
    authenticated = []
    output = {"name": "draft", "output_port": "state_result", "filename": "draft.json",
              "object_id": "sha256:" + "b" * 64, "size": 4, "media_type": "application/json"}
    data = {"association_id": "snapshot-1", "role": "recoverable_snapshot"}
    result = {"data": data, "receipt": {"receipt_id": "receipt-1", "command_kind": "attempt.recoverable_snapshot.publish",
        "idempotency_key": "save-1", "request_hash": "sha256:" + "a" * 64, "project_id": "project-1",
        "project_seq": [1, 1], "event_ids": ["1"], "result": data, "created_at": "2026-01-01T00:00:00Z"}}
    def publish(attempt_id, body, *, idempotency_key, identity):
        calls.append((attempt_id, body, idempotency_key, identity))
        return result
    def transport(method, path, headers, body):
        handler = object.__new__(RuntimeHandler)
        handler.server = SimpleNamespace(runtime=SimpleNamespace(publish_recoverable_snapshot=publish))
        handler.command = method
        handler.path = path
        handler._identity = lambda scope: authenticated.append(scope) or {"actor": "reviewer"}
        handler._project_mutation_body = lambda: json.loads(body)
        handler._idempotency_key = lambda: headers["Idempotency-Key"]
        handler._send = lambda status, value: (status, {}, json.dumps(value).encode())
        return handler._route()
    client = WorkspaceClient("http://runtime", "reviewer-token", transport=transport)
    saved = client.publish_recoverable_snapshot("attempt-1", lease_id="lease-1", fence=2, runtime_epoch=7,
        revision=3, output=output, idempotency_key="save-1")
    assert saved["association_id"] == data["association_id"] and saved["role"] == "recoverable_snapshot"
    assert saved.receipt["receipt_id"] == "receipt-1"
    assert authenticated == ["worker:execute"]
    assert calls == [("attempt-1", {"lease_id": "lease-1", "fence": 2, "runtime_epoch": 7, "revision": 3,
                      "output": output}, "save-1", {"actor": "reviewer"})]
