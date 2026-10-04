from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import ApiError, Capability, ClaimWaiting, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore


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


def test_owner_get_executor_observes_exact_readiness_and_session(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        owner = WorkspaceClient(daemon.endpoint, daemon.token)
        owner.register_executor({
            "executor_id": "exact-worker", "max_concurrency": 1,
            "resource_keys": [], "capabilities": ["render.basic"],
            "protocol": "workspace.v1", "source_digest": "sha256:" + "a" * 64,
        }, idempotency_key="exact-worker-register")
        observed = owner.get_executor("exact-worker")
        assert observed.executor_id == "exact-worker"
        assert observed.readiness == "ready"
        assert observed.runtime_epoch == daemon.service.store._current_runtime_epoch()
        assert observed.runtime_session_id == daemon.service.runtime_session_id
        assert observed.source_digest == "sha256:" + "a" * 64
        assert observed.last_seen_at
        daemon.service.store.set_executor_readiness(
            "exact-worker", ready=False, reason="observer_probe",
            runtime_epoch=observed.runtime_epoch,
        )
        not_ready = owner.get_executor("exact-worker")
        assert not_ready.readiness == "not_ready"
        assert not_ready.readiness_reason == "observer_probe"
        with pytest.raises(ApiError) as missing:
            owner.get_executor("foreign-worker")
        assert missing.value.status == 404
        with pytest.raises(ApiError) as denied:
            WorkspaceClient(daemon.endpoint, daemon.worker_token).get_executor("exact-worker")
        assert denied.value.status in {401, 403}
    finally:
        daemon.stop()


def test_generated_owner_local_generation_readback() -> None:
    def transport(method, path, _headers, body):
        if (method, path) == ("GET", "/v1/control/local-worker/generation"):
            return 200, {}, json.dumps({
                "executor_incarnation": "incarnation-1",
                "evidence_digest": "sha256:" + "a" * 64,
                "profile_id": "astrid", "workspace_uuid": "realm-1",
                "state": "stop_unknown",
            }).encode()
        assert (method, path) == ("POST", "/v1/control/local-worker/relinquish")
        assert json.loads(body) == {
            "executor_incarnation": "incarnation-1",
            "evidence_digest": "sha256:" + "a" * 64,
        }
        return 200, {}, b'{"state":"relinquished","executor_incarnation":"incarnation-1"}'

    client = WorkspaceClient("http://runtime", "owner-token", transport=transport)
    observed = client.get_local_worker_generation()
    assert observed["executor_incarnation"] == "incarnation-1"
    assert observed["state"] == "stop_unknown"
    assert client.relinquish_local_worker(
        observed["executor_incarnation"], observed["evidence_digest"]
    )["state"] == "relinquished"


def test_generated_owner_local_worker_restart():
    expected = {
        "state": "active", "operation_id": "operation-1", "profile_id": "astrid",
        "workspace_uuid": "realm-1", "machine_id": "machine-1",
        "executor_incarnation": "incarnation-2",
        "evidence_digest": "sha256:" + "b" * 64,
    }

    def transport(method, path, _headers, body):
        assert (method, path) == ("POST", "/v1/control/local-worker/start")
        assert json.loads(body) == {
            "profile_id": "astrid", "expected_workspace_uuid": "realm-1",
        }
        return 200, {}, json.dumps(expected).encode()

    client = WorkspaceClient("http://runtime", "owner-token", transport=transport)
    assert client.start_local_worker("astrid", "realm-1") == expected


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


def test_expected_effect_round_trips_through_public_task_read(tmp_path: Path) -> None:
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    effect_payload = {
        "version": 1,
        "modality": "video",
        "generation_type": "vibecomfy.run",
        "metadata": {"h3_av": {"request_digest": "sha256:" + "a" * 64}},
        "partial_success_policy": "reject",
        "groups": [{
            "group_key": "main",
            "selectors": [{
                "selector": "video",
                "ordinal": 0,
                "variant_key": "original",
                "output_port": "vibecomfy_run",
            }],
        }],
    }
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = client.create_project(
            "H3 receipt projection",
            idempotency_key="effect-projection-project",
            slug="h3-receipt-projection",
        )
        effect = {
            "effect_type": "generation.publish_v1",
            "target_id": project.project_id,
            "payload": effect_payload,
        }
        admitted = client.admit_task(
            capability_id="vibecomfy.run",
            capability_digest="sha256:" + hashlib.sha256(b"vibecomfy.run").hexdigest(),
            input_object_ids=[],
            idempotency_key="effect-projection-task",
            project_id=project.project_id,
            settlement_effect=effect,
            generation_intent={
                "version": 1,
                "modality": "video",
                "partial_success_policy": "reject",
                "metadata": effect_payload["metadata"],
                "groups": effect_payload["groups"],
            },
        )

        task = client.get_task(admitted["task_id"])
        assert task.expected_effect == effect
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


def _preference_fixture(name: str = "preferences-user.json") -> dict:
    return json.loads((Path(__file__).parents[1] / "conformance" / "fixtures" / name).read_text())


def test_preferences_generated_client_typed_user_result_and_encoded_project_selector() -> None:
    from banodoco_workspace_client import PreferenceMutationResult, PreferenceResource

    resource = _preference_fixture()
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, json.loads(body) if body else None))
        data = dict(resource)
        if "project" in path:
            data.update(scope="project", actor_id=None, project_id="p /?", document_id="preferences:project:p /?")
        if method == "GET":
            return 200, {}, json.dumps(data).encode()
        return 200, {}, json.dumps({"data": data, "receipt": {"receipt_id": "committed-project"} if data["scope"] == "project" else None}).encode()

    client = WorkspaceClient("http://runtime", "token", transport=transport)
    assert isinstance(client.get_preferences("user"), PreferenceResource)
    user = client.update_preferences("user", resource["content"], 0, "user-write")
    assert isinstance(user, PreferenceMutationResult)
    assert isinstance(user.data, PreferenceResource)
    assert user.content == resource["content"] and user.receipt is None
    assert calls[-1][3] == {"content": resource["content"], "expected_version": 0}
    assert calls[-1][2]["Idempotency-Key"] == "user-write"
    assert calls[-1][2]["Authorization"] == "Bearer token"
    project = client.update_preferences("project", "text", 1, "project-write", "p /?")
    assert project.receipt == {"receipt_id": "committed-project"}
    assert calls[-1][1] == "/v1/preferences/project?project_id=p%20%2F%3F"
    client.get_preferences("project")
    assert calls[-1][1] == "/v1/preferences/project"


@pytest.mark.parametrize("scope,selector", [("user", "p"), ("invalid", None)])
def test_preferences_generated_client_rejects_invalid_scope_and_user_project_selector(scope, selector) -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: pytest.fail("transport called"))
    with pytest.raises(ValueError):
        client.get_preferences(scope, selector)
    with pytest.raises(ValueError):
        client.update_preferences(scope, "content", 0, "key", selector)


@pytest.mark.parametrize("response", [
    {"data": _preference_fixture(), "receipt": {}},
    {"data": _preference_fixture()},
    {"data": {**_preference_fixture(), "content": {}}, "receipt": None},
    {"data": {**_preference_fixture(), "version": True}, "receipt": None},
    {"data": {**_preference_fixture(), "actor_id": None}, "receipt": None},
    {"data": {**_preference_fixture(), "project_id": "forged"}, "receipt": None},
    {"data": {**_preference_fixture(), "document_id": "other"}, "receipt": None},
    {"data": {**_preference_fixture(), "extra": "value"}, "receipt": None},
    {"data": _preference_fixture(), "receipt": None, "extra": "value"},
])
def test_preferences_user_null_receipt_decoder_is_narrow(response) -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: (200, {}, json.dumps(response).encode()))
    with pytest.raises(ApiError, match="invalid_response"):
        client.update_preferences("user", "content", 0, "key")


def test_preferences_project_and_ordinary_mutations_still_require_receipts() -> None:
    resource = {**_preference_fixture(), "scope": "project", "actor_id": None, "project_id": "p", "document_id": "preferences:project:p"}
    client = WorkspaceClient("http://runtime", transport=lambda *args: (200, {}, json.dumps({"data": resource, "receipt": None}).encode()))
    with pytest.raises(ApiError, match="committed receipt"):
        client.update_preferences("project", "content", 0, "key")
    with pytest.raises(ApiError, match="committed receipt"):
        client.update_document("p", "doc", expected_version=1, idempotency_key="key", content="content")


def test_update_document_distinguishes_omitted_content_from_json_null() -> None:
    payloads = []

    def transport(method, path, headers, body):
        assert method == "PATCH" and path == "/v1/projects/p/documents/doc"
        payload = json.loads(body)
        payloads.append(payload)
        resource = {
            "document_id": "doc", "project_id": "p", "kind": "pack.note",
            "content": payload.get("content", "previous"), "version": 2,
            "created_at": "2026-10-02T00:00:00Z", "updated_at": "2026-10-02T00:00:01Z",
        }
        return 200, {}, json.dumps({"data": resource, "receipt": {}}).encode()

    client = WorkspaceClient("http://runtime", transport=transport)
    client.update_document("p", "doc", expected_version=1, idempotency_key="null", content=None)
    client.update_document("p", "doc", expected_version=1, idempotency_key="omitted")
    assert payloads == [
        {"expected_version": 1, "content": None},
        {"expected_version": 1},
    ]


def test_list_documents_generated_client_kind_filter_is_encoded() -> None:
    def transport(method, path, headers, body):
        assert method == "GET"
        assert path == "/v1/projects/p%20%2F/documents?limit=5&cursor=next%2Fpage&kind=astrid.note%20%2F%3F"
        return 200, {}, b'{"items": [], "next_cursor": null}'
    assert WorkspaceClient("http://runtime", transport=transport).list_documents("p /", cursor="next/page", limit=5, kind="astrid.note /?") == ([], None)
