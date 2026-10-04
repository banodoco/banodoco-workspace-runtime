"""Persisted admission identity fences legacy receipt refresh/reconstruction."""
from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from banodoco_workspace_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError
from runtime_protocol.store import (
    GENERATION_INTENT_STORAGE_KEY,
    LEGACY_GENERATION_INTENT_STORAGE_KEY,
    RealmStore,
)
from runtime_protocol.util import canonical_json

CAPABILITY = "fixture.replay-identity"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


@pytest.fixture
def store(tmp_path):
    store = RealmStore.initialize(tmp_path / "realm")
    store.begin_runtime_session("replay-test-session")
    try:
        yield store
    finally:
        store.close()


def _admit(store, *, spec=None, effect=None, digest=DIGEST, request=None):
    return store.create_task(CAPABILITY, spec if spec is not None else {"message": "hello"},
        idempotency_key="same-admission", expected_effect=effect, capability_digest=digest,
        execution_request=request)


def _receipt_state(store, mode):
    if mode in {"partial_current", "partial_stale"}:
        store.conn.execute("UPDATE command_idempotency SET txn_id=NULL, primary_stream_id=NULL, resulting_stream_seq=NULL, first_project_seq=NULL, last_project_seq=NULL, event_ids_json=NULL WHERE command_kind='task.create'")
    if mode in {"stale", "partial_stale"}:
        store.conn.execute("UPDATE command_idempotency SET request_hash='legacy-stale-hash' WHERE command_kind='task.create'")
    elif mode == "absent":
        store.conn.execute("DELETE FROM command_idempotency WHERE command_kind='task.create'")
    store.conn.commit()


def _snapshot(store):
    return {
        table: [dict(row) for row in store.conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]
        for table in ("tasks", "runs", "events", "command_idempotency", "project_sequences")
    }


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("changed", ["effect", "digest", "removed_effect", "effect_scalar_type"])
def test_changed_effect_or_digest_conflicts_without_mutating_any_admission_evidence(store, receipt, changed):
    effect = {"effect_type": "fixture.effect", "value": True}
    _admit(store, effect=effect)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    requested_effect, requested_digest = copy.deepcopy(effect), DIGEST
    if changed == "effect":
        requested_effect["value"] = False
    elif changed == "digest":
        requested_digest = OTHER_DIGEST
    elif changed == "removed_effect":
        requested_effect = None
    else:
        requested_effect["value"] = 1  # JSON true and 1 are distinct identity.
    with pytest.raises(ConflictError, match="different input"):
        _admit(store, effect=requested_effect, digest=requested_digest)
    assert _snapshot(store) == before


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("changed", ["spec", "execution_request"])
def test_json_boolean_and_number_are_distinct_replay_identity(store, receipt, changed):
    spec = {"value": True}
    request = {
        "schema_version": 1,
        "target": {"kind": "machine", "id": "chosen-machine"},
        "inputs": [],
        "creative_options": {"value": True},
    }
    admitted = _admit(store, spec=spec, request=request)
    _receipt_state(store, receipt)
    before = _snapshot(store)

    if changed == "spec":
        spec = {"value": 1}
    else:
        request["creative_options"]["value"] = 1
    with pytest.raises(ConflictError, match="different input"):
        _admit(store, spec=spec, request=request)

    assert _snapshot(store) == before
    assert _admit(store, spec={"value": True}, request={
        "schema_version": 1,
        "target": {"kind": "machine", "id": "chosen-machine"},
        "inputs": [],
        "creative_options": {"value": True},
    }) == admitted


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("requested_effect", [None, {}])
@pytest.mark.parametrize("omit_digest", [False, True])
def test_no_effect_and_omitted_digest_remain_compatible_with_persisted_evidence(store, receipt, requested_effect, omit_digest):
    admitted = _admit(store)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, effect=requested_effect, digest=None if omit_digest else DIGEST)
    assert replay["task"]["id"] == admitted["task"]["id"]
    after = _snapshot(store)
    assert after["tasks"] == before["tasks"]
    assert after["runs"] == before["runs"]
    assert after["events"] == before["events"]
    assert len(after["command_idempotency"]) == 1
    row = after["command_idempotency"][0]
    assert row["txn_id"] and row["first_project_seq"] and row["last_project_seq"]
    if receipt in {"current", "stale"}:
        saved = before["command_idempotency"][0]
        assert {key: value for key, value in row.items() if key not in {"request_hash", "result_json"}} == {key: value for key, value in saved.items() if key not in {"request_hash", "result_json"}}
    else:
        assert json.loads(row["event_ids_json"]) == []
    assert _admit(store, effect=requested_effect, digest=None if omit_digest else DIGEST) == replay


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_equivalent_effect_mapping_order_refreshes_without_rewriting_task(store, receipt):
    effect = {"effect_type": "fixture.effect", "nested": {"first": 1, "second": 2}}
    admitted = _admit(store, effect=effect)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    reordered = {"nested": {"second": 2, "first": 1}, "effect_type": "fixture.effect"}
    replay = _admit(store, effect=reordered)
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert _snapshot(store)["tasks"] == before["tasks"]
    assert _snapshot(store)["runs"] == before["runs"]


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_legacy_nested_request_and_intent_refresh_only_equivalent_admission(store, receipt):
    request = {"schema_version": 1, "target": {"kind": "machine", "id": "chosen-machine"}, "inputs": []}
    intent = {"modality": "video", "members": [{"ordinal": 0}]}
    spec = {"message": "hello", GENERATION_INTENT_STORAGE_KEY: intent}
    admitted = _admit(store, spec=spec, request=request)
    # Represent precisely the inventoried pre-correction outer-spec shape.
    legacy = {"message": "hello", LEGACY_GENERATION_INTENT_STORAGE_KEY: intent, "execution_request": request}
    store.conn.execute("UPDATE tasks SET spec_json=?, execution_request_json=NULL", (canonical_json(legacy),))
    store.conn.execute("UPDATE runs SET spec_json=?", (canonical_json(legacy),))
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, spec=spec, request=request)
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert replay["task"]["execution_request"] == request
    assert replay["task"]["generation_intent"] == intent
    after = _snapshot(store)
    assert after["tasks"] == before["tasks"] and after["runs"] == before["runs"]
    assert after["events"] == before["events"]
    assert len(after["command_idempotency"]) == 1
    assert _admit(store, spec=spec, request=request) == replay
    bad_intent = {**spec, GENERATION_INTENT_STORAGE_KEY: {**intent, "modality": "image"}}
    with pytest.raises(ConflictError, match="different input"):
        _admit(store, spec=bad_intent, request=request)
    assert _snapshot(store) == after


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_explicit_digest_can_use_consistent_legacy_spec_evidence(store, receipt):
    spec = {"capability_digest": DIGEST, "message": "hello"}
    admitted = _admit(store, spec=spec)
    store.conn.execute("UPDATE tasks SET capability_digest=NULL")
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, spec=spec)
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert _snapshot(store)["tasks"] == before["tasks"]
    assert _snapshot(store)["runs"] == before["runs"]


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("missing", ["task", "digest", "inconsistent_digest"])
def test_insufficient_or_conflicting_persisted_identity_fails_closed(store, receipt, missing):
    spec = {"capability_digest": DIGEST} if missing == "inconsistent_digest" else {"message": "hello"}
    _admit(store, spec=spec)
    if missing == "task":
        store.conn.execute("DELETE FROM tasks")
    elif missing == "digest":
        store.conn.execute("UPDATE tasks SET capability_digest=NULL")
    elif missing == "inconsistent_digest":
        store.conn.execute("UPDATE tasks SET capability_digest=?", (OTHER_DIGEST,))
    _receipt_state(store, receipt)
    before = _snapshot(store)
    with pytest.raises(ConflictError):
        _admit(store, spec=spec)
    assert _snapshot(store) == before


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_current_catalog_is_not_persisted_replay_digest_authority(store, receipt):
    admitted = _admit(store)
    store.register_capability(CAPABILITY, OTHER_DIGEST, status="unavailable")
    _receipt_state(store, receipt)
    replay = _admit(store)
    assert replay["task"]["id"] == admitted["task"]["id"]


def test_generated_http_concurrent_exact_requests_converge_and_changed_effect_conflicts(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root).start()
    try:
        daemon.service.register_capability({"capability_id": CAPABILITY, "definition_digest": DIGEST})
        arguments = dict(capability_id=CAPABILITY, capability_digest=DIGEST, input_object_ids=[],
                        idempotency_key="concurrent-admission", settlement_effect={"effect_type": "fixture.effect"})
        def admit(_):
            return WorkspaceClient(daemon.endpoint, daemon.token).admit_task(**arguments)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(admit, range(2)))
        assert results[0] == results[1]
        before = _snapshot(daemon.service.store)
        with pytest.raises(ApiError) as conflict:
            WorkspaceClient(daemon.endpoint, daemon.token).admit_task(**{**arguments, "settlement_effect": None})
        assert conflict.value.code == "conflict"
        assert _snapshot(daemon.service.store) == before
    finally:
        daemon.stop()


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("registered", [False, True])
def test_initially_omitted_digest_replays_without_inventing_new_digest(store, receipt, registered):
    if registered:
        store.register_capability(CAPABILITY, DIGEST)
    admitted = _admit(store, digest=None)
    assert admitted["task"]["capability_digest"] == (DIGEST if registered else None)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, digest=None)
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert _snapshot(store)["tasks"] == before["tasks"]
    assert _snapshot(store)["runs"] == before["runs"]


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_persisted_empty_effect_uses_existing_no_effect_semantics(store, receipt):
    admitted = _admit(store)
    store.conn.execute("UPDATE tasks SET expected_effect_json='{}'")
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, effect={})
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert _snapshot(store)["tasks"] == before["tasks"]
    assert _snapshot(store)["runs"] == before["runs"]


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_generated_http_equivalent_reconstruction_returns_valid_receipt_without_task_events(tmp_path, receipt):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root).start()
    try:
        daemon.service.register_capability({"capability_id": CAPABILITY, "definition_digest": DIGEST})
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        arguments = dict(capability_id=CAPABILITY, capability_digest=DIGEST, input_object_ids=[], idempotency_key="same-admission")
        first = client.admit_task(**arguments)
        store = daemon.service.store
        _receipt_state(store, receipt)
        before = _snapshot(store)
        replay = client.admit_task(**arguments)
        assert replay["task_id"] == first["task_id"] and replay["run_id"] == first["run_id"]
        assert replay.receipt["receipt_id"]
        assert replay.receipt["command_kind"] == "task.create"
        assert replay.receipt["project_seq"][0] > 0
        assert replay.receipt["project_seq"][1] >= replay.receipt["project_seq"][0]
        after = _snapshot(store)
        assert after["tasks"] == before["tasks"] and after["runs"] == before["runs"]
        assert after["events"] == before["events"]
        if receipt == "stale":
            assert replay.receipt["receipt_id"] == first.receipt["receipt_id"]
            assert replay.receipt["project_seq"] == first.receipt["project_seq"]
        else:
            assert replay.receipt["event_ids"] == []
        second_replay = client.admit_task(**arguments)
        assert second_replay.receipt == replay.receipt
        assert _snapshot(store) == after
    finally:
        daemon.stop()


def test_unkeyed_store_admission_still_creates_fresh_tasks(store):
    first = store.create_task(CAPABILITY, {"message": "hello"})
    second = store.create_task(CAPABILITY, {"message": "hello"})
    assert first["task"]["id"] != second["task"]["id"]
