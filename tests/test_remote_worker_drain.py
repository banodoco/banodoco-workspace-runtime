from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Barrier

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError
from tests.test_remote_worker_activation import (
    CAPABILITY,
    CAPABILITY_DIGEST,
    OLD,
    OWNER,
    Inspector,
    Preparer,
    _claim,
    _identity,
    _observation,
    _reference,
    _service,
)
from runtime_protocol.auth import CredentialStore
from runtime_protocol.remote_worker_activation import QualifiedRemoteWorkerLauncher


def _active(tmp_path, *, children=False, staged=False, ttl_seconds=300):
    service, task_id = _service(tmp_path, child_delegation=children)
    if staged:
        original = service._task_resource(service.store.get_task(task_id))
        service.cancel_task_canonical(
            task_id, {}, idempotency_key="cancel-unstaged-fixture"
        )
        task_id = service.create_task(
            {
                "capability_id": CAPABILITY,
                "capability_digest": CAPABILITY_DIGEST,
                "project": original["project_id"],
                "input_object_ids": [],
                "spec": {},
                "execution_request": {"schema_version": 1, "target": OLD},
                "child_delegation": {
                    "capabilities": [
                        {
                            "capability_id": CAPABILITY,
                            "capability_digest": CAPABILITY_DIGEST,
                        }
                    ],
                    "targets": [OLD],
                    "input_object_ids": [],
                    "stages": [
                        {
                            "name": name,
                            "capability_id": CAPABILITY,
                            "capability_digest": CAPABILITY_DIGEST,
                            "target": OLD,
                            "inputs": [],
                        }
                        for name in ["first", "later", "publish"]
                    ],
                },
                "idempotency_key": "staged-parent",
            },
            enforce_readiness=True,
        )["task"]["id"]
    ref = _reference(tmp_path, service, task_id)
    credentials = CredentialStore(tmp_path / "credentials")
    launcher = QualifiedRemoteWorkerLauncher(
        runtime=service,
        credentials=credentials,
        preparer=Preparer(),
        inspector=Inspector(_observation(ref, service)),
        ttl_seconds=ttl_seconds,
    )
    parked = launcher.park(ref, target=OLD)
    qualification = launcher.activate(
        service._task_resource(service.store.get_task(task_id)), ref, parked
    )
    return service, task_id, _identity(credentials), qualification


def _lease(claim):
    return {key: claim[key] for key in ("lease_id", "fence", "runtime_epoch")}


def _settle(service, claim, identity, key):
    return service.settle_attempt(
        claim["attempt_id"],
        {**_lease(claim), "outputs": []},
        idempotency_key=key,
        identity=identity,
    )


def _child(service, parent, identity, key, *, staged=False):
    authority = service.issue_child_authority(
        parent["attempt_id"], _lease(parent), identity=identity
    )["authority"]
    return service.admit_delegated_child(
        {
            "authority": authority,
            "task": {
                "capability_id": CAPABILITY,
                "capability_digest": CAPABILITY_DIGEST,
                **({} if staged else {"input_object_ids": []}),
                "spec": {"params": {"stage": key}, "inputs": {}},
                "execution_request": {
                    "schema_version": 1,
                    "target": OLD,
                    **({} if staged else {"inputs": []}),
                },
                **({"stage": key, "input_refs": []} if staged else {}),
            },
        },
        idempotency_key=key,
        identity=identity,
    )


def test_staged_parent_continues_after_cutoff_and_finishes(tmp_path):
    service, task_id, identity, qualification = _active(
        tmp_path, children=True, staged=True
    )
    try:
        parent = _claim(service, OLD, identity, "parent")
        first = _child(service, parent, identity, "first", staged=True)
        first_claim = _claim(service, OLD, identity, "first-claim")
        assert first_claim["task_id"] == first["task"]["id"]
        assert (
            service.begin_remote_drain(task_id, qualification, identity=OWNER)["state"]
            == "pending"
        )
        assert (
            service._remote_drain(task_id)["parent_attempt"]["parent_attempt_id"]
            == parent["attempt_id"]
        )
        service.heartbeat_attempt(
            parent["attempt_id"],
            _lease(parent),
            idempotency_key="heartbeat",
            identity=identity,
        )
        _settle(service, first_claim, identity, "first-settle")
        with pytest.raises(ConflictError, match="drain"):
            service.retry_task(first["task"]["id"], idempotency_key="fresh-child-retry")
        assert (
            service.finish_remote_drain(task_id, qualification, identity=OWNER)["state"]
            == "pending"
        )
        later = _child(service, parent, identity, "later", staged=True)
        later_claim = _claim(service, OLD, identity, "later-claim")
        assert later_claim["task_id"] == later["task"]["id"]
        _settle(service, later_claim, identity, "later-settle")
        final = _child(service, parent, identity, "publish", staged=True)
        final_claim = _claim(service, OLD, identity, "publication-claim")
        assert final_claim["task_id"] == final["task"]["id"]
        _settle(service, final_claim, identity, "publication-settle")
        _settle(service, parent, identity, "parent-settle")
        with pytest.raises(ConflictError, match="drain"):
            service.retry_task(task_id, idempotency_key="new-parent")
        assert (
            service.finish_remote_drain(task_id, qualification, identity=OWNER)["state"]
            == "drained"
        )
        assert (
            service.finish_remote_drain(task_id, qualification, identity=OWNER)["state"]
            == "drained"
        )
        assert service._latest_remote_activation(task_id) is None
        with pytest.raises(AuthorizationError):
            _child(service, parent, identity, "too-late")
    finally:
        service.close()


@pytest.mark.parametrize("claim_first", [False, True])
def test_parent_claim_serializes_with_drain(tmp_path, claim_first):
    service, task_id, identity, qualification = _active(tmp_path)
    try:
        # Force each ordering while both threads participate in owner exclusion.
        barrier = Barrier(2)

        def claiming():
            barrier.wait()
            with service.store._mutex:
                if not claim_first:
                    service.begin_remote_drain(task_id, qualification, identity=OWNER)
                return _claim(service, OLD, identity, "claim-race")

        def draining():
            barrier.wait()
            with service.store._mutex:
                if claim_first:
                    _claim(service, OLD, identity, "claim-race")
                return service.begin_remote_drain(
                    task_id, qualification, identity=OWNER
                )

        with ThreadPoolExecutor(2) as pool:
            a, b = pool.submit(claiming), pool.submit(draining)
            result, _ = a.result(), b.result()
        marker = service._remote_drain(task_id)
        if claim_first:
            assert marker["parent_attempt"]["parent_attempt_id"] == result["attempt_id"]
        else:
            assert marker["parent_attempt"] is None
            assert result["waiting_reason"] == "remote_activation_missing"
            assert (
                service.store.conn.execute("SELECT count(*) FROM attempts").fetchone()[
                    0
                ]
                == 0
            )
    finally:
        service.close()


def test_child_admission_and_claim_cannot_escape_finish(tmp_path):
    service, task_id, identity, qualification = _active(tmp_path, children=True)
    try:
        parent = _claim(service, OLD, identity, "parent")
        service.begin_remote_drain(task_id, qualification, identity=OWNER)
        barrier = Barrier(2)

        def child():
            barrier.wait()
            admitted = _child(service, parent, identity, "racing-child")
            claimed = _claim(service, OLD, identity, "racing-claim")
            return admitted, claimed

        def finish():
            barrier.wait()
            return service.finish_remote_drain(task_id, qualification, identity=OWNER)

        with ThreadPoolExecutor(2) as pool:
            a, b = pool.submit(child), pool.submit(finish)
            admitted, claimed = a.result()
            assert b.result()["state"] == "pending"
        assert claimed["task_id"] == admitted["task"]["id"]
        _settle(service, claimed, identity, "child-done")
        _settle(service, parent, identity, "parent-done")
        assert (
            service.finish_remote_drain(task_id, qualification, identity=OWNER)["state"]
            == "drained"
        )
    finally:
        service.close()


@pytest.mark.parametrize(
    "blocker", ["unknown", "queued-child", "unsettled", "reservation", "binding"]
)
def test_finish_checks_authoritative_state_for_every_child(tmp_path, blocker):
    service, task_id, identity, qualification = _active(tmp_path, children=True)
    try:
        parent = _claim(service, OLD, identity, "parent")
        child = _child(service, parent, identity, "child")["task"]["id"]
        service.begin_remote_drain(task_id, qualification, identity=OWNER)
        claimed = _claim(service, OLD, identity, "child-claim")
        _settle(service, claimed, identity, "child-done")
        _settle(service, parent, identity, "parent-done")
        if blocker == "unknown":
            service.store.conn.execute(
                "UPDATE tasks SET waiting_reason='provider_state_unknown' WHERE id=?",
                (child,),
            )
        elif blocker == "queued-child":
            service.store.conn.execute(
                "UPDATE tasks SET status='queued' WHERE id=?", (child,)
            )
        elif blocker == "unsettled":
            service.store.conn.execute(
                "UPDATE attempts SET settled=0 WHERE id=?", (claimed["attempt_id"],)
            )
        elif blocker == "binding":
            service.store.conn.execute(
                "UPDATE execution_bindings SET status='claimed' WHERE task_id=?",
                (child,),
            )
        else:
            # Reuse an actual reservation row by adding a capability resource.
            columns = [
                row["name"]
                for row in service.store.conn.execute("PRAGMA table_info(reservations)")
            ]
            assert "released_at" in columns
            service.store.conn.execute(
                "INSERT INTO reservations(executor_id, resource_key, task_id, lease_token, created_at) VALUES ('host','gpu',?,?, 'now')",
                (child, claimed["lease_id"]),
            )
        assert (
            service.finish_remote_drain(task_id, qualification, identity=OWNER)["state"]
            == "pending"
        )
        assert service._latest_remote_activation(task_id) == qualification
    finally:
        service.close()


@pytest.mark.parametrize(
    "field",
    [
        "activation_id",
        "executor_incarnation",
        "runtime_session_id",
        "runtime_epoch",
        "effective_target",
    ],
)
def test_stale_drain_qualification_never_changes_authority(tmp_path, field):
    service, task_id, identity, qualification = _active(tmp_path)
    try:
        wrong = copy.deepcopy(qualification)
        wrong[field] = 999 if field == "runtime_epoch" else "foreign"
        with pytest.raises(ConflictError):
            service.begin_remote_drain(task_id, wrong, identity=OWNER)
        assert service._remote_drain(task_id) is None
        assert service._latest_remote_activation(task_id) == qualification
    finally:
        service.close()


def test_drain_blocks_fresh_resume_before_binding_reset_and_preserves_exact_replay(
    tmp_path,
):
    service, task_id, identity, qualification = _active(tmp_path)
    try:
        claim = _claim(service, OLD, identity, "claim")
        prepared = service.prepare_reboot(
            {"attempt_id": claim["attempt_id"], **_lease(claim)}, identity=identity
        )
        checkpoint = service.checkpoint_attempt(
            claim["attempt_id"],
            {
                **_lease(claim),
                "nonce": prepared["nonce"],
                "authorization": prepared["nonce"],
                "state": {},
            },
            identity=identity,
        )
        service.store.conn.execute(
            "UPDATE recovery_checkpoints SET state='recovered' WHERE id=?",
            (checkpoint["checkpoint_id"],),
        )
        service.begin_remote_drain(task_id, qualification, identity=OWNER)
        body = {
            "checkpoint_id": checkpoint["checkpoint_id"],
            "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "runtime_epoch": claim["runtime_epoch"],
        }
        before = service.store.execution_binding(task_id)
        with pytest.raises(ConflictError, match="drain"):
            service.resume_attempt(body, identity=identity)
        assert service.store.execution_binding(task_id) == before
        assert (
            service.store.conn.execute("SELECT count(*) FROM attempts").fetchone()[0]
            == 1
        )
    finally:
        service.close()


def test_exact_completed_resume_receipt_replays_after_drain(tmp_path):
    service, task_id, identity, qualification = _active(tmp_path)
    try:
        claim = _claim(service, OLD, identity, "claim")
        prepared = service.prepare_reboot(
            {"attempt_id": claim["attempt_id"], **_lease(claim)}, identity=identity
        )
        checkpoint = service.checkpoint_attempt(
            claim["attempt_id"],
            {
                **_lease(claim),
                "nonce": prepared["nonce"],
                "authorization": prepared["nonce"],
                "state": {},
            },
            identity=identity,
        )
        # Model the checkpoint recovery disposition, then invoke the real
        # resume owner to create its attempt and durable exact replay receipt.
        service.store.conn.execute(
            "UPDATE recovery_checkpoints SET state='recovered' WHERE id=?",
            (checkpoint["checkpoint_id"],),
        )
        service.store.conn.execute(
            "UPDATE tasks SET status='queued', waiting_reason='provider_state_unknown' WHERE id=?",
            (task_id,),
        )
        body = {
            "checkpoint_id": checkpoint["checkpoint_id"],
            "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "runtime_epoch": claim["runtime_epoch"],
        }
        resumed = service.resume_attempt(body, identity=identity)
        assert resumed["attempt"]["attempt_id"] != claim["attempt_id"]
        service.begin_remote_drain(task_id, qualification, identity=OWNER)
        before = service.store.execution_binding(task_id)
        assert service.resume_attempt(body, identity=identity) == resumed
        assert service.store.execution_binding(task_id) == before
        assert (
            service.store.conn.execute("SELECT count(*) FROM attempts").fetchone()[0]
            == 2
        )
    finally:
        service.close()


def test_cutoff_child_continuation_survives_qualification_expiry(tmp_path, monkeypatch):
    import runtime_protocol.service as service_module

    service, task_id, identity, qualification = _active(
        tmp_path, children=True, ttl_seconds=1
    )
    try:
        parent = _claim(service, OLD, identity, "parent")
        service.begin_remote_drain(task_id, qualification, identity=OWNER)

        class AfterExpiry(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + timedelta(seconds=2)

        monkeypatch.setattr(service_module, "datetime", AfterExpiry)
        child = _child(service, parent, identity, "continuation")
        claim = _claim(service, OLD, identity, "continuation-claim")
        assert claim["task_id"] == child["task"]["id"]
        _settle(service, claim, identity, "child-done")
        _settle(service, parent, identity, "parent-done")
        assert (
            service.finish_remote_drain(task_id, qualification, identity=OWNER)["state"]
            == "drained"
        )
    finally:
        service.close()


@pytest.mark.parametrize(
    "field", ["id", "lease_id", "fence", "executor_id", "runtime_epoch"]
)
def test_successor_or_foreign_parent_attempt_is_outside_cutoff(tmp_path, field):
    service, task_id, identity, qualification = _active(tmp_path)
    try:
        parent = _claim(service, OLD, identity, "parent")
        service.begin_remote_drain(task_id, qualification, identity=OWNER)
        forged = dict(
            service.store.conn.execute(
                "SELECT * FROM attempts WHERE id=?", (parent["attempt_id"],)
            ).fetchone()
        )
        forged[field] = 999 if field in {"fence", "runtime_epoch"} else "foreign"
        with pytest.raises(AuthorizationError):
            service._assert_attempt_identity(forged, identity)
        assert (
            service.finish_remote_drain(task_id, qualification, identity=OWNER)["state"]
            == "pending"
        )
    finally:
        service.close()
