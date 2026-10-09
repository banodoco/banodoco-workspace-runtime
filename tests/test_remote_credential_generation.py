from __future__ import annotations

import copy
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event

import pytest

from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES
from runtime_protocol.errors import AuthorizationError, ConflictError
from runtime_protocol.store import RealmStore
from tests.test_remote_activation_http import _qualification
from tests.test_remote_worker_activation import OWNER


def _task(daemon, key, *, children=False):
    service = daemon.service
    capability = "remote.generation.fixture"
    digest = "sha256:" + hashlib.sha256(capability.encode()).hexdigest()
    service.register_capability(
        {"capability_id": capability, "definition_digest": digest}
    )
    extras = {}
    if children:
        extras = {
            "project": service.create_project(
                {"slug": key, "name": key}, idempotency_key="project-" + key
            )["id"],
            "child_delegation": {
                "capabilities": [
                    {"capability_id": capability, "capability_digest": digest}
                ],
                "targets": [
                    {
                        "kind": "runpod",
                        "pod_id": "pod-1",
                        "provider_account_ref": "account-1",
                    }
                ],
                "input_object_ids": [],
            },
        }
    task_id = service.create_task(
        {
            **extras,
            "capability_id": capability,
            "capability_digest": digest,
            "input_object_ids": [],
            "spec": {},
            "execution_request": {
                "schema_version": 1,
                "target": {
                    "kind": "runpod",
                    "pod_id": "pod-1",
                    "provider_account_ref": "account-1",
                },
            },
            "idempotency_key": key,
        },
        enforce_readiness=True,
    )["task"]["id"]
    qualification = _qualification(service, task_id)
    qualification["credential_actor"] = WORKER_ACTOR
    qualification["activation_id"] = "activation-" + key
    placement = {
        "actual": qualification["effective_target"],
        "executor_incarnation": qualification["executor_incarnation"],
        "verification": {
            "method": "credential_claim",
            "verified": True,
            "evidence_digest": qualification["evidence_digest"],
        },
    }
    return task_id, qualification, placement


@pytest.fixture
def daemon(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(
        realm, support_root=tmp_path / "support", production_worker_credentials=True
    ).start()
    try:
        yield daemon
    finally:
        daemon.stop()


def _control(daemon, task_id, action, **body):
    return daemon.remote_credential_control(
        task_id, {"action": action, **body}, identity=OWNER
    )


def _token(daemon):
    return daemon.credentials.path_for(WORKER_ACTOR).read_bytes()


def _claim_generation(daemon, qualification, identity, key):
    return daemon.service.claim_next(
        {
            "executor_id": WORKER_ACTOR,
            "capability_ids": ["remote.generation.fixture"],
            "runtime_epoch": daemon.service.store._current_runtime_epoch(),
            "target": qualification["effective_target"],
        },
        idempotency_key=key,
        identity=identity,
    )


@pytest.mark.parametrize("gate", ["child-authority", "child-admission", "resume"])
def test_startup_credential_cannot_use_existing_attempt_before_commit(daemon, gate):
    task_id, qualification, placement = _task(daemon, "pending-" + gate, children=True)
    service = daemon.service
    service.register_executor(
        {
            "executor_id": WORKER_ACTOR,
            "capabilities": ["remote.generation.fixture"],
            "max_concurrency": 2,
        },
        idempotency_key="executor",
    )
    # Existing ordinary-task attempts can predate remote qualification. Seed
    # one through the existing service path so each gate has valid lease data.
    prior = {
        "actor": WORKER_ACTOR,
        "scopes": list(WORKER_SCOPES),
        "execution_binding": placement,
    }
    claim = _claim_generation(daemon, qualification, prior, "existing-attempt")
    lease = {field: claim[field] for field in ("lease_id", "fence", "runtime_epoch")}
    if gate == "child-admission":
        authority = service.issue_child_authority(
            claim["attempt_id"], lease, identity=prior
        )["authority"]
        body = {
            "authority": authority,
            "task": {
                "capability_id": "remote.generation.fixture",
                "capability_digest": "sha256:"
                + hashlib.sha256(b"remote.generation.fixture").hexdigest(),
                "input_object_ids": [],
                "spec": {},
                "execution_request": {
                    "schema_version": 1,
                    "target": qualification["effective_target"],
                },
            },
        }
    elif gate == "resume":
        prepared = service.prepare_reboot(
            {"attempt_id": claim["attempt_id"], **lease}, identity=prior
        )
        checkpoint = service.checkpoint_attempt(
            claim["attempt_id"],
            {
                **lease,
                "nonce": prepared["nonce"],
                "authorization": prepared["nonce"],
                "state": {},
            },
            identity=prior,
        )
        service.store.conn.execute(
            "UPDATE recovery_checkpoints SET state='recovered' WHERE id=?",
            (checkpoint["checkpoint_id"],),
        )
        body = {
            "checkpoint_id": checkpoint["checkpoint_id"],
            "nonce": prepared["nonce"],
            "authorization": prepared["nonce"],
            "runtime_epoch": claim["runtime_epoch"],
        }
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    _control(daemon, task_id, "enable", activation_id=qualification["activation_id"])
    identity = daemon.credentials.load(_token(daemon).decode())
    before_binding = service.store.execution_binding(task_id)
    before_attempts = service.store.conn.execute(
        "SELECT count(*) FROM attempts"
    ).fetchone()[0]
    before_tasks = service.store.conn.execute("SELECT count(*) FROM tasks").fetchone()[
        0
    ]
    with pytest.raises(AuthorizationError, match="activation"):
        if gate == "child-authority":
            service.issue_child_authority(claim["attempt_id"], lease, identity=identity)
        elif gate == "child-admission":
            service.admit_delegated_child(
                body, idempotency_key="pending-child", identity=identity
            )
        else:
            service.resume_attempt(body, identity=identity)
    assert service.store.execution_binding(task_id) == before_binding
    assert (
        service.store.conn.execute("SELECT count(*) FROM attempts").fetchone()[0]
        == before_attempts
    )
    assert (
        service.store.conn.execute("SELECT count(*) FROM tasks").fetchone()[0]
        == before_tasks
    )
    assert _control(
        daemon, task_id, "verify", activation_id=qualification["activation_id"]
    ) == {"fresh": False}
    service.record_remote_activation(task_id, qualification, identity=OWNER)
    assert _control(
        daemon, task_id, "verify", activation_id=qualification["activation_id"]
    ) == {"fresh": True}
    if gate == "child-authority":
        assert service.issue_child_authority(
            claim["attempt_id"], lease, identity=identity
        )["authority"]
    elif gate == "child-admission":
        child = service.admit_delegated_child(
            body, idempotency_key="pending-child", identity=identity
        )
        assert (
            _claim_generation(daemon, qualification, identity, "postcommit-child")[
                "task_id"
            ]
            == child["task"]["id"]
        )
    else:
        service.store.conn.execute(
            "UPDATE tasks SET status='queued', lease_token=NULL, lease_expires_at=NULL WHERE id=?",
            (task_id,),
        )
        assert (
            service.resume_attempt(body, identity=identity)["attempt"]["attempt_id"]
            != claim["attempt_id"]
        )


@pytest.mark.parametrize(
    "changed",
    [
        "runtime_session_id",
        "runtime_epoch",
        "binding_digest",
        "run_id",
        "credential_actor",
        "placement",
        "expiry",
        "activation_id",
        "executor_incarnation",
    ],
)
def test_precommit_enable_refuses_stale_or_foreign_provision(daemon, changed):
    task_id, qualification, placement = _task(daemon, "stale-" + changed)
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    if changed == "placement":
        placement["verification"]["evidence_digest"] = "sha256:" + "b" * 64
    elif changed == "expiry":
        qualification["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()
    elif changed == "runtime_epoch":
        qualification[changed] += 1
    elif changed in {"activation_id", "executor_incarnation"}:
        qualification[changed] = ""
    else:
        qualification[changed] = "foreign"
    # Exercise the defensive current-proof check with internally consistent
    # credential bytes, rather than failing only the file-integrity check.
    token, _ = daemon.credentials.provision(
        WORKER_ACTOR,
        list(WORKER_SCOPES),
        rotate=True,
        enabled=False,
        metadata={
            "execution_binding": placement,
            "qualified_activation": qualification,
        },
    )
    with pytest.raises(ConflictError):
        _control(
            daemon, task_id, "enable", activation_id=qualification["activation_id"]
        )
    with pytest.raises(AuthorizationError):
        daemon.credentials.load(token)
    assert _control(
        daemon, task_id, "verify", activation_id=qualification["activation_id"]
    ) == {"fresh": False}


def test_precommit_enable_cannot_target_foreign_task_or_activation(daemon):
    task_id, qualification, placement = _task(daemon, "exact-startup")
    foreign_task, foreign, _ = _task(daemon, "foreign-startup")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    before = _token(daemon)
    for requested_task, activation_id in [
        (foreign_task, qualification["activation_id"]),
        (task_id, foreign["activation_id"]),
    ]:
        with pytest.raises(ConflictError):
            _control(daemon, requested_task, "enable", activation_id=activation_id)
        assert _token(daemon) == before
        with pytest.raises(AuthorizationError):
            daemon.credentials.load(before.decode())
    assert _control(
        daemon, task_id, "enable", activation_id=qualification["activation_id"]
    ) == {"enabled": True}
    assert (
        daemon.credentials.load(before.decode())["qualified_activation"]
        == qualification
    )
    assert _control(
        daemon, task_id, "verify", activation_id=qualification["activation_id"]
    ) == {"fresh": False}


def test_precommit_enable_refuses_revoked_generation_with_cleanup_pending(
    daemon, monkeypatch
):
    task_id, qualification, placement = _task(daemon, "revoked-startup")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )

    def interrupted(_actor):
        raise OSError("cleanup interrupted")

    monkeypatch.setattr(daemon.credentials, "revoke", interrupted)
    with pytest.raises(OSError):
        _control(
            daemon, task_id, "revoke", activation_id=qualification["activation_id"]
        )
    with pytest.raises(ConflictError):
        _control(
            daemon, task_id, "enable", activation_id=qualification["activation_id"]
        )
    with pytest.raises(AuthorizationError):
        daemon.credentials.load(_token(daemon).decode())
    assert _control(
        daemon, task_id, "verify", activation_id=qualification["activation_id"]
    ) == {"fresh": False}


def test_precommit_enable_serializes_with_claim_and_exact_revoke(daemon, monkeypatch):
    task_id, qualification, placement = _task(daemon, "startup-race")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    daemon.service.register_executor(
        {"executor_id": WORKER_ACTOR, "capabilities": ["remote.generation.fixture"]},
        idempotency_key="executor",
    )
    identity = daemon.credentials.actor_metadata(WORKER_ACTOR)
    token = _token(daemon).decode()
    entered, release = Event(), Event()
    original = daemon.credentials.enable_actor

    def paused(actor):
        entered.set()
        assert release.wait(5)
        original(actor)

    monkeypatch.setattr(daemon.credentials, "enable_actor", paused)
    barrier = Barrier(2)

    def claim():
        barrier.wait()
        return _claim_generation(daemon, qualification, identity, "racing-startup")

    def revoke():
        barrier.wait()
        return _control(
            daemon, task_id, "revoke", activation_id=qualification["activation_id"]
        )

    with ThreadPoolExecutor(3) as pool:
        enable = pool.submit(
            _control,
            daemon,
            task_id,
            "enable",
            activation_id=qualification["activation_id"],
        )
        try:
            assert entered.wait(5)
            assert not daemon.service.store._mutex.acquire(blocking=False)
            claiming, revoking = pool.submit(claim), pool.submit(revoke)
        finally:
            release.set()
        assert enable.result() == {"enabled": True}
        assert "attempt_id" not in claiming.result()
        assert revoking.result() == {"revoked": True}
    assert daemon.service.store.get_task(task_id)["task"]["status"] == "queued"
    assert (
        daemon.service.store.conn.execute("SELECT count(*) FROM attempts").fetchone()[0]
        == 0
    )
    assert daemon.service._latest_remote_activation(task_id) is None
    with pytest.raises(AuthorizationError):
        daemon.credentials.load(token)


def test_same_provision_retry_and_lost_reply_do_not_rotate(daemon, monkeypatch):
    task_id, qualification, placement = _task(daemon, "one")
    original = daemon.credentials.provision

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("lost provision reply")

    monkeypatch.setattr(daemon.credentials, "provision", lost)
    with pytest.raises(OSError):
        _control(
            daemon,
            task_id,
            "provision",
            qualification=qualification,
            placement=placement,
        )
    before = _token(daemon)
    monkeypatch.setattr(daemon.credentials, "provision", original)
    result = _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    assert result["credential_actor"] == WORKER_ACTOR
    assert _token(daemon) == before
    daemon.service.record_remote_activation(task_id, qualification, identity=OWNER)
    _control(daemon, task_id, "enable", activation_id=qualification["activation_id"])
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    assert _token(daemon) == before
    assert (
        daemon.credentials.load(before.decode())["qualified_activation"]
        == qualification
    )


def test_competing_provisions_serialize_and_never_replace_foreign_pending(daemon):
    first, second = _task(daemon, "first"), _task(daemon, "second")
    barrier = Barrier(2)

    def provision(item):
        task_id, qualification, placement = item
        barrier.wait()
        try:
            return _control(
                daemon,
                task_id,
                "provision",
                qualification=qualification,
                placement=placement,
            )
        except ConflictError:
            return "conflict"

    with ThreadPoolExecutor(2) as pool:
        a, b = pool.submit(provision, first), pool.submit(provision, second)
        result = [a.result(), b.result()]
    assert result.count("conflict") == 1
    winner = daemon.credentials.actor_metadata(WORKER_ACTOR)["qualified_activation"]
    loser = second if winner == first[1] else first
    before = _token(daemon)
    with pytest.raises(ConflictError):
        _control(
            daemon, loser[0], "provision", qualification=loser[1], placement=loser[2]
        )
    assert _token(daemon) == before


def test_old_enable_revoke_and_cleanup_replay_preserve_replacement(daemon):
    task_id, old, placement = _task(daemon, "old")
    _control(daemon, task_id, "provision", qualification=old, placement=placement)
    daemon.service.record_remote_activation(task_id, old, identity=OWNER)
    _control(daemon, task_id, "enable", activation_id=old["activation_id"])
    assert _control(daemon, task_id, "revoke", activation_id=old["activation_id"]) == {
        "revoked": True
    }
    assert _control(daemon, task_id, "revoke", activation_id=old["activation_id"]) == {
        "revoked": True
    }
    newer = copy.deepcopy(old)
    newer["activation_id"] = "newer"
    _control(daemon, task_id, "provision", qualification=newer, placement=placement)
    daemon.service.record_remote_activation(task_id, newer, identity=OWNER)
    before = _token(daemon)
    barrier = Barrier(3)

    def old_action(action):
        barrier.wait()
        with pytest.raises(ConflictError):
            _control(daemon, task_id, action, activation_id=old["activation_id"])

    def enable_current():
        barrier.wait()
        return _control(daemon, task_id, "enable", activation_id=newer["activation_id"])

    with ThreadPoolExecutor(3) as pool:
        a, b, c = (
            pool.submit(old_action, "enable"),
            pool.submit(old_action, "revoke"),
            pool.submit(enable_current),
        )
        a.result()
        b.result()
        assert c.result() == {"enabled": True}
    assert _token(daemon) == before
    assert daemon.credentials.load(before.decode())["qualified_activation"] == newer


def test_unrecorded_generation_cleanup_is_exact_and_retryable(daemon):
    task_id, qualification, placement = _task(daemon, "unrecorded")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    assert _control(
        daemon, task_id, "revoke", activation_id=qualification["activation_id"]
    ) == {"revoked": True}
    assert _control(
        daemon, task_id, "revoke", activation_id=qualification["activation_id"]
    ) == {"revoked": True}
    with pytest.raises(ConflictError, match="revoked"):
        daemon.service.record_remote_activation(task_id, qualification, identity=OWNER)


def _completed_draining(daemon):
    task_id, qualification, placement = _task(daemon, "completed")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    daemon.service.record_remote_activation(task_id, qualification, identity=OWNER)
    _control(daemon, task_id, "enable", activation_id=qualification["activation_id"])
    service = daemon.service
    service.register_executor(
        {"executor_id": WORKER_ACTOR, "capabilities": ["remote.generation.fixture"]},
        idempotency_key="executor",
    )
    identity = daemon.credentials.load(_token(daemon).decode())
    claim = service.claim_next(
        {
            "executor_id": WORKER_ACTOR,
            "capability_ids": ["remote.generation.fixture"],
            "runtime_epoch": service.store._current_runtime_epoch(),
            "target": qualification["effective_target"],
        },
        idempotency_key="claim",
        identity=identity,
    )
    _control(daemon, task_id, "begin-drain", qualification=qualification)
    service.settle_attempt(
        claim["attempt_id"],
        {
            "lease_id": claim["lease_id"],
            "fence": claim["fence"],
            "runtime_epoch": claim["runtime_epoch"],
            "outputs": [],
        },
        idempotency_key="settle",
        identity=identity,
    )
    return task_id, qualification, placement


def test_restart_retains_disabled_exact_generation_and_finishes_quiescent_cleanup(
    daemon, tmp_path
):
    task_id, qualification, _ = _completed_draining(daemon)
    before = _token(daemon)
    daemon.stop()
    bootstrap = tmp_path / "bootstrap.token"
    bootstrap.write_text("fresh-bootstrap")
    daemon.bootstrap_token_file = bootstrap
    daemon.start()
    assert _token(daemon) == before
    assert not bootstrap.exists()
    assert daemon.credentials.load("fresh-bootstrap")["actor"] == "bootstrap"
    with pytest.raises(AuthorizationError):
        daemon.credentials.load(before.decode())
    assert _control(
        daemon, task_id, "verify", activation_id=qualification["activation_id"]
    ) == {"fresh": False}
    with pytest.raises(ConflictError):
        _control(
            daemon, task_id, "enable", activation_id=qualification["activation_id"]
        )
    assert (
        _control(daemon, task_id, "finish-drain", qualification=qualification)["state"]
        == "drained"
    )
    assert daemon.credentials.actor_metadata(WORKER_ACTOR) is None


def test_lost_finish_reply_does_not_remove_new_credential(daemon):
    task_id, qualification, placement = _completed_draining(daemon)
    assert (
        _control(daemon, task_id, "finish-drain", qualification=qualification)["state"]
        == "drained"
    )
    newer = copy.deepcopy(qualification)
    newer["activation_id"] = "replacement-after-finish"
    _control(daemon, task_id, "provision", qualification=newer, placement=placement)
    daemon.service.record_remote_activation(task_id, newer, identity=OWNER)
    before = _token(daemon)
    assert (
        _control(daemon, task_id, "finish-drain", qualification=qualification)["state"]
        == "drained"
    )
    assert _token(daemon) == before
    assert (
        daemon.credentials.actor_metadata(WORKER_ACTOR)["qualified_activation"] == newer
    )


def test_pending_generation_survives_restart_and_blocks_foreign_replacement(daemon):
    task_id, qualification, placement = _task(daemon, "pending-before-restart")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    before = _token(daemon)
    daemon.stop()
    daemon.start()
    assert _token(daemon) == before
    foreign_task, foreign, foreign_placement = _task(daemon, "foreign-after-restart")
    with pytest.raises(ConflictError):
        _control(
            daemon,
            foreign_task,
            "provision",
            qualification=foreign,
            placement=foreign_placement,
        )
    assert _token(daemon) == before
    with pytest.raises(ConflictError):
        _control(
            daemon, task_id, "enable", activation_id=qualification["activation_id"]
        )
    assert _control(
        daemon, task_id, "revoke", activation_id=qualification["activation_id"]
    ) == {"revoked": True}
    _control(
        daemon,
        foreign_task,
        "provision",
        qualification=foreign,
        placement=foreign_placement,
    )


def test_corrupt_generation_is_never_rotated_or_removed_by_drain(daemon):
    task_id, qualification, placement = _task(daemon, "corrupt")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    before = _token(daemon)
    metadata_path = daemon.credentials.path_for(WORKER_ACTOR).with_suffix(".json")
    metadata_path.write_text("{}")
    with pytest.raises(ConflictError, match="unresolved"):
        _control(
            daemon,
            task_id,
            "provision",
            qualification=qualification,
            placement=placement,
        )
    with pytest.raises(ConflictError):
        _control(daemon, task_id, "finish-drain", qualification=qualification)
    assert _token(daemon) == before


def test_live_restart_retains_unresolved_attempt_and_refuses_finish(daemon):
    task_id, qualification, placement = _task(daemon, "active-restart")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    daemon.service.record_remote_activation(task_id, qualification, identity=OWNER)
    _control(daemon, task_id, "enable", activation_id=qualification["activation_id"])
    identity = daemon.credentials.load(_token(daemon).decode())
    daemon.service.register_executor(
        {"executor_id": WORKER_ACTOR, "capabilities": ["remote.generation.fixture"]},
        idempotency_key="executor",
    )
    claim = daemon.service.claim_next(
        {
            "executor_id": WORKER_ACTOR,
            "capability_ids": ["remote.generation.fixture"],
            "runtime_epoch": daemon.service.store._current_runtime_epoch(),
            "target": qualification["effective_target"],
        },
        idempotency_key="live-claim",
        identity=identity,
    )
    _control(daemon, task_id, "begin-drain", qualification=qualification)
    before = _token(daemon)
    daemon.stop()
    daemon.start()
    assert _token(daemon) == before
    assert (
        _control(daemon, task_id, "finish-drain", qualification=qualification)["state"]
        == "pending"
    )
    assert (
        daemon.service.task(task_id)["task"]["waiting_reason"]
        == "provider_state_unknown"
    )
    assert (
        daemon.service.store.conn.execute(
            "SELECT settled FROM attempts WHERE id=?", (claim["attempt_id"],)
        ).fetchone()[0]
        == 0
    )
    with pytest.raises(AuthorizationError):
        daemon.service._assert_attempt_identity(
            daemon.service.store.conn.execute(
                "SELECT * FROM attempts WHERE id=?", (claim["attempt_id"],)
            ).fetchone(),
            identity,
        )
    assert (
        daemon.credentials.actor_metadata(WORKER_ACTOR)["qualified_activation"]
        == qualification
    )


def test_existing_remote_generation_defers_local_worker_actor_takeover(daemon):
    task_id, qualification, placement = _task(daemon, "remote-owned")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    before = _token(daemon)
    daemon.local_worker_profiles = {"fixture": {}}
    daemon._provision_credentials()
    assert _token(daemon) == before
    assert daemon._local_worker_deferred is True
    assert daemon.local_worker_launcher is None
    with pytest.raises(ConflictError, match="remote or unresolved"):
        daemon.start_local_worker("fixture", daemon.service.realm["id"])


def test_remote_control_uses_shared_actor_while_local_launcher_is_idle(daemon):
    class IdlePreparer:
        @staticmethod
        def control_alive(_handle):
            return False

        @staticmethod
        def current_handle():
            return None

    daemon.local_worker_profiles = {"fixture": object()}
    daemon.local_worker_preparer = IdlePreparer()
    daemon.local_worker_inspector = object()
    launcher = daemon._create_local_worker_launcher()
    assert launcher.is_idle()
    daemon.credentials.provision(
        WORKER_ACTOR,
        ["worker:execute"],
        metadata={"local_launch_receipt": {"pending-restart-check": True}},
    )
    assert not launcher.is_idle()
    daemon.credentials.revoke(WORKER_ACTOR)
    assert launcher.is_idle()

    task_id, qualification, placement = _task(daemon, "idle-local-launcher")
    _control(
        daemon,
        task_id,
        "provision",
        qualification=qualification,
        placement=placement,
    )
    with launcher._state_lock:
        launcher._active_handle = object()
    with pytest.raises(ConflictError, match="local Worker owns"):
        _control(
            daemon, task_id, "revoke", activation_id=qualification["activation_id"]
        )
    with launcher._state_lock:
        launcher._active_handle = None
    assert _control(
        daemon, task_id, "revoke", activation_id=qualification["activation_id"]
    ) == {"revoked": True}
    assert launcher.is_idle()
    assert not any(path.exists() for path in daemon.credentials._paths(WORKER_ACTOR))


def test_neutral_qualified_task_cannot_bypass_drain_with_unqualified_identity(daemon):
    task_id, qualification, placement = _task(daemon, "neutral")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    daemon.service.record_remote_activation(task_id, qualification, identity=OWNER)
    _control(daemon, task_id, "begin-drain", qualification=qualification)
    daemon.service.register_executor(
        {"executor_id": WORKER_ACTOR, "capabilities": ["remote.generation.fixture"]},
        idempotency_key="executor",
    )
    result = daemon.service.claim_next(
        {
            "executor_id": WORKER_ACTOR,
            "capability_ids": ["remote.generation.fixture"],
            "runtime_epoch": daemon.service.store._current_runtime_epoch(),
            "target": qualification["effective_target"],
        },
        idempotency_key="bypass",
        identity={
            "actor": WORKER_ACTOR,
            "scopes": ["worker:execute"],
            "execution_binding": placement,
        },
    )
    assert result["waiting_reason"] == "remote_activation_missing"
    assert (
        daemon.service.store.conn.execute("SELECT count(*) FROM attempts").fetchone()[0]
        == 0
    )


def test_generic_credential_route_cannot_overwrite_shared_worker(daemon):
    from tests.http_helpers import Api

    task_id, qualification, placement = _task(daemon, "generic-bypass")
    _control(
        daemon, task_id, "provision", qualification=qualification, placement=placement
    )
    before = _token(daemon)
    with pytest.raises(RuntimeError) as error:
        Api(daemon.endpoint, daemon.token).request(
            "POST",
            "/v1/credentials",
            {
                "actor_id": WORKER_ACTOR,
                "credential": "replacement-token",
                "scope": "astrid",
            },
        )
    assert error.value.status == 409
    assert _token(daemon) == before
    assert (
        daemon.credentials.actor_metadata(WORKER_ACTOR)["qualified_activation"]
        == qualification
    )


@pytest.mark.parametrize("cut", ["before-delete", "after-commit", "after-metadata"])
def test_interrupted_exact_credential_delete_reconciles_after_restart(
    daemon, monkeypatch, cut
):
    task_id, qualification, _ = _completed_draining(daemon)
    token_path, metadata_path, commit_path = daemon.credentials._paths(WORKER_ACTOR)
    before = token_path.read_bytes()

    def interrupted(actor):
        assert actor == WORKER_ACTOR
        if cut != "before-delete":
            commit_path.unlink()
        if cut == "after-metadata":
            metadata_path.unlink()
        raise OSError("interrupted credential cleanup")

    monkeypatch.setattr(daemon.credentials, "revoke", interrupted)
    with pytest.raises(OSError):
        _control(daemon, task_id, "finish-drain", qualification=qualification)
    assert daemon.service._latest_remote_activation(task_id) is None
    assert token_path.read_bytes() == before
    daemon.stop()
    daemon.start()
    assert token_path.read_bytes() == before
    with pytest.raises(AuthorizationError):
        daemon.credentials.load(before.decode())
    assert (
        _control(daemon, task_id, "finish-drain", qualification=qualification)["state"]
        == "drained"
    )
    assert not any(path.exists() for path in daemon.credentials._paths(WORKER_ACTOR))
    assert (
        _control(daemon, task_id, "finish-drain", qualification=qualification)["state"]
        == "drained"
    )


@pytest.mark.parametrize("changed", ["token", "metadata", "commit"])
def test_cleanup_intent_cannot_delete_changed_orphan_bytes(
    daemon, monkeypatch, changed
):
    task_id, qualification, _ = _completed_draining(daemon)
    token_path, metadata_path, commit_path = daemon.credentials._paths(WORKER_ACTOR)

    def interrupted(actor):
        if changed != "commit":
            commit_path.unlink()
        if changed == "token":
            metadata_path.unlink()
        raise OSError("interrupted credential cleanup")

    monkeypatch.setattr(daemon.credentials, "revoke", interrupted)
    with pytest.raises(OSError):
        _control(daemon, task_id, "finish-drain", qualification=qualification)
    changed_path = {
        "token": token_path,
        "metadata": metadata_path,
        "commit": commit_path,
    }[changed]
    changed_path.write_bytes(b"changed-or-foreign-bytes")
    before = {
        path: path.read_bytes()
        for path in (token_path, metadata_path, commit_path)
        if path.exists()
    }
    daemon.local_worker_profiles = {"fixture": {}}
    daemon.local_worker_preparer = object()
    daemon.local_worker_inspector = object()
    daemon.stop()
    daemon.start()
    assert daemon.local_worker_launcher is None
    with pytest.raises(ConflictError, match="remote or unresolved"):
        daemon.start_local_worker("fixture", daemon.service.realm["id"])
    with pytest.raises(ConflictError, match="bytes changed"):
        _control(daemon, task_id, "finish-drain", qualification=qualification)
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize("partial_cleanup", [False, True])
def test_remote_cleanup_restart_with_local_profiles_then_local_start(
    daemon, monkeypatch, partial_cleanup
):
    task_id, qualification, _ = _completed_draining(daemon)
    if partial_cleanup:
        token_path, metadata_path, commit_path = daemon.credentials._paths(WORKER_ACTOR)

        def interrupted(actor):
            commit_path.unlink()
            metadata_path.unlink()
            raise OSError("interrupted cleanup")

        monkeypatch.setattr(daemon.credentials, "revoke", interrupted)
        with pytest.raises(OSError):
            _control(daemon, task_id, "finish-drain", qualification=qualification)
    before = _token(daemon)
    daemon.stop()
    local_owner = RuntimeDaemon(
        daemon.root,
        support_root=daemon.support_root,
        production_worker_credentials=True,
        local_worker_profiles={"fixture": {}},
        local_worker_preparer=object(),
        local_worker_inspector=object(),
    )
    try:
        local_owner.start()
        assert local_owner.httpd is not None
        assert local_owner.local_worker_launcher is None
        assert local_owner.credentials.path_for(WORKER_ACTOR).read_bytes() == before
        with pytest.raises(ConflictError, match="remote or unresolved"):
            local_owner.start_local_worker("fixture", local_owner.service.realm["id"])
        assert (
            _control(
                local_owner,
                task_id,
                "finish-drain",
                qualification=qualification,
            )["state"]
            == "drained"
        )
        assert not any(
            path.exists() for path in local_owner.credentials._paths(WORKER_ACTOR)
        )

        class LocalStartProbe:
            def __init__(self, **_kwargs):
                pass

            def start(self, profile_id, workspace_uuid):
                return {
                    "state": "local-started",
                    "profile_id": profile_id,
                    "workspace_uuid": workspace_uuid,
                }

            def begin_shutdown(self):
                return []

            def finish_shutdown(self, _handles):
                return None

        from runtime_protocol import local_worker

        monkeypatch.setattr(local_worker, "LocalWorkerLauncher", LocalStartProbe)
        assert local_owner.start_local_worker(
            "fixture", local_owner.service.realm["id"]
        ) == {
            "state": "local-started",
            "profile_id": "fixture",
            "workspace_uuid": local_owner.service.realm["id"],
        }
    finally:
        local_owner.stop()
