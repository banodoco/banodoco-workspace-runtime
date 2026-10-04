from __future__ import annotations

import os
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR
from runtime_protocol.errors import ConflictError
from runtime_protocol.store import RealmStore
from tests.test_local_worker_placement import FakeInspector, FakePreparer, _observation, _profile
from tests.test_remote_credential_generation import _task
from tests.test_remote_worker_activation import OWNER


class StoreProxy:
    store = None

    def __getattr__(self, name):
        return getattr(self.store, name)


class StopPreparer(FakePreparer):
    fail_stop = False

    def prepare(self, profile, *, operation_id, channel_id):
        self.aborted = False
        return super().prepare(profile, operation_id=operation_id, channel_id=channel_id)

    def stop_owned(self, receipt, *, handle=None):
        assert receipt["worker"]["pid"] == self.observation.worker.pid
        if handle is not None:
            assert handle is self.handle
        self.events.append("stop_owned")
        if self.fail_stop:
            raise ConflictError("receipt-owned process stop failed")
        self.handle = None
        self.aborted = True
        return True


def _daemon(tmp_path, preparer=None, proxy=None):
    root = tmp_path / "realm"
    if not root.exists():
        initialized = RealmStore.initialize(root)
        workspace_uuid = initialized.realm["id"]
        initialized.close()
    else:
        opened = RealmStore(root)
        workspace_uuid = opened.realm["id"]
        opened.close()
    profile = _profile(tmp_path, workspace_uuid)
    proxy = proxy or StoreProxy()
    observation = _observation(profile, os.getpid())
    preparer = preparer or StopPreparer(proxy, observation)
    inspector = FakeInspector(proxy, observation)
    daemon = RuntimeDaemon(
        root, support_root=profile.support_root,
        production_worker_credentials=True,
        local_worker_profiles={"astrid": profile},
        local_worker_preparer=preparer,
        local_worker_inspector=inspector,
    ).start()
    proxy.store = daemon.credentials
    return daemon, preparer, proxy, workspace_uuid


def _launch(daemon, workspace_uuid):
    return Api(daemon.endpoint, daemon.token).request(
        "POST", "/v1/control/local-worker/start",
        {"profile_id": "astrid", "expected_workspace_uuid": workspace_uuid},
    )


def _relinquish(daemon, launch):
    return Api(daemon.endpoint, daemon.token).request(
        "POST", "/v1/control/local-worker/relinquish",
        {"executor_incarnation": launch["executor_incarnation"],
         "evidence_digest": launch["evidence_digest"]},
    )


def test_owner_exact_handover_fences_and_retires_local_generation(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path)
    try:
        launch = _launch(daemon, workspace_uuid)
        observed = Api(daemon.endpoint, daemon.token).request(
            "GET", "/v1/control/local-worker/generation"
        )
        assert observed["executor_incarnation"] == launch["executor_incarnation"]
        assert observed["evidence_digest"] == launch["evidence_digest"]
        assert observed["state"] == "active"
        worker_token = daemon.credentials.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
        with pytest.raises(RuntimeError) as denied_read:
            Api(daemon.endpoint, worker_token).request(
                "GET", "/v1/control/local-worker/generation"
            )
        assert denied_read.value.status == 401
        with pytest.raises(RuntimeError) as denied:
            Api(daemon.endpoint, daemon.token).request(
                "POST", "/v1/control/local-worker/relinquish",
                {"executor_incarnation": "foreign", "evidence_digest": launch["evidence_digest"]},
            )
        assert denied.value.status == 409
        assert preparer.events.count("stop_owned") == 0

        result = _relinquish(daemon, launch)
        assert result == {"state": "relinquished", "executor_incarnation": launch["executor_incarnation"]}
        assert preparer.events.count("stop_owned") == 1
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is None
        assert daemon.local_worker_launcher is None
        assert _relinquish(daemon, launch) == result
    finally:
        daemon.stop()


def test_handover_refuses_active_actor_claim_and_reservation(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path)
    try:
        launch = _launch(daemon, workspace_uuid)
        service = daemon.service
        capability = service.register_capability({
            "capability_id": "handover.fixture",
            "definition_digest": "sha256:" + hashlib.sha256(b"handover.fixture").hexdigest(),
        })
        service.register_executor({
            "executor_id": WORKER_ACTOR, "capabilities": ["handover.fixture"],
            "max_concurrency": 1, "resource_keys": ["gpu"],
        }, idempotency_key="handover-executor")
        task = service.create_task({
            "capability_id": "handover.fixture",
            "capability_digest": capability["definition_digest"],
            "input_object_ids": [], "spec": {}, "idempotency_key": "handover-task",
        })["task"]
        claim = service.claim_next({
            "executor_id": WORKER_ACTOR, "capability_ids": ["handover.fixture"],
            "runtime_epoch": service.store._current_runtime_epoch(),
        }, idempotency_key="handover-claim")
        assert claim["task_id"] == task["id"]
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 409
        assert preparer.events.count("stop_owned") == 0
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
    finally:
        daemon.stop()


def test_failed_stop_stays_fenced_and_exact_replay_survives_restart(tmp_path):
    daemon, preparer, proxy, workspace_uuid = _daemon(tmp_path)
    launch = _launch(daemon, workspace_uuid)
    preparer.fail_stop = True
    try:
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 409
        assert daemon._local_relinquish_state()["state"] == "stop_unknown"
        assert Api(daemon.endpoint, daemon.token).request(
            "GET", "/v1/control/local-worker/generation"
        )["state"] == "stop_unknown"
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
        assert daemon.credentials._disabled_actors == {WORKER_ACTOR}
    finally:
        daemon.stop()

    preparer.fail_stop = False
    replacement, _, _, _ = _daemon(tmp_path, preparer, proxy)
    try:
        assert replacement.local_worker_launcher is None
        assert replacement._local_worker_deferred
        restored = Api(replacement.endpoint, replacement.token).request(
            "GET", "/v1/control/local-worker/generation"
        )
        assert restored["executor_incarnation"] == launch["executor_incarnation"]
        assert restored["state"] == "stop_unknown"
        with pytest.raises(RuntimeError) as denied:
            Api(replacement.endpoint, replacement.token).request(
                "POST", "/v1/control/local-worker/relinquish",
                {"executor_incarnation": "foreign", "evidence_digest": launch["evidence_digest"]},
            )
        assert denied.value.status == 409
        assert _relinquish(replacement, launch)["state"] == "relinquished"
        assert replacement.credentials.actor_metadata(WORKER_ACTOR) is None
    finally:
        replacement.stop()


def test_relinquished_actor_allows_remote_provision_then_fresh_local_launcher(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path)
    try:
        launch = _launch(daemon, workspace_uuid)
        old_launcher = daemon.local_worker_launcher
        _relinquish(daemon, launch)
        task_id, qualification, placement = _task(daemon, "after-local-handover")
        daemon.remote_credential_control(
            task_id, {"action": "provision", "qualification": qualification, "placement": placement},
            identity=OWNER,
        )
        daemon.service.record_remote_activation(task_id, qualification, identity=OWNER)
        daemon.remote_credential_control(
            task_id, {"action": "enable", "activation_id": qualification["activation_id"]},
            identity=OWNER,
        )
        with pytest.raises(RuntimeError) as denied:
            _launch(daemon, workspace_uuid)
        assert denied.value.status == 409
        daemon.remote_credential_control(
            task_id, {"action": "begin-drain", "qualification": qualification},
            identity=OWNER,
        )
        daemon.service.cancel_run(
            daemon.service.store.get_task(task_id)["run"]["id"],
            idempotency_key="handover-finish-remote-run",
        )
        assert daemon.remote_credential_control(
            task_id, {"action": "finish-drain", "qualification": qualification},
            identity=OWNER,
        )["state"] == "drained"
        daemon.local_worker_inspector.calls = 0
        fresh = _launch(daemon, workspace_uuid)
        assert fresh["executor_incarnation"] != launch["executor_incarnation"]
        assert daemon.local_worker_launcher is not old_launcher
        assert preparer.events.count("prepare") == 2
    finally:
        daemon.stop()


def test_claim_cannot_race_fenced_generation_and_store_remains_available(tmp_path):
    daemon, preparer, _, workspace_uuid = _daemon(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    original_stop = preparer.stop_owned

    def waiting_stop(receipt, *, handle=None):
        entered.set()
        assert release.wait(5)
        return original_stop(receipt, handle=handle)

    preparer.stop_owned = waiting_stop
    try:
        launch = _launch(daemon, workspace_uuid)
        worker_token = daemon.credentials.path_for(WORKER_ACTOR).read_text(encoding="utf-8")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_relinquish, daemon, launch)
            assert entered.wait(3)
            assert Api(daemon.endpoint, None).health()["status"] == "ok"
            with pytest.raises(RuntimeError) as denied:
                Api(daemon.endpoint, worker_token).request(
                    "POST", "/v1/tasks/claim",
                    {"executor_id": WORKER_ACTOR, "capability_ids": [],
                     "runtime_epoch": daemon.service.store._current_runtime_epoch()},
                    headers={"Idempotency-Key": "claim-during-local-stop"},
                )
            assert denied.value.status == 401
            release.set()
            assert future.result(timeout=5)["state"] == "relinquished"
    finally:
        release.set()
        daemon.stop()


def test_credential_cleanup_failure_replays_exact_stopped_generation_after_restart(tmp_path):
    daemon, preparer, proxy, workspace_uuid = _daemon(tmp_path)
    launch = _launch(daemon, workspace_uuid)

    def failed_revoke(_actor):
        raise OSError("injected credential cleanup failure")

    daemon.credentials.revoke = failed_revoke
    try:
        with pytest.raises(RuntimeError) as denied:
            _relinquish(daemon, launch)
        assert denied.value.status == 500
        assert daemon._local_relinquish_state()["state"] == "stopped"
        assert preparer.events.count("stop_owned") == 1
        assert daemon.credentials.actor_metadata(WORKER_ACTOR) is not None
    finally:
        daemon.stop()

    replacement, _, _, _ = _daemon(tmp_path, preparer, proxy)
    try:
        assert replacement._local_worker_deferred
        assert _relinquish(replacement, launch)["state"] == "relinquished"
        assert replacement.credentials.actor_metadata(WORKER_ACTOR) is None
    finally:
        replacement.stop()
