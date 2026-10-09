"""Canonical owner contract proof; no native lifecycle qualification."""
from __future__ import annotations

import copy
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime_protocol.auth import CredentialStore
from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES
from runtime_protocol.errors import ConflictError
from runtime_protocol.local_execution_handoff import FENCE_VERSION, HandoffJournal, read_protected
from runtime_protocol.local_worker import _credential_commit_generation
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _owner(tmp_path):
    root = tmp_path / "realm"; RealmStore.initialize(root)
    support = tmp_path / "support"; support.mkdir(mode=0o700)
    service = RuntimeService(root, support_root=support)
    credentials = CredentialStore(support / "credentials")
    receipt = {"workspace_uuid": service.realm["id"], "executor_incarnation": "incarnation"}
    binding = {"executor_incarnation": "incarnation", "actual": {"kind": "machine", "id": "machine", "profile_revision": "revision", "profile_digest": "sha256:" + "2" * 64, "release_digest": "sha256:" + "3" * 64}, "verification": {"method": "credential_claim", "verified": True, "evidence_digest": "sha256:" + "4" * 64}}
    credentials.provision(WORKER_ACTOR, list(WORKER_SCOPES), metadata={"local_launch_receipt": receipt, "execution_binding": binding})
    daemon = object.__new__(RuntimeDaemon); daemon.service = service; daemon.credentials = credentials
    daemon._worker_actor_lock = threading.RLock()
    service.set_local_claim_generation_verifier(daemon._verify_local_claim_generation, actor=WORKER_ACTOR)
    fence = {"version": FENCE_VERSION, "state": "held", "workspace_uuid": service.realm["id"], "executor_incarnation": "incarnation", "credential_generation_digest": _credential_commit_generation(credentials, WORKER_ACTOR), "operation_id": "operation", "handoff_id": "handoff", "intent_digest": "sha256:" + "1" * 64, "source_owner_epoch": "A", "target_owner_epoch": "B", "fence_generation": 1, "release_ack_digest": None}
    identity = {"actor": WORKER_ACTOR, "scopes": list(WORKER_SCOPES), "execution_binding": binding}
    return daemon, fence, identity


def test_held_fence_rejects_claim_replay_new_claim_and_resume(tmp_path):
    daemon, fence, identity = _owner(tmp_path); service = daemon.service
    try:
        epoch = service.health()["runtime_epoch"]
        body = {"executor_id": WORKER_ACTOR, "capability_ids": [], "runtime_epoch": epoch}
        service.register_executor({"executor_id": WORKER_ACTOR, "runtime_epoch": epoch}, identity=identity)
        assert service.claim_next(body, identity=identity, idempotency_key="old-claim") is None
        service.hold_local_claim_fence(fence, assert_no_work=daemon._assert_worker_actor_has_no_work)
        for key in ("old-claim", "new-claim"):
            with pytest.raises(ConflictError, match="claims are fenced"):
                service.claim_next(body, identity=identity, idempotency_key=key)
        with pytest.raises(ConflictError, match="claims are fenced"):
            service.resume_attempt({"nonce": "n", "authorization": "a", "runtime_epoch": epoch}, identity=identity)
        assert read_protected(service._local_claim_fence_path()) == fence
    finally:
        service.close()


def test_startup_reconstructs_generation_bound_fence_before_admission(tmp_path):
    daemon, fence, identity = _owner(tmp_path); service = daemon.service
    service.hold_local_claim_fence(fence, assert_no_work=daemon._assert_worker_actor_has_no_work)
    root, support = service.store.root, service.support_root
    service.close()
    restarted = RuntimeService(root, support_root=support)
    try:
        assert restarted._local_claim_fence == fence
        with pytest.raises(ConflictError, match="generation is unresolved"):
            restarted.claim_next({"executor_id": WORKER_ACTOR, "capability_ids": [], "runtime_epoch": restarted.health()["runtime_epoch"]}, identity=identity)
        restarted._local_claim_fence_path().write_text('{"version":1,"version":2}')
        with pytest.raises(ConflictError, match="fence is unresolved"):
            restarted.claim_next({"executor_id": WORKER_ACTOR, "capability_ids": [], "runtime_epoch": restarted.health()["runtime_epoch"]}, identity=identity)
    finally:
        restarted.close()


def test_registration_preserves_generation_without_claim_authority(tmp_path):
    daemon, fence, identity = _owner(tmp_path); service = daemon.service
    try:
        before = {p: p.read_bytes() for p in daemon.credentials._paths(WORKER_ACTOR)}
        service.hold_local_claim_fence(fence, assert_no_work=daemon._assert_worker_actor_has_no_work)
        epoch = service.health()["runtime_epoch"]
        registered = service.register_executor({"executor_id": WORKER_ACTOR, "runtime_epoch": epoch}, identity=identity, idempotency_key="selected-register")
        assert registered["executor_id"] == WORKER_ACTOR
        assert before == {p: p.read_bytes() for p in before}
        wrong = copy.deepcopy(identity); wrong["execution_binding"]["executor_incarnation"] = "other"
        with pytest.raises(ConflictError, match="caller differs"):
            service.register_executor({"executor_id": WORKER_ACTOR, "runtime_epoch": epoch}, identity=wrong)
        with pytest.raises(ConflictError, match="claims are fenced"):
            service.claim_next({"executor_id": WORKER_ACTOR, "capability_ids": [], "runtime_epoch": epoch}, identity=identity)
    finally:
        service.close()


def test_store_mutex_is_released_before_control_rpc(tmp_path):
    daemon, fence, identity = _owner(tmp_path); service = daemon.service
    from test_local_execution_supervisor import _handoff_case
    request, reply = _handoff_case(tmp_path)
    daemon.hold_local_execution_claims = lambda binding: service.hold_local_claim_fence(fence, assert_no_work=daemon._assert_worker_actor_has_no_work)
    observed = []
    def rpc(received):
        assert not service.store._mutex._is_owned()
        def another_owner():
            with service.store._mutex:
                observed.append(True)
        thread = threading.Thread(target=another_owner); thread.start(); thread.join(1)
        assert not thread.is_alive()
        return reply
    daemon.local_worker_launcher = SimpleNamespace(retained_handoff_command=rpc)
    try:
        assert daemon.forward_local_execution_handoff(request) == reply
        assert observed == [True]
    finally:
        service.close()


def test_authenticated_committed_outcome_replays_after_deadline_without_side_effect(tmp_path, monkeypatch):
    from test_local_execution_supervisor import _handoff_case
    from runtime_protocol.local_execution_supervisor import RelayHandoffEndpoint
    request, reply = _handoff_case(tmp_path)
    authentications = []; calls = []
    journal = HandoffJournal(tmp_path / "custody" / "relay-handoff-state.json", writer=request["binding"]["source_owner"], owner_epoch="A", authority=lambda: authentications.append(True))
    def rpc(r):
        calls.append(True); return reply
    endpoint = RelayHandoffEndpoint(SimpleNamespace(_call=rpc), journal, verify_binding=lambda b: None, verify_fence=lambda r: None)
    assert endpoint.handoff(request) == reply
    before = journal.path.read_bytes()
    monkeypatch.setattr("runtime_protocol.local_execution_handoff.time.time_ns", lambda: request["binding"]["deadline_unix_ms"] * 1_000_000 + 1_000_000)
    assert endpoint.handoff(request) == reply
    assert len(calls) == 1 and len(authentications) >= 2
    assert journal.path.read_bytes() == before
    journal.authority = lambda: (_ for _ in ()).throw(ConflictError("wrong actual peer"))
    assert endpoint.handoff(request)["status"] == "unresolved"


def _finalization_case(tmp_path, monkeypatch):
    """Real canonical store/credentials/journals; labeled CPU kernel providers.

    Host frames are deterministic protocol fixtures, not joined Astrid proof.
    Native authentication is covered by the earlier frozen transport selectors.
    """
    import hashlib
    from banodoco_local import custody_broker as custody
    from runtime_protocol.local_execution_handoff import VERSION, digest, write_protected
    from runtime_protocol.local_worker_handoff import FreshSuccessorPeer, successor_authentication_digest, relay_transition_id, transfer_relay_to_successor
    from test_local_execution_supervisor import _handoff_case
    daemon, _, identity = _owner(tmp_path); service = daemon.service
    daemon.host = "127.0.0.1"; daemon.httpd = SimpleNamespace(server_port=1234); daemon.instance_id = "B"
    prepare, reply = _handoff_case(tmp_path); b = prepare["binding"]; scope = Path(b["custody_scope"])
    identities = {pid: {"pid": pid, "uid": 501, "birth_id": f"birth-{pid}"} for pid in (10, 11, 20, 21, 22, 23)}
    tokens = {pid: {"pid": pid, "uid": 501, "pidversion": pid + 1, "sha256": "sha256:" + f"{pid:064x}", "words": [pid] * 8} for pid in identities}
    monkeypatch.setattr(custody, "audit_token_details", lambda words: {k: v for k, v in tokens[words[0]].items() if k != "words"})
    monkeypatch.setattr(custody, "default_process_identity", identities.get)
    monkeypatch.setattr(custody, "current_process_audit_token", tokens.get)
    actors = {pid: custody.AuthenticatedCleanupActor(lambda pid=pid: tokens[pid], identities.get) for pid in (10, 11, 20, 21)}
    monkeypatch.setattr(custody.AuthenticatedCleanupActor, "current", classmethod(lambda cls, **kwargs: actors[11]))
    roles = {}
    for role, pid, owner in (("relay", 20, 10), ("host", 21, 20), ("engine", 22, 21), ("engine_listener", 23, 21)):
        authority = custody.RoleCustodyAuthority(scope, role)
        authority.designate_pending(actor=actors[owner], identity=identities[pid], token=tokens[pid], owner_epoch="A")
        authority.bind_target(actor=actors[owner], generation=1, identity=identities[pid], token=tokens[pid])
        roles[role] = authority
    b.update(source_owner=actors[10].verify(), new_owner=actors[11].verify(), workspace_uuid=service.realm["id"],
             executor_incarnation="incarnation", credential_generation_digest=_credential_commit_generation(daemon.credentials, WORKER_ACTOR),
             current_roles={role: authority.reference() for role, authority in roles.items()})
    b["original_roles"] = copy.deepcopy(b["current_roles"]); b["source_relay_reference"] = b["current_roles"]["relay"]
    write_protected(scope / "activation-record.json", {"fixture": "immutable launch evidence without bearer"})
    b["activation_record_digest"] = "sha256:" + hashlib.sha256((scope / "activation-record.json").read_bytes()).hexdigest()
    b["intent_digest"] = digest({"version": VERSION, "binding": {k: v for k, v in b.items() if k != "intent_digest"}})
    health = service.health()
    runtime = {"endpoint": daemon.endpoint, "protocol": health["protocol"], "schema_digest": health["schema_digest"],
               "runtime_epoch": health["runtime_epoch"], "runtime_session_id": service.runtime_session_id,
               "runtime_instance_id": "B", "coordinator_epoch": "B"}
    caps = {"cap": {"capability_digest": "sha256:" + "1" * 64, "source_digest": "sha256:" + "2" * 64, "dependency_digest": "sha256:" + "3" * 64}}
    registration = {"executor_incarnation": "incarnation", "source_epoch": "source", "capabilities": caps, "runtime": runtime}
    body = {"executor_id": WORKER_ACTOR, "runtime_epoch": health["runtime_epoch"], "capabilities": [{"capability_id": "cap", "definition_digest": caps["cap"]["capability_digest"]}],
            "source_digest": digest({"cap": "2" * 64}).removeprefix("sha256:"), "dependency_digest": digest({"cap": "3" * 64}).removeprefix("sha256:"), "source_epoch": "source"}
    service.register_executor(body, identity=identity)
    reply.update(binding_digest=digest(b), request_digest=digest(prepare), registered_state=registration, custody_capabilities=b["current_roles"])
    journal = HandoffJournal(scope / "runtime-handoff-state.json", writer=b["source_owner"], owner_epoch="A",
              authority=lambda: roles["relay"].verify_reference(b["source_relay_reference"], expected_actor=b["source_owner"], owner_epoch="A"))
    relay_journal = HandoffJournal(scope / "relay-handoff-state.json", writer=b["current_roles"]["relay"]["target"], owner_epoch="A", authority=actors[20].verify)
    for j in (journal, relay_journal):
        j.begin(prepare); j.finish(prepare, reply)
    fence = {"version": FENCE_VERSION, "state": "held", **{k: b[k] for k in ("workspace_uuid", "executor_incarnation", "credential_generation_digest", "operation_id", "handoff_id", "intent_digest", "source_owner_epoch")},
             "target_owner_epoch": "B", "fence_generation": 1, "release_ack_digest": None}
    service.hold_local_claim_fence(fence, assert_no_work=daemon._assert_worker_actor_has_no_work)
    export = {"version": "runtime.local-execution-handoff-export/v1", **{k: b[k] for k in ("handoff_id", "intent_digest", "nonce_digest", "credential_generation_digest", "source_owner_epoch", "source_relay_reference", "launch_evidence_digest")},
              "host_pause_ack_digest": digest(reply), "task_fence_digest": digest(fence), "descriptor_identity_digest": "sha256:" + "7" * 64}
    seal = {"version": "runtime.local-execution-handoff-seal/v1", **{k: export[k] for k in ("handoff_id", "intent_digest", "nonce_digest", "credential_generation_digest", "source_owner_epoch", "source_relay_reference", "host_pause_ack_digest", "task_fence_digest")},
            "export_digest": digest(export), "target_owner_epoch": "B", "successor_incarnation": b["new_owner"]}
    sealed = {**prepare, "command": "handoff_export_sealed", "payload": {"export_metadata": export, "seal_record": seal, "sealed_record_digest": digest(seal)}}
    export_reply = {**reply, "command": sealed["command"], "request_digest": digest(sealed), "phase": "export_sealed"}
    for j in (journal, relay_journal):
        j.begin(sealed); j.finish(sealed, export_reply)
    transfer_ack = {"version": "runtime.role-custody-designation/v1", "transition_id": relay_transition_id(b), "role": "relay", "generation": 2,
                    "owner_epoch": "B", "actor": b["new_owner"], "target": b["source_relay_reference"]["target"]}
    adopt = {**prepare, "command": "handoff_adopt", "payload": {"export_digest": digest(export), "sealed_record_digest": digest(seal), "task_fence_digest": digest(fence),
             "relay_transfer_ack": transfer_ack, "successor_authentication_digest": successor_authentication_digest(b, b["new_owner"])}}
    peer = FreshSuccessorPeer(None, actors[11], digest(b), digest(seal))
    def verify_fence(request):
        assert read_protected(service._local_claim_fence_path()) == fence
    transfer_relay_to_successor(adopt, peer=peer, source_actor=actors[10], runtime_journal=journal, authority=roles["relay"], verify_fence=verify_fence)
    current_roles = {**b["current_roles"], "relay": roles["relay"].reference()}
    def verify_b(binding):
        if custody.AuthenticatedCleanupActor.current().verify() != binding["new_owner"]:
            raise ConflictError("wrong actual B")
        if _credential_commit_generation(daemon.credentials, WORKER_ACTOR) != binding["credential_generation_digest"]:
            raise ConflictError("changed current generation")
        roles["relay"].verify_reference(current_roles["relay"], expected_actor=b["new_owner"], owner_epoch="B")
    journal_b = HandoffJournal(journal.path, writer=b["new_owner"], owner_epoch="B", authority=lambda: verify_b(b))
    for command, phase, payload in (
        ("handoff_adopt", "adopt_prepared", adopt["payload"]),
        ("handoff_commit", "rebind_committed", {"new_runtime": runtime, "task_fence_digest": digest(fence), "relay_reference": current_roles["relay"]}),
        ("resume_prepare", "resume_armed", {"new_runtime": runtime, "task_fence_digest": digest(fence), "registered_state_digest": digest(registration)}),
        ("resume_commit", "resumed", {"new_runtime": runtime, "task_fence_digest": digest(fence), "registered_state_digest": digest(registration)}),
        ("handoff_finalize", "finalized", {"task_fence_digest": digest(fence), "registered_state_digest": digest(registration)}),
    ):
        request = {**prepare, "command": command, "payload": payload}
        ack = {**reply, "command": command, "request_digest": digest(request), "phase": phase, "custody_capabilities": current_roles,
               "quiescence": {**reply["quiescence"], "claim_gate_closed": command != "handoff_finalize"}}
        for j in (relay_journal, journal_b):
            j.begin(request); j.finish(request, ack)
    write_protected(scope / "host-handoff-state.json", {"version": "runtime.local-execution-handoff-journal/v1", "writer_incarnation": f"{ack['host']['pid']}:{ack['host']['birth_id']}",
                    "writer_owner_epoch": "A", "handoff_id": b["handoff_id"], "command": "handoff_finalize", "request_digest": digest(request), "reply": ack})
    calls = []
    def rpc(received):
        assert not service.store._mutex._is_owned()
        assert received == request
        calls.append("authenticated_cached_outcome")
        return copy.deepcopy(ack)
    daemon.local_worker_launcher = SimpleNamespace(_verify_adopted_handoff=verify_b, retained_handoff_command=rpc)
    return daemon, request, ack, fence, identity, body, actors, calls


def test_finalize_releases_only_exact_durable_successor_outcome(tmp_path, monkeypatch):
    from runtime_protocol.local_execution_handoff import digest
    daemon, request, ack, fence, identity, _, _, calls = _finalization_case(tmp_path, monkeypatch)
    service = daemon.service
    try:
        credential_bytes = {p: p.read_bytes() for p in daemon.credentials._paths(WORKER_ACTOR)}
        assert daemon.forward_local_execution_handoff(request) == ack
        released = read_protected(service._local_claim_fence_path())
        assert released == {**fence, "state": "released", "release_ack_digest": digest(ack)}
        assert credential_bytes == {p: p.read_bytes() for p in credential_bytes}
        assert calls == ["authenticated_cached_outcome"]
        assert service.claim_next({"executor_id": WORKER_ACTOR, "capability_ids": ["cap"], "runtime_epoch": service.health()["runtime_epoch"]}, identity=identity) is None
    finally:
        service.close()


@pytest.mark.parametrize("changed", ["wrong_B", "registration", "generation", "host_missing", "host_changed", "relay_missing", "relay_changed", "runtime_missing", "runtime_changed", "activation", "fence_digest", "registered_digest", "roles", "unknown"])
def test_finalize_unknown_or_changed_evidence_keeps_claims_fenced(tmp_path, monkeypatch, changed):
    from banodoco_local import custody_broker as custody
    from runtime_protocol.local_execution_handoff import write_protected
    daemon, request, ack, fence, identity, body, actors, calls = _finalization_case(tmp_path, monkeypatch)
    service = daemon.service; scope = Path(request["binding"]["custody_scope"])
    try:
        before = service._local_claim_fence_path().read_bytes()
        if changed == "wrong_B":
            monkeypatch.setattr(custody.AuthenticatedCleanupActor, "current", classmethod(lambda cls, **kwargs: actors[10]))
        elif changed == "registration":
            service.register_executor({**body, "source_epoch": "changed"}, identity=identity)
        elif changed == "generation":
            previous_generation = _credential_commit_generation(daemon.credentials, WORKER_ACTOR)
            metadata = {k: copy.deepcopy(v) for k, v in daemon.credentials.actor_metadata(WORKER_ACTOR).items()
                        if k not in {"actor", "scopes"}}
            daemon.credentials.provision(WORKER_ACTOR, list(WORKER_SCOPES), rotate=True, metadata=metadata)
            assert _credential_commit_generation(daemon.credentials, WORKER_ACTOR) != previous_generation
        elif changed == "activation":
            write_protected(scope / "activation-record.json", {"fixture": "changed immutable activation"})
        elif changed in ("fence_digest", "registered_digest"):
            request = copy.deepcopy(request)
            key = "task_fence_digest" if changed == "fence_digest" else "registered_state_digest"
            request["payload"][key] = "sha256:" + "9" * 64
        elif changed == "roles":
            custody.RoleCustodyAuthority(scope, "engine").transfer(actor=actors[21], next_actor=actors[20], generation=1,
                                       transition_id="different-engine-owner", owner_epoch="A")
        elif changed.endswith("missing"):
            (scope / (changed.split("_")[0] + "-handoff-state.json")).unlink()
        elif changed.endswith("changed"):
            path = scope / (changed.split("_")[0] + "-handoff-state.json"); state = read_protected(path)
            if changed.startswith("host"):
                state["request_digest"] = "sha256:" + "9" * 64
            elif changed.startswith("runtime"):
                state["ownership"]["owner_epoch"] = "changed"
            else:
                state["entries"][request["binding"]["handoff_id"] + ":handoff_finalize"]["request_digest"] = "sha256:" + "9" * 64
            write_protected(path, state)
        else:
            unknown = {**ack, "status": "unresolved", "error_code": "quiescence_unresolved", "quiescence": {k: ("unknown" if k == "observation_status" else None) for k in ack["quiescence"]}}
            daemon.local_worker_launcher.retained_handoff_command = lambda _: unknown
        if changed == "unknown":
            assert daemon.forward_local_execution_handoff(request)["status"] == "unresolved"
        else:
            with pytest.raises((ConflictError, OSError, custody.CustodyError)):
                daemon.forward_local_execution_handoff(request)
        assert service._local_claim_fence_path().read_bytes() == before
        with pytest.raises(ConflictError):
            service.claim_next({"executor_id": WORKER_ACTOR, "capability_ids": ["cap"], "runtime_epoch": service.health()["runtime_epoch"]}, identity=identity)
    finally:
        service.close()


@pytest.mark.parametrize("window", ["normal", "before_fence_write", "after_fence_write"])
def test_finalize_replay_after_lost_ack_preserves_generation_and_side_effects(tmp_path, monkeypatch, window):
    from runtime_protocol import local_execution_handoff as protocol
    daemon, request, ack, fence, identity, _, _, calls = _finalization_case(tmp_path, monkeypatch)
    service = daemon.service; scope = Path(request["binding"]["custody_scope"])
    try:
        snapshot = {p: p.read_bytes() for p in scope.glob("*.json")}
        credential_bytes = {p: p.read_bytes() for p in daemon.credentials._paths(WORKER_ACTOR)}
        original = protocol.write_protected
        def lost_ack(path, value):
            if Path(path) == service._local_claim_fence_path():
                if window == "before_fence_write":
                    raise OSError("before fence persistence")
                original(path, value)
                raise OSError("after fence persistence")
            return original(path, value)
        if window != "normal":
            monkeypatch.setattr(protocol, "write_protected", lost_ack)
            with pytest.raises(OSError, match="fence persistence"):
                daemon.forward_local_execution_handoff(request)
            assert read_protected(service._local_claim_fence_path())["state"] == ("held" if window == "before_fence_write" else "released")
            monkeypatch.setattr(protocol, "write_protected", original)
        assert daemon.forward_local_execution_handoff(request) == ack
        released = service._local_claim_fence_path().read_bytes()
        assert daemon.forward_local_execution_handoff(request) == ack
        assert service._local_claim_fence_path().read_bytes() == released
        assert read_protected(service._local_claim_fence_path())["fence_generation"] == fence["fence_generation"]
        assert credential_bytes == {p: p.read_bytes() for p in credential_bytes}
        assert snapshot == {p: p.read_bytes() for p in snapshot}
        # Changed terminal evidence cannot replay even an already released ACK.
        host_path = scope / "host-handoff-state.json"; changed = read_protected(host_path)
        changed["request_digest"] = "sha256:" + "9" * 64; original(host_path, changed)
        with pytest.raises(ConflictError):
            daemon.forward_local_execution_handoff(request)
        assert service._local_claim_fence_path().read_bytes() == released
    finally:
        service.close()
