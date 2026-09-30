from __future__ import annotations

import os
import json
import stat

import pytest

from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.orderly_handoff import HandoffRecord, RECORD_VERSION, digest, nonce_digest


_FINAL_ACK = {
    "request_digest": "sha256:" + "1" * 64,
    "worker_ack_digest": "sha256:" + "2" * 64,
    "host_ack_digest": "sha256:" + "3" * 64,
}


def _initial(tmp_path):
    directory = tmp_path / "handoff"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return HandoffRecord(directory / "record.json"), {
        "version": RECORD_VERSION,
        "state": "OWNED",
        "handoff_id": "handoff-1",
        "realm_id": "realm-1",
        "realm_root": str(tmp_path / "realm"),
        "support_root": str(directory),
        "deadline_monotonic": 9_999_999_999.0,
        "deadline_unix_ms": 9_999_999_999_999,
        "nonce_digest": None,
        "sealed_record_digest": None,
        "old_owner": {"pid": os.getpid(), "birth_id": "birth-a"},
        "export": None,
        "export_sealed_digest": None,
        "adopter": None,
        "predecessor_active_ref_digest": None,
    }


def test_handoff_record_seals_digest_only_and_enforces_state_cas(tmp_path):
    record, initial = _initial(tmp_path)
    created = record.create(initial)
    raw = "raw-capability-value-that-is-never-durable"
    sealed = record.seal(
        expected_record_digest=created["record_digest"],
        nonce_sha256=nonce_digest(raw),
    )
    assert raw not in record.path.read_text(encoding="utf-8")
    assert sealed["nonce_digest"] == nonce_digest(raw)
    prepared = record.transition(
        expected_state="OWNED",
        new_state="PREPARED",
        handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        updates={"receipt_evidence_digest": "sha256:" + "a" * 64},
    )
    assert prepared["state"] == "PREPARED"
    with pytest.raises(ConflictError, match="compare-and-swap"):
        record.transition(
            expected_state="OWNED",
            new_state="PREPARED",
            handoff_id="handoff-1",
            sealed_record_digest=sealed["sealed_record_digest"],
        )
    with pytest.raises(ValidationError, match="transition"):
        record.transition(
            expected_state="PREPARED",
            new_state="ADOPTED",
            handoff_id="handoff-1",
            sealed_record_digest=sealed["sealed_record_digest"],
        )


def test_handoff_record_atomic_replace_fsyncs_parent_directory(tmp_path, monkeypatch):
    record, initial = _initial(tmp_path)
    observed_modes = []
    real_fsync = os.fsync

    def capture(descriptor):
        observed_modes.append(os.fstat(descriptor).st_mode)
        return real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", capture)
    record.create(initial)
    assert any(stat.S_ISDIR(mode) for mode in observed_modes)


def test_aborted_record_requires_complete_digest_bound_cleanup_receipt(tmp_path):
    record, initial = _initial(tmp_path)
    expected = []
    rows = []
    for offset, role in enumerate(("worker", "host", "engine", "engine_listener"), 1):
        identity = {"pid": 100 + offset, "birth_id": f"birth-{role}"}
        identity_digest = digest(identity)
        expected.append({
            "role": role, "identity": identity,
            "identity_digest": identity_digest,
        })
        rows.append({
            "role": role, "pid": identity["pid"],
            "expected_birth_id": identity["birth_id"],
            "identity_digest": identity_digest,
            "observed_birth_id": None, "associated_alive": False,
            "absent": True,
        })
    final_census = {
        "process_rows": rows,
        "listener": {
            "host": "127.0.0.1", "port": 8188,
            "expected_owner_pid": expected[-1]["identity"]["pid"],
            "expected_owner_birth_id": expected[-1]["identity"]["birth_id"],
            "observed_owner_pid": None, "owner_absent": True,
            "port_free": True,
        },
        "uncertainties": [],
    }
    final_census["census_digest"] = digest(final_census)
    receipt = {
        "version": 1,
        "runtime_instance_id": "runtime-b",
        "receipt_evidence_digest": "sha256:" + "9" * 64,
        "expected_processes": expected,
        "graph_and_engine_listener_absent": True,
        "authority_descriptors_closed": True,
        "worker_credential_revoked": True,
        "catalog_neutral": True,
        "discovery_absent": True,
        "replacement_graph_not_launched": True,
        "final_census": final_census,
        "complete": True,
    }
    export_receipt = {
        "version": "runtime.local-worker-receipt/v3",
        "evidence_digest": receipt["receipt_evidence_digest"],
        "engine_binding": {
            "endpoint": "http://127.0.0.1:8188",
            "socket_owner_pid": expected[-1]["identity"]["pid"],
        },
        **{row["role"]: row["identity"] for row in expected},
    }
    export = {"receipt": export_receipt}
    created_owned = record.create({
        **initial,
        "export": export,
        "export_sealed_digest": digest(export),
    })
    with pytest.raises(ConflictError, match="cleanup receipt"):
        record.transition(
            expected_state="OWNED",
            new_state="ABORTED",
            handoff_id="handoff-1",
            sealed_record_digest=None,
            expected_record_digest=created_owned["record_digest"],
            updates={"abort_reason": "test"},
        )
    created = record.transition(
        expected_state="OWNED",
        new_state="ABORTED",
        handoff_id="handoff-1",
        sealed_record_digest=None,
        expected_record_digest=created_owned["record_digest"],
        updates={
            "abort_reason": "test",
            "cleanup_receipt": receipt,
            "cleanup_receipt_digest": digest(receipt),
        },
    )
    assert created["cleanup_receipt_digest"] == digest(receipt)
    for mutation in (
        {**receipt, "expected_processes": []},
        {**receipt, "final_census": {}},
        {
            **receipt,
            "final_census": {
                **final_census,
                "uncertainties": ["identity unavailable"],
                "census_digest": digest({
                    **{
                        key: item for key, item in final_census.items()
                        if key != "census_digest"
                    },
                    "uncertainties": ["identity unavailable"],
                }),
            },
        },
    ):
        with pytest.raises(ConflictError, match="cleanup|census|process"):
            HandoffRecord._validate({
                **created,
                "cleanup_receipt": mutation,
                "cleanup_receipt_digest": digest(mutation),
                "record_digest": digest({
                    key: item for key, item in {
                        **created,
                        "cleanup_receipt": mutation,
                        "cleanup_receipt_digest": digest(mutation),
                    }.items() if key != "record_digest"
                }),
            })

    changed_identity = json.loads(json.dumps(receipt))
    changed_identity["expected_processes"][0]["identity"]["pid"] = 999
    changed_identity["expected_processes"][0]["identity_digest"] = digest(
        changed_identity["expected_processes"][0]["identity"]
    )
    changed_identity["final_census"]["process_rows"][0].update({
        "pid": 999,
        "identity_digest": changed_identity["expected_processes"][0]["identity_digest"],
    })
    changed_identity["final_census"]["census_digest"] = digest({
        key: item for key, item in changed_identity["final_census"].items()
        if key != "census_digest"
    })
    for mutation in (
        {**receipt, "receipt_evidence_digest": "sha256:" + "8" * 64},
        changed_identity,
    ):
        candidate = {
            **created,
            "cleanup_receipt": mutation,
            "cleanup_receipt_digest": digest(mutation),
        }
        candidate["record_digest"] = digest({
            key: item for key, item in candidate.items() if key != "record_digest"
        })
        with pytest.raises(ConflictError, match="sealed export"):
            HandoffRecord._validate(candidate)


def test_handoff_record_refuses_raw_nonce_and_non_owner_directory(tmp_path):
    record, initial = _initial(tmp_path)
    with pytest.raises(ValidationError, match="raw capability"):
        record.create({**initial, "nonce": "secret"})
    with pytest.raises(ValidationError, match="raw capability"):
        record.create({**initial, "nested": {"nonce": "secret"}})

    weak = tmp_path / "weak"
    weak.mkdir(mode=0o755)
    weak.chmod(0o755)
    with pytest.raises(ValidationError, match="owner-only"):
        HandoffRecord(weak / "record.json").create(initial)


def test_handoff_record_rejects_invalid_capability_digest_before_mutation(tmp_path):
    record, initial = _initial(tmp_path)
    created = record.create(initial)
    before = record.path.read_bytes()
    with pytest.raises(ValidationError, match="capability digest"):
        record.seal(
            expected_record_digest=created["record_digest"],
            nonce_sha256="sha256:not-a-digest",
        )
    assert record.path.read_bytes() == before


def test_export_seal_and_sole_adopter_form_one_stale_safe_digest_chain(tmp_path):
    record, initial = _initial(tmp_path)
    created = record.create({**initial, "export": None, "export_sealed_digest": None})
    sealed = record.seal(
        expected_record_digest=created["record_digest"],
        nonce_sha256=nonce_digest("x" * 32),
    )
    export = {
        "receipt": {"version": "runtime.local-worker-receipt/v3", "evidence_digest": "sha256:" + "a" * 64},
        "identity": {"worker": {"pid": 41, "birth_id": "worker-birth"}},
        "credential_generation": {"generation": "g1"},
        "registered_state": {"executor_id": "astrid-pack-host"},
    }
    bound_export = record.bind_export(
        handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=sealed["record_digest"],
        export=export,
    )
    assert bound_export["export"] == export
    assert bound_export["export_sealed_digest"].startswith("sha256:")
    before_stale_export = record.path.read_bytes()
    with pytest.raises(ConflictError, match="export compare-and-swap"):
        record.bind_export(
            handoff_id="handoff-1",
            sealed_record_digest=sealed["sealed_record_digest"],
            expected_record_digest=sealed["record_digest"],
            export={**export, "identity": {}},
        )
    assert record.path.read_bytes() == before_stale_export

    prepared = record.transition(
        expected_state="OWNED", new_state="PREPARED", handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=bound_export["record_digest"],
    )
    committed = record.transition(
        expected_state="PREPARED", new_state="COMMITTED_ORPHAN", handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=prepared["record_digest"],
        updates={"owner_a_released": True},
    )
    adopter = {"pid": 52, "birth_id": "owner-b-birth", "runtime_instance_id": "runtime-b"}
    adopted_binding = record.bind_adopter(
        handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=committed["record_digest"],
        adopter=adopter,
    )
    assert adopted_binding["state"] == "COMMITTED_ORPHAN"
    assert adopted_binding["adopter"] == adopter
    before_contender = record.path.read_bytes()
    with pytest.raises(ConflictError, match="sole-adopter"):
        record.bind_adopter(
            handoff_id="handoff-1",
            sealed_record_digest=sealed["sealed_record_digest"],
            expected_record_digest=committed["record_digest"],
            adopter={"pid": 53, "birth_id": "contender", "runtime_instance_id": "runtime-c"},
        )
    assert record.path.read_bytes() == before_contender

    finalizing = record.transition(
        expected_state="COMMITTED_ORPHAN", new_state="FINALIZING", handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=adopted_binding["record_digest"],
        updates={
            "result": {"state": "resume_committed"},
            "new_owner": {
                "pid": 52,
                "birth_id": "owner-b-birth",
                "runtime_instance_id": "runtime-b",
                "runtime": {"runtime_instance_id": "runtime-b"},
            },
            "finalization": {"final_ack": None, "ready_surfaces": False},
        },
    )
    final_acknowledged = record.checkpoint_finalizing(
        handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=finalizing["record_digest"],
        final_ack=_FINAL_ACK,
        ready_surfaces=False,
    )
    before_rollback = record.path.read_bytes()
    with pytest.raises(ConflictError, match="cannot be rolled back"):
        record.checkpoint_finalizing(
            handoff_id="handoff-1",
            sealed_record_digest=sealed["sealed_record_digest"],
            expected_record_digest=final_acknowledged["record_digest"],
            final_ack=None,
            ready_surfaces=False,
        )
    assert record.path.read_bytes() == before_rollback
    surfaced = record.checkpoint_finalizing(
        handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=final_acknowledged["record_digest"],
        final_ack=_FINAL_ACK,
        ready_surfaces=True,
    )
    assert surfaced["finalization"] == {
        "final_ack": _FINAL_ACK,
        "ready_surfaces": True,
    }
    final = record.transition(
        expected_state="FINALIZING", new_state="ADOPTED", handoff_id="handoff-1",
        sealed_record_digest=sealed["sealed_record_digest"],
        expected_record_digest=surfaced["record_digest"],
        updates={"publication_predecessor_digest": surfaced["record_digest"]},
    )
    assert final["state"] == "ADOPTED"
    assert final["export"] == export
    assert final["adopter"] == adopter
