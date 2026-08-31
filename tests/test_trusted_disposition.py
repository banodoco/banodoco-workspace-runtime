from __future__ import annotations

import hashlib
import json

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError
from tools.astrid_migrate import (
    DispositionNonceLedger,
    MigrationConfig,
    Migrator,
    RuntimeServiceAdapter,
    build_synthetic_fixture,
    issue_trusted_disposition,
    migrate_with_trusted_disposition,
    resolve_trusted_dispositions,
    seal_trusted_disposition,
    verify_trusted_disposition,
)
from runtime_protocol.service import RuntimeService


def _disposition(tmp_path, *, owner="owner-1", decision="preserve", nonce="nonce-1"):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    config = MigrationConfig(source, tmp_path / "archive", tmp_path / "destination", capacity_margin_bytes=0)
    inventory = Migrator(config).inventory()
    key = b"k" * 32
    value = issue_trusted_disposition(
        owner_identity=owner,
        source_manifest_sha256=inventory["source_manifest_sha256"],
        fact_scope=["owner-data", "media"],
        field_scope=["all"],
        source_pair_scope=["legacy-clone -> neutral-runtime"],
        decision=decision,
        basis_artifact_sha256=hashlib.sha256(b"sealed basis").hexdigest(),
        epochs={"source_epoch": "source-1", "migration_epoch": "migration-1"},
        signing_key=key,
        issuer_identity="release-verifier-1",
        disposition_id="DISPOSITION-B10:test",
        nonce=nonce,
    )
    return config, inventory, key, value


def test_trusted_disposition_is_authenticated_and_bound(tmp_path):
    config, inventory, key, value = _disposition(tmp_path)
    verified = verify_trusted_disposition(
        value, verification_key=key, expected_owner_identity="owner-1", expected_source_manifest_sha256=inventory["source_manifest_sha256"]
    )
    assert verified["source_owner_binding"]["source_owner_id"] == "owner-1"
    sealed = tmp_path / "evidence" / "trusted-disposition.json"
    digest = seal_trusted_disposition(sealed, value, verification_key=key, expected_owner_identity="owner-1", expected_source_manifest_sha256=inventory["source_manifest_sha256"])
    assert len(digest) == 64
    assert json.loads(sealed.read_text())["signature_or_attestation_sha256"] == value["signature_or_attestation_sha256"]


@pytest.mark.parametrize("mutation", ["decision", "source_manifest_sha256", "owner_identity", "signature_or_attestation_sha256"])
def test_tamper_and_foreign_owner_fail_closed(tmp_path, mutation):
    _, inventory, key, value = _disposition(tmp_path)
    forged = dict(value)
    forged[mutation] = "forged" if mutation != "source_manifest_sha256" else "0" * 64
    with pytest.raises((AuthorizationError, ConflictError)):
        verify_trusted_disposition(forged, verification_key=key, expected_owner_identity="owner-1", expected_source_manifest_sha256=inventory["source_manifest_sha256"])


def test_self_issue_and_replay_are_rejected(tmp_path):
    with pytest.raises(AuthorizationError):
        _ = issue_trusted_disposition(owner_identity="same", source_manifest_sha256="0" * 64, fact_scope=[], field_scope=[], source_pair_scope=[], decision="preserve", basis_artifact_sha256="0" * 64, epochs={}, signing_key=b"k" * 32, issuer_identity="same")
    _, inventory, key, value = _disposition(tmp_path)
    ledger = DispositionNonceLedger(tmp_path / "nonce-ledger.json")
    result = resolve_trusted_dispositions([value], verification_key=key, expected_owner_identity="owner-1", expected_source_manifest_sha256=inventory["source_manifest_sha256"], nonce_ledger=ledger)
    assert result["decision"] == "preserve"
    with pytest.raises(ConflictError, match="already been consumed"):
        resolve_trusted_dispositions([value], verification_key=key, expected_owner_identity="owner-1", expected_source_manifest_sha256=inventory["source_manifest_sha256"], nonce_ledger=ledger)


def test_conflicting_decisions_stop_without_resolution(tmp_path):
    _, inventory, key, first = _disposition(tmp_path, nonce="nonce-a")
    second = dict(first)
    second["disposition_id"] = "DISPOSITION-B10:other"
    second["nonce"] = "nonce-b"
    second["decision"] = "exclude"
    second["signature_or_attestation_sha256"] = ""
    second["signature_or_attestation_sha256"] = __import__("tools.astrid_migrate.disposition", fromlist=["_signature"])._signature(second, key)
    with pytest.raises(ConflictError, match="preserve both sides and stop"):
        resolve_trusted_dispositions([first, second], verification_key=key, expected_owner_identity="owner-1", expected_source_manifest_sha256=inventory["source_manifest_sha256"])


def test_authorized_migration_consumes_disposition_and_binds_frozen_source(tmp_path):
    config, inventory, key, value = _disposition(tmp_path)
    runtime = RuntimeService(config.destination_root)
    try:
        report = migrate_with_trusted_disposition(config, RuntimeServiceAdapter(runtime), dispositions=[value], verification_key=key, source_owner_id="owner-1", nonce_ledger=DispositionNonceLedger(tmp_path / "nonce-ledger.json"))
    finally:
        runtime.close()
    assert report["trusted_disposition"]["decision"] == "preserve"
    assert report["trusted_disposition"]["trusted_disposition_sha256"]
    assert report["source_freeze"]
