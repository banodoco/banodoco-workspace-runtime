from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate import (
    B13Recovery,
    MigrationError,
    issue_b13_authorizations,
    run_b13_recovery,
)


class _FakeReboot:
    """Faithful test executor: reopen once and publish a changed boot id."""

    def __init__(self, runtime):
        self.runtime = runtime
        self.boot = "fake-boot-before"
        self.calls = 0

    def identity(self):
        return self.boot

    def execute(self, command, checkpoint):
        assert command == "reboot"
        old = self.runtime
        root = old.store.root
        display_name = old.realm["display_name"]
        realm_id = old.realm["id"]
        support_root = old.support_root
        old.close()
        reopened = RuntimeService(root, display_name=display_name, realm_id=realm_id, support_root=support_root)
        self.runtime = reopened
        self.boot = f"fake-boot-after:{checkpoint['checkpoint_id']}"
        self.calls += 1
        return {
            "status": "executed",
            "before_boot_identity": checkpoint["boot_identity_before"],
            "after_boot_identity": self.boot,
            "runtime_epoch_before": checkpoint["runtime_epoch"],
            "runtime_epoch_after": int(reopened.health()["runtime_epoch"]),
            "before_runtime_session_id": checkpoint["runtime_session_id_before"],
            "runtime": reopened,
        }


def _r2_kwargs(active):
    fake = _FakeReboot(active)
    return {"reboot_executor": fake.execute, "boot_identity_provider": fake.identity}, fake


def _setup(tmp_path):
    active = RuntimeService(tmp_path / "active", display_name="Selected")
    # The rollback archive is the pre-migration authority.  Add the migrated
    # project only after it is captured, so final rollback and reactivation
    # exercise different durable identities.
    rollback_archive = tmp_path / "b12-rollback-archive"
    active.backup(rollback_archive)
    active.create_project({"name": "Migrated", "slug": "migrated"})
    auth = issue_b13_authorizations(selected_realm_id=active.realm["id"])
    return active, rollback_archive, auth


def test_b13_r2_purges_only_disposable_target_and_reactivates_verified_state(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    r2, _fake = _r2_kwargs(active)
    try:
        report = run_b13_recovery(
            active,
            recovery_base_backup=tmp_path / "recovery-base",
            rollback_archive=rollback_archive,
            evidence_root=tmp_path / "evidence",
            disposable_root=tmp_path / "disposable",
            authorizations=auth,
            **r2,
        )
        assert report["packet"] == "B13.2"
        assert report["journal"]["state"] == "reactivated"
        assert report["identity"]["integrity_ok"] is True
        assert report["identity"]["runtime_epoch"] == 4
        assert report["active_runtime"].store.realm["id"] == report["identity"]["realm_id"]
        assert report["active_runtime"].list_projects()["items"]
        assert not (tmp_path / "disposable").exists()
        assert json.loads((tmp_path / "evidence" / "purge-receipt-b13.json").read_text())["purged"] is True
        assert json.loads((tmp_path / "evidence" / "activated-destination-b13.json").read_text())["state"] == "reactivated"
        replay = run_b13_recovery(
            report["active_runtime"],
            recovery_base_backup=tmp_path / "recovery-base",
            rollback_archive=rollback_archive,
            evidence_root=tmp_path / "evidence",
            disposable_root=tmp_path / "disposable",
            authorizations=auth,
            **r2,
        )
        assert replay["idempotent"] is True
    finally:
        # The service object can be replaced by the activation helper; close
        # whichever object is currently authoritative.
        active.close()


@pytest.mark.parametrize(
    "crash_at",
    [
        "after_disposable_restore",
        "after_recovery_base",
        "after_purge",
        "after_reboot_execute",
        "after_final_rollback_activation",
        "after_final_reactivation_activation",
    ],
)
def test_b13_r2_resumes_from_each_durable_crash_seam(tmp_path, crash_at):
    active, rollback_archive, auth = _setup(tmp_path)
    r2, fake = _r2_kwargs(active)
    kwargs = dict(
        recovery_base_backup=tmp_path / "recovery-base",
        rollback_archive=rollback_archive,
        evidence_root=tmp_path / "evidence",
        disposable_root=tmp_path / "disposable",
        authorizations=auth,
    )
    recovery = B13Recovery(active, **kwargs, **r2)
    try:
        with pytest.raises(MigrationError, match="injected B13.2 crash"):
            recovery.crash_at = crash_at
            recovery.run()
        # Keep the independent post-R2 RuntimeService that the recovery
        # controller opened; this models the new owner without a second boot.
        recovery.crash_at = None
        resumed = recovery.run()
        assert resumed["journal"]["state"] == "reactivated"
        assert resumed["identity"]["integrity_ok"] is True
        resumed["active_runtime"].close()
    finally:
        active.close()


def test_b13_rejects_conflicting_authorization_and_missing_rollback_archive(tmp_path):
    active = RuntimeService(tmp_path / "active")
    try:
        auth = issue_b13_authorizations(selected_realm_id=active.realm["id"])
        with pytest.raises(MigrationError, match="backup is not authenticated"):
            B13Recovery(
                active,
                tmp_path / "recovery-base",
                tmp_path / "missing-rollback",
                tmp_path / "evidence",
                tmp_path / "disposable",
                auth,
            ).run()
    finally:
        active.close()


def test_b13_authorizations_are_operation_scoped_and_realm_bound(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    try:
        for authorization_id in auth:
            mismatched = {key: dict(value) for key, value in auth.items()}
            mismatched[authorization_id]["scope"] = "wrong-operation"
            with pytest.raises(MigrationError, match="scope"):
                B13Recovery(
                    active,
                    tmp_path / f"base-{authorization_id}",
                    rollback_archive,
                    tmp_path / f"evidence-{authorization_id}",
                    tmp_path / f"disposable-{authorization_id}",
                    mismatched,
                )
        with pytest.raises(ValueError, match="concrete selected realm"):
            issue_b13_authorizations()
        wrong_realm = issue_b13_authorizations(selected_realm_id="different-realm")
        with pytest.raises(MigrationError, match="different selected realm"):
            B13Recovery(
                active,
                tmp_path / "wrong-base",
                rollback_archive,
                tmp_path / "wrong-evidence",
                tmp_path / "wrong-disposable",
                wrong_realm,
            ).run()
    finally:
        active.close()


def test_b13_purge_rejects_a_catalog_selected_or_live_target(tmp_path):
    support = tmp_path / "support"
    active = RuntimeService(tmp_path / "active", support_root=support)
    target = tmp_path / "disposable"
    support.mkdir(parents=True, exist_ok=True)
    (support / "catalog.json").write_text(json.dumps({"version": 1, "selected_realm_id": active.realm["id"], "realms": [{"realm_id": active.realm["id"], "display_name": "Selected", "data_root": str(target)}]}), encoding="utf-8")
    rollback_archive = tmp_path / "rollback"
    active.backup(rollback_archive)
    auth = issue_b13_authorizations(selected_realm_id=active.realm["id"])
    try:
        with pytest.raises(MigrationError, match="classified|authoritative"):
            run_b13_recovery(active, recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=target, authorizations=auth)
        assert not target.exists()
    finally:
        active.close()


def test_b13_purge_rejects_a_source_target(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    source = tmp_path / "source-target"
    try:
        with pytest.raises(MigrationError, match="classified|authoritative"):
            run_b13_recovery(active, recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=source, source_root=source, authorizations=auth)
        assert not source.exists()
    finally:
        active.close()


def test_b13_interrupted_purge_revalidates_target_inode_and_parent(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    disposable = tmp_path / "disposable-parent" / "disposable"
    kwargs = dict(recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=disposable, authorizations=auth)
    try:
        with pytest.raises(MigrationError, match="injected B13.2 crash"):
            run_b13_recovery(active, **kwargs, crash_at="before_purge")
        replacement = disposable
        shutil.rmtree(replacement)
        replacement.mkdir()
        (replacement / "replacement-marker").write_text("must survive", encoding="utf-8")
        with pytest.raises(MigrationError, match="identity|bytes"):
            run_b13_recovery(active, **kwargs)
        assert (replacement / "replacement-marker").exists()
    finally:
        active.close()


def test_b13_interrupted_purge_rejects_a_symlinked_parent(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    parent = tmp_path / "disposable-parent"
    disposable = parent / "disposable"
    outside = tmp_path / "outside"
    kwargs = dict(recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=disposable, authorizations=auth)
    try:
        with pytest.raises(MigrationError, match="injected B13.2 crash"):
            run_b13_recovery(active, **kwargs, crash_at="before_purge")
        parent.rename(tmp_path / "real-disposable-parent")
        outside.mkdir()
        parent.symlink_to(outside, target_is_directory=True)
        with pytest.raises(MigrationError, match="unsafe|ordinary|symlink"):
            run_b13_recovery(active, **kwargs)
        assert parent.is_symlink()
    finally:
        active.close()


def test_b13_interrupted_purge_rejects_catalog_reclassification(tmp_path):
    support = tmp_path / "support"
    active = RuntimeService(tmp_path / "active", display_name="Selected", support_root=support)
    support.mkdir(parents=True, exist_ok=True)
    catalog_path = support / "catalog.json"
    catalog_path.write_text(json.dumps({"version": 1, "selected_realm_id": active.realm["id"], "realms": [{"realm_id": active.realm["id"], "display_name": "Selected", "data_root": str(active.store.root)}]}), encoding="utf-8")
    rollback_archive = tmp_path / "rollback"
    active.backup(rollback_archive)
    auth = issue_b13_authorizations(selected_realm_id=active.realm["id"])
    kwargs = dict(recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=tmp_path / "disposable", authorizations=auth)
    try:
        with pytest.raises(MigrationError, match="injected B13.2 crash"):
            run_b13_recovery(active, **kwargs, crash_at="before_purge")
        value = json.loads(catalog_path.read_text(encoding="utf-8"))
        value["realms"][0]["data_root"] = str(tmp_path / "disposable")
        catalog_path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(MigrationError, match="classification"):
            run_b13_recovery(active, **kwargs)
        assert (tmp_path / "disposable").exists()
    finally:
        active.close()


def test_b13_terminal_replay_requires_purged_target_to_remain_absent(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    r2, _fake = _r2_kwargs(active)
    kwargs = dict(recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=tmp_path / "disposable", authorizations=auth, **r2)
    try:
        report = run_b13_recovery(active, **kwargs)
        Path(tmp_path / "disposable").mkdir()
        with pytest.raises(MigrationError, match="purged target"):
            run_b13_recovery(report["active_runtime"], **kwargs)
    finally:
        try:
            report["active_runtime"].close()
        except (UnboundLocalError, KeyError):
            active.close()


def test_b13_requires_an_explicit_reboot_executor(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    try:
        with pytest.raises(MigrationError, match="injectable reboot executor"):
            run_b13_recovery(active, recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=tmp_path / "disposable", authorizations=auth)
        assert not (tmp_path / "disposable").exists()
    finally:
        active.close()


def test_b13_terminal_replay_survives_a_runtime_process_reopen(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    r2, fake = _r2_kwargs(active)
    kwargs = dict(recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=tmp_path / "disposable", authorizations=auth, **r2)
    try:
        report = run_b13_recovery(active, **kwargs)
        runtime = report["active_runtime"]
        root = runtime.store.root
        display_name = runtime.realm["display_name"]
        realm_id = runtime.realm["id"]
        runtime.close()
        reopened = RuntimeService(root, display_name=display_name, realm_id=realm_id)
        fake.runtime = reopened
        replay = run_b13_recovery(reopened, **kwargs)
        assert replay["idempotent"] is True
        replay["active_runtime"].close()
    finally:
        active.close()


def test_b13_terminal_replay_rejects_corrupt_reachable_cas_bytes(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    active.ingest_object(b"b13-cas-content", media_type="application/octet-stream")
    r2, _fake = _r2_kwargs(active)
    kwargs = dict(recovery_base_backup=tmp_path / "base", rollback_archive=rollback_archive, evidence_root=tmp_path / "evidence", disposable_root=tmp_path / "disposable", authorizations=auth, **r2)
    try:
        report = run_b13_recovery(active, **kwargs)
        digest = next(report["active_runtime"].store.conn.execute("SELECT digest FROM objects"))[0]
        cas_path = report["active_runtime"].store.cas_root / digest[:2] / digest[2:]
        cas_path.write_bytes(b"corrupt-after-terminal")
        with pytest.raises(MigrationError, match="unhealthy|CAS"):
            run_b13_recovery(report["active_runtime"], **kwargs)
    finally:
        try:
            report["active_runtime"].close()
        except (UnboundLocalError, KeyError):
            active.close()


def test_b13_rejects_disposable_symlink_without_deleting_resolved_target(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    outside = tmp_path / "outside-target"
    outside.mkdir()
    disposable = tmp_path / "disposable"
    disposable.symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(MigrationError, match="fresh ordinary path"):
            run_b13_recovery(
                active,
                recovery_base_backup=tmp_path / "recovery-base",
                rollback_archive=rollback_archive,
                evidence_root=tmp_path / "evidence",
                disposable_root=disposable,
                authorizations=auth,
            )
        assert disposable.is_symlink()
        assert outside.exists()
    finally:
        active.close()


def test_b13_terminal_replay_binds_live_wal_identity(tmp_path):
    active, rollback_archive, auth = _setup(tmp_path)
    r2, _fake = _r2_kwargs(active)
    kwargs = dict(
        recovery_base_backup=tmp_path / "recovery-base",
        rollback_archive=rollback_archive,
        evidence_root=tmp_path / "evidence",
        disposable_root=tmp_path / "disposable",
        authorizations=auth,
    )
    kwargs.update(r2)
    try:
        report = run_b13_recovery(active, **kwargs)
        report["active_runtime"].store.conn.execute("UPDATE runtime_lifecycle SET boot_id='tampered' WHERE id=1")
        report["active_runtime"].store.conn.commit()
        with pytest.raises(MigrationError, match="live database identity"):
            run_b13_recovery(report["active_runtime"], **kwargs)
    finally:
        try:
            report["active_runtime"].close()
        except (UnboundLocalError, KeyError):
            active.close()


@pytest.mark.parametrize("conflict", ["disposable_root", "authorization_nonce"])
def test_b13_terminal_replay_rejects_complete_request_conflicts(tmp_path, conflict):
    active, rollback_archive, auth = _setup(tmp_path)
    r2, _fake = _r2_kwargs(active)
    kwargs = dict(
        recovery_base_backup=tmp_path / "recovery-base",
        rollback_archive=rollback_archive,
        evidence_root=tmp_path / "evidence",
        disposable_root=tmp_path / "disposable",
        authorizations=auth,
    )
    kwargs.update(r2)
    try:
        report = run_b13_recovery(active, **kwargs)
        if conflict == "disposable_root":
            kwargs["disposable_root"] = tmp_path / "other-disposable"
        else:
            kwargs["authorizations"]["AUTH-REBOOT-R2"]["nonce"] = "changed-nonce"
        with pytest.raises(MigrationError, match="request binding"):
            run_b13_recovery(report["active_runtime"], **kwargs)
    finally:
        try:
            report["active_runtime"].close()
        except (UnboundLocalError, KeyError):
            active.close()
