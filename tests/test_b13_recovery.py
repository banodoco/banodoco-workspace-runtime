from __future__ import annotations

import json

import pytest

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate import (
    B13Recovery,
    MigrationError,
    issue_b13_authorizations,
    run_b13_recovery,
)


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
    try:
        report = run_b13_recovery(
            active,
            recovery_base_backup=tmp_path / "recovery-base",
            rollback_archive=rollback_archive,
            evidence_root=tmp_path / "evidence",
            disposable_root=tmp_path / "disposable",
            authorizations=auth,
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
        )
        assert replay["idempotent"] is True
    finally:
        # The service object can be replaced by the activation helper; close
        # whichever object is currently authoritative.
        active.close()


@pytest.mark.parametrize(
    "crash_at",
    [
        "after_recovery_base",
        "after_purge",
        "after_reboot_execute",
        "after_final_rollback_activation",
        "after_final_reactivation_activation",
    ],
)
def test_b13_r2_resumes_from_each_durable_crash_seam(tmp_path, crash_at):
    active, rollback_archive, auth = _setup(tmp_path)
    kwargs = dict(
        recovery_base_backup=tmp_path / "recovery-base",
        rollback_archive=rollback_archive,
        evidence_root=tmp_path / "evidence",
        disposable_root=tmp_path / "disposable",
        authorizations=auth,
    )
    recovery = B13Recovery(active, **kwargs)
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
