from __future__ import annotations

from pathlib import Path

import pytest

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate.migrator import MigrationError
from tools.astrid_migrate.capacity import capture_activation_path
from tools.astrid_migrate.rehearsal import RuntimeServiceAdapter
import tools.astrid_migrate.rehearsal as rehearsal


@pytest.mark.parametrize("state", ["active", "reactivated"])
def test_activation_anchors_last_rename_to_validated_parent(tmp_path: Path, monkeypatch, state: str):
    """A parent swap at the rename syscall cannot redirect activation writes."""
    authority = tmp_path / "authority"
    authority.mkdir()
    active = RuntimeService(authority / "active")
    backup = tmp_path / "backup"
    active.backup(backup)
    candidate = tmp_path / "candidate"
    active.restore(backup, candidate)
    outside = tmp_path / "outside"
    outside.mkdir()
    identity = capture_activation_path(authority / "active")
    original_rename = rehearsal.os.rename
    swapped = False

    def hostile_rename(source, destination, **kwargs):
        nonlocal swapped
        # Trigger at the actual publication rename, after the replacement
        # runtime has been fully prepared.  The old service must remain usable
        # while the failed publication is rolled back.
        if destination == "active" and str(source).startswith(".active.activate-") and not swapped:
            swapped = True
            authority.rename(tmp_path / "authority-real")
            authority.symlink_to(outside, target_is_directory=True)
        return original_rename(source, destination, **kwargs)

    monkeypatch.setattr(rehearsal.os, "rename", hostile_rename)
    try:
        with pytest.raises(MigrationError, match="parent|publication|identity"):
            RuntimeServiceAdapter(active).activate_destination(candidate, state=state, target_identity=identity)
        assert swapped
        assert active.health()["status"] == "ok"
        assert not any(outside.iterdir())
        assert (tmp_path / "authority-real" / "active").is_dir()
    finally:
        active.close()
