from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from runtime_protocol.release_identity import ReleaseIdentityError, build_prelive_manifest, create_candidate_core_identity, create_pre_live_identity, load_receipt


def _git_repo(root: Path) -> Path:
    repo = root / "component"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Release Test"], check=True)
    (repo / "contract.json").write_text('{"version":1}\n')
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
    return repo


def test_runtime_identity_round_trip(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    path = tmp_path / "pre.json"
    pre = create_pre_live_identity({"NEUTRAL-RUNTIME": repo}, output=path)
    assert load_receipt(path)["identity"] == pre["identity"]
    core = create_candidate_core_identity(path, {"NEUTRAL-RUNTIME": repo})
    assert core["candidate_core"]["pre_live_evidence_root"] == pre["identity"]


def test_runtime_identity_rejects_dirty_checkout(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    (repo / "dirty.txt").write_text("pending\n")
    with pytest.raises(ReleaseIdentityError, match="uncommitted"):
        create_pre_live_identity({"NEUTRAL-RUNTIME": repo})


def test_runtime_manifest_rejects_missing_seeds(tmp_path: Path) -> None:
    with pytest.raises(ReleaseIdentityError, match="actual"):
        build_prelive_manifest({})


def test_runtime_receipt_cannot_be_written_inside_component(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    with pytest.raises(ReleaseIdentityError, match="inside"):
        create_pre_live_identity({"NEUTRAL-RUNTIME": repo}, output=repo / "receipt.json")
