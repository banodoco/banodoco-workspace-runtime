from __future__ import annotations

import json

import pytest

from runtime_protocol.auth import CredentialStore
from runtime_protocol.errors import ValidationError


def test_generation_snapshot_is_secret_free_stable_while_disabled_and_rotates(tmp_path):
    store = CredentialStore(tmp_path / "credentials")
    token, _ = store.provision("worker", ["worker:execute"], metadata={"profile": "p1"})

    first = store.generation_snapshot("worker")
    assert set(first) == {
        "generation",
        "token_sha256",
        "metadata_sha256",
        "commit_sha256",
    }
    assert token not in json.dumps(first, sort_keys=True)

    store.disable_actor("worker")
    assert store.generation_snapshot("worker") == first
    store.enable_actor("worker")
    assert store.generation_snapshot("worker") == first

    rotated, _ = store.provision(
        "worker", ["worker:execute"], metadata={"profile": "p1"}, rotate=True
    )
    second = store.generation_snapshot("worker")
    assert rotated != token
    assert second["generation"] != first["generation"]
    assert second["token_sha256"] != first["token_sha256"]
    assert second["commit_sha256"] != first["commit_sha256"]


def test_generation_snapshot_rejects_a_corrupt_commit_marker(tmp_path):
    store = CredentialStore(tmp_path / "credentials")
    _, token_path = store.provision("worker", ["worker:execute"])
    commit_path = token_path.with_suffix(".commit")
    commit = json.loads(commit_path.read_text(encoding="utf-8"))
    commit.pop("generation")
    commit_path.write_text(json.dumps(commit), encoding="utf-8")
    commit_path.chmod(0o600)

    with pytest.raises(ValidationError, match="generation marker"):
        store.generation_snapshot("worker")
