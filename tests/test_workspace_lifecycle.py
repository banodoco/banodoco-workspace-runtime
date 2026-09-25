from __future__ import annotations

import json
from pathlib import Path

import pytest

from banodoco_local.bootstrap import BootstrapConfig, BootstrapError, SourceProfile, bootstrap
from banodoco_local.paths import RuntimePaths
from banodoco_local.workspace import configure_workspace, inspect_workspace
from runtime_protocol.store import RealmStore


class _Boundary:
    def __init__(self):
        self.calls = []

    def create(self, *, realm_id, realm_root, display_name, source_profile):
        self.calls.append(("create", realm_id, Path(realm_root)))
        RealmStore.initialize(realm_root, realm_id=realm_id, display_name=display_name).close()
        return {"state": "created", "realm_id": realm_id}

    def inspect(self, *, realm_root):
        self.calls.append(("inspect", Path(realm_root)))
        return RealmStore.inspect_realm(realm_root)

    def start(self, **_kwargs):
        self.calls.append(("start",))
        raise AssertionError("observation/setup test must not launch")


def _config(tmp_path):
    profile = SourceProfile("astrid", str(tmp_path), str(tmp_path))
    return BootstrapConfig(source_profile=profile)


def test_up_refuses_missing_selection_without_creating_support_state(tmp_path):
    support = tmp_path / "support"
    paths = RuntimePaths.current_mac(data_root=support)
    boundary = _Boundary()
    with pytest.raises(BootstrapError, match="No workspace is configured"):
        bootstrap(paths, boundary, _config(tmp_path))
    assert not support.exists()
    assert boundary.calls == []


def test_explicit_create_preserves_omitted_vs_explicit_empty_identity(tmp_path):
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    boundary = _Boundary()
    with pytest.raises(BootstrapError, match="opaque identifier"):
        configure_workspace(
            paths,
            boundary,
            _config(tmp_path),
            mode="create",
            realm_root=tmp_path / "empty-id",
            realm_id="",
        )
    assert not paths.app_support.exists()

    result = configure_workspace(
        paths,
        boundary,
        _config(tmp_path),
        mode="create",
        realm_root=tmp_path / "generated-id",
        realm_id=None,
    )
    assert result["status"] == "configured_create"
    assert result["realm_id"]
    catalog = json.loads(paths.catalog_path.read_text())
    assert catalog["selected_realm_id"] == result["realm_id"]


def test_attach_accepts_bounded_opaque_identity_and_fences_mismatch(tmp_path):
    root = tmp_path / "existing"
    RealmStore.initialize(root, realm_id="realm:opaque-01").close()
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    boundary = _Boundary()
    with pytest.raises(BootstrapError, match="identity mismatch"):
        configure_workspace(
            paths,
            boundary,
            _config(tmp_path),
            mode="attach",
            realm_root=root,
            realm_id="wrong",
        )
    assert not paths.app_support.exists()

    result = configure_workspace(
        paths,
        boundary,
        _config(tmp_path),
        mode="attach",
        realm_root=root,
        realm_id="realm:opaque-01",
    )
    assert result["realm_id"] == "realm:opaque-01"


def test_candidate_inspection_is_nonstarting_and_does_not_create_support(tmp_path):
    root = tmp_path / "candidate"
    RealmStore.initialize(root, realm_id="candidate-id").close()
    files_before = {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    directories_before = sorted(
        path.relative_to(root) for path in root.rglob("*") if path.is_dir()
    )
    paths = RuntimePaths.current_mac(data_root=tmp_path / "support")
    boundary = _Boundary()
    result = inspect_workspace(
        paths,
        boundary,
        realm_root=root,
        expected_realm_id="candidate-id",
    )
    assert result["state"] == "inspectable"
    assert not paths.app_support.exists()
    assert [call[0] for call in boundary.calls] == ["inspect"]
    assert {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    } == files_before
    assert sorted(path.relative_to(root) for path in root.rglob("*") if path.is_dir()) == directories_before
