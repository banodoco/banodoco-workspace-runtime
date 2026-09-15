from pathlib import Path

import pytest

from banodoco_local import RuntimePaths
from banodoco_local.cli import parser


def test_explicit_data_root_is_used_without_mac_support_suffix(tmp_path):
    root = tmp_path / "Astrid" / ".astrid-data"
    paths = RuntimePaths.current_mac(tmp_path / "home", data_root=root)

    assert paths.app_support == root
    assert paths.runtime_support == root / "runtime"
    assert paths.realms_dir == root / "runtime" / "realms"
    assert paths.credentials_dir == root / "credentials"
    assert "Library" not in paths.runtime_support.parts


def test_relative_data_root_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="absolute"):
        RuntimePaths.current_mac(tmp_path, data_root=".astrid-data")


def test_lifecycle_commands_accept_data_root(tmp_path):
    args = parser().parse_args(["status", "--data-root", str(tmp_path / ".astrid-data")])
    assert args.data_root == tmp_path / ".astrid-data"


def test_environment_data_root_and_explicit_precedence_are_isolated(tmp_path, monkeypatch):
    configured = tmp_path / "configured"
    monkeypatch.setenv("BANODOCO_LOCAL_DATA_ROOT", str(configured))
    assert RuntimePaths.current_mac().app_support == configured
    assert RuntimePaths.current_mac(data_root=tmp_path / "explicit").app_support == tmp_path / "explicit"
    assert RuntimePaths.sandbox(tmp_path / "sandbox").app_support != configured
    assert not configured.exists()
