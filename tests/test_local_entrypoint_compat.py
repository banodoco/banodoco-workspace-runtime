"""N1 canonical/legacy Runtime entrypoint contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path
import tomllib

import pytest

from banodoco_local import entrypoint
from banodoco_local import cli
from banodoco_local import paths as runtime_paths
from banodoco_local import provenance
from banodoco_local import runtime_boundary
from banodoco_local.compatibility import (
    EnvironmentMigrationError,
    apply_legacy_environment,
    resolve_environment,
)


@pytest.mark.parametrize("alias", ["astrid-local", "banodoco-local", "astrid-runtime"])
def test_aliases_share_one_provenance_owner(monkeypatch, capsys, tmp_path, alias: str) -> None:
    monkeypatch.setenv("ASTRID_LOCAL_DATA_ROOT", str(tmp_path / "support"))
    monkeypatch.delenv("BANODOCO_LOCAL_DATA_ROOT", raising=False)
    monkeypatch.setattr(sys, "argv", [alias, "--provenance"])
    assert entrypoint.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["implementation_owner"] == "banodoco_local.cli:main"
    assert output["distribution"] == "banodoco-workspace-runtime"
    assert output["command_alias"] == alias
    assert output["deprecation_target"] == (None if alias == "astrid-local" else "astrid-local")


@pytest.mark.parametrize("alias", ["astrid-local", "banodoco-local", "astrid-runtime"])
def test_aliases_report_canonical_support_root_and_selected_realm(
    monkeypatch, capsys, tmp_path, alias: str
) -> None:
    support_root = tmp_path / "astrid-data"
    runtime_root = support_root / "runtime"
    realm_root = runtime_root / "realms" / "realm-1"
    realm_root.mkdir(parents=True)
    (runtime_root / "catalog.json").write_text(
        json.dumps(
            {
                "version": 1,
                "selected_realm_id": "realm-1",
                "realms": [
                    {
                        "realm_id": "realm-1",
                        "display_name": "Astrid Workspace",
                        "data_root": str(realm_root),
                    }
                ],
                "source_profiles": {},
            }
        ),
        encoding="utf-8",
    )
    source_manifest = tmp_path / "source-profile.json"
    source_manifest.write_text(
        json.dumps({"profile": "astrid", "selected_realm_id": "untrusted-realm"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASTRID_LOCAL_DATA_ROOT", str(support_root))
    monkeypatch.setenv("ASTRID_LOCAL_SOURCE_MANIFEST", str(source_manifest))
    monkeypatch.delenv("BANODOCO_LOCAL_DATA_ROOT", raising=False)
    monkeypatch.delenv("BANODOCO_LOCAL_SOURCE_MANIFEST", raising=False)
    monkeypatch.setattr(sys, "argv", [alias, "--provenance"])

    assert entrypoint.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["support_root"] == str(support_root)
    assert output["realm_id"] == "realm-1"
    assert output["receipt"]["selected_realm_id"] == "untrusted-realm"


def test_provenance_home_override_reports_resolved_support_root(monkeypatch, tmp_path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.delenv("ASTRID_LOCAL_DATA_ROOT", raising=False)
    monkeypatch.delenv("BANODOCO_LOCAL_DATA_ROOT", raising=False)
    monkeypatch.setenv("ASTRID_LOCAL_HOME", str(home))
    monkeypatch.delenv("BANODOCO_LOCAL_HOME", raising=False)

    output = provenance.identity()

    assert output["support_root"] == str(
        home / "Library" / "Application Support" / "Banodoco"
    )
    assert output["realm_id"] is None


@pytest.mark.parametrize("alias", ["banodoco-local", "astrid-runtime"])
def test_legacy_aliases_emit_deprecation(monkeypatch, capsys, tmp_path, alias: str) -> None:
    monkeypatch.setenv("ASTRID_LOCAL_DATA_ROOT", str(tmp_path / "support"))
    monkeypatch.delenv("BANODOCO_LOCAL_DATA_ROOT", raising=False)
    monkeypatch.setattr(sys, "argv", [alias, "--provenance"])
    assert entrypoint.main() == 0
    assert f"{alias}: deprecated; use astrid-local instead" in capsys.readouterr().err


def test_canonical_environment_wins_when_legacy_is_absent() -> None:
    env = {"ASTRID_LOCAL_DATA_ROOT": "/tmp/astrid-root"}
    resolution = resolve_environment(env)
    assert resolution.values["ASTRID_LOCAL_DATA_ROOT"] == "/tmp/astrid-root"
    assert resolution.warnings == ()


def test_legacy_environment_is_accepted_with_warning() -> None:
    env = {"BANODOCO_LOCAL_DATA_ROOT": "/tmp/legacy-root"}
    resolution = resolve_environment(env)
    assert resolution.values["ASTRID_LOCAL_DATA_ROOT"] == "/tmp/legacy-root"
    assert resolution.warnings == (
        "BANODOCO_LOCAL_DATA_ROOT is deprecated; use ASTRID_LOCAL_DATA_ROOT instead",
    )


def test_conflicting_environment_values_fail_closed() -> None:
    with pytest.raises(EnvironmentMigrationError, match="conflicting environment values"):
        resolve_environment(
            {
                "ASTRID_LOCAL_DATA_ROOT": "/tmp/new-root",
                "BANODOCO_LOCAL_DATA_ROOT": "/tmp/old-root",
            }
        )


def test_relative_roots_fail_closed() -> None:
    with pytest.raises(EnvironmentMigrationError, match="absolute path"):
        resolve_environment({"ASTRID_LOCAL_DATA_ROOT": "relative-root"})


def test_apply_legacy_environment_feeds_existing_cli_without_cwd_adoption() -> None:
    env = {"ASTRID_LOCAL_DATA_ROOT": "/tmp/astrid-root"}
    resolution = apply_legacy_environment(env)
    assert env["BANODOCO_LOCAL_DATA_ROOT"] == "/tmp/astrid-root"
    assert "ASTRID_LOCAL_DATA_ROOT" in resolution.values


def test_runtime_consumers_use_legacy_aliases_and_warn(monkeypatch, capsys, tmp_path) -> None:
    import banodoco_local.compatibility as compatibility

    monkeypatch.delenv("ASTRID_LOCAL_HOME", raising=False)
    monkeypatch.delenv("ASTRID_LOCAL_SOURCE_MANIFEST", raising=False)
    monkeypatch.delenv("ASTRID_LOCAL_DATA_ROOT", raising=False)
    monkeypatch.delenv("ASTRID_RUNTIME_ADMISSION_TIMEOUT_SECONDS", raising=False)
    monkeypatch.setenv("BANODOCO_LOCAL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BANODOCO_LOCAL_SOURCE_MANIFEST", str(tmp_path / "manifest.json"))
    monkeypatch.setenv("BANODOCO_LOCAL_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("BANODOCO_RUNTIME_ADMISSION_TIMEOUT_SECONDS", "7")
    compatibility._EMITTED_WARNINGS.clear()

    args = SimpleNamespace(home=None, data_root=None, source_manifest=None)
    selected = cli._paths(args)
    configured = cli._config(args, selected)
    assert selected.home == (tmp_path / "home").resolve()
    assert selected.app_support == (tmp_path / "data").resolve()
    assert configured.source_manifest == tmp_path / "manifest.json"
    assert runtime_boundary._admission_timeout_from_environment() == 7
    stderr = capsys.readouterr().err
    assert "BANODOCO_LOCAL_HOME is deprecated" in stderr
    assert "BANODOCO_LOCAL_SOURCE_MANIFEST is deprecated" in stderr
    assert "BANODOCO_LOCAL_DATA_ROOT is deprecated" in stderr
    assert "BANODOCO_RUNTIME_ADMISSION_TIMEOUT_SECONDS is deprecated" in stderr


def test_packaging_publishes_one_canonical_local_owner() -> None:
    root = Path(__file__).resolve().parents[1]
    scripts = tomllib.loads((root / "pyproject.toml").read_text())[
        "project"
    ]["scripts"]
    assert scripts["astrid-local"] == "banodoco_local.entrypoint:main"
    assert scripts["banodoco-local"] == scripts["astrid-local"]
    assert scripts["astrid-runtime"] == scripts["astrid-local"]


def test_python_module_alias_uses_canonical_owner() -> None:
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root)
    result = subprocess.run(
        [sys.executable, "-m", "banodoco_local", "--provenance"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    output = json.loads(result.stdout)
    assert output["command_alias"] == "astrid-local"
    assert output["implementation_owner"] == "banodoco_local.cli:main"
