from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from banodoco_local import cli
from runtime_protocol.errors import ConflictError, ValidationError
from runtime_protocol.service import RuntimeService


def test_backup_manifest_metadata_is_canonically_authenticated(tmp_path):
    service = RuntimeService(tmp_path / "realm", display_name="Authenticated")
    try:
        backup = tmp_path / "backup"
        service.backup(backup)
        manifest_path = backup / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        assert manifest["format_version"] == 2
        assert manifest["realm"]["id"] == service.realm["id"]
        assert manifest["schema"]["version"] >= 1
        assert set(manifest["files"]) == {"realm.sqlite3", "cas-manifest.json"}
        manifest["realm"]["display_name"] = "tampered"
        manifest_path.write_text(json.dumps(manifest))
        with pytest.raises(ConflictError, match="authentication"):
            service.restore(backup, tmp_path / "restored")
        assert not (tmp_path / "restored").exists()
    finally:
        service.close()


def test_recovery_requires_realm_version_and_scoped_confirmation_before_mutation(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        before = service.store.realm_lifecycle()
        for body in ({}, {"expected_realm_id": service.realm["id"]}, {"expected_realm_id": "wrong", "expected_version": 1, "noninteractive": True}):
            with pytest.raises((ValidationError, ConflictError)):
                service.recover_realm(body)
            assert service.store.realm_lifecycle() == before
        with pytest.raises(ValidationError):
            service.recover_realm({"expected_realm_id": service.realm["id"], "expected_version": 1, "noninteractive": True, "confirmation": "RECOVER anything"})
        assert service.store.realm_lifecycle() == before
        service.tombstone({"reason": "test"})
        recovered = service.recover_realm({"expected_realm_id": service.realm["id"], "expected_version": 2, "noninteractive": True})
        assert recovered["state"] == "active"
    finally:
        service.close()


def test_up_converts_import_and_client_failures_without_catching_interrupt(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BANODOCO_LOCAL_HOME", str(tmp_path))
    monkeypatch.setattr(cli, "bootstrap", lambda *args, **kwargs: (_ for _ in ()).throw(ImportError("client unavailable")))
    assert cli.main(["up"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output == {"error": "client unavailable", "ok": False}


def test_operator_tools_and_entrypoints_are_present_in_built_wheel(tmp_path):
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    root = Path(__file__).parents[1]
    built = subprocess.run([sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--wheel-dir", str(wheelhouse)], cwd=root, env=os.environ.copy(), capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    wheel = next(wheelhouse.glob("*.whl"))
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True, text=True)
    python = venv / "bin" / "python"
    subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], check=True, capture_output=True, text=True)
    metadata = subprocess.run([str(python), "-c", "import importlib.metadata as m; print(sorted(e.name for e in m.distribution('banodoco-workspace-runtime').entry_points if e.group == 'console_scripts'))"], capture_output=True, text=True)
    assert metadata.returncode == 0 and "banodoco-local" in metadata.stdout and "banodoco-runtime" in metadata.stdout
    for command in (["banodoco-local", "--version"], ["banodoco-local", "rehearse", "--help"], ["banodoco-runtime", "--help"]):
        result = subprocess.run([str(python), "-m", "banodoco_local" if command[0] == "banodoco-local" else "runtime_protocol", *command[1:]], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    imported = subprocess.run([str(python), "-c", "from tools.astrid_migrate import migrate, run_rehearsal; print('ok')"], capture_output=True, text=True)
    assert imported.returncode == 0 and imported.stdout.strip() == "ok", imported.stderr
