from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.local_worker import LocalWorkerProfile
from runtime_protocol.local_worker_composition import (
    OSProcessInspector,
    load_local_worker_composition,
)


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _profile_document(tmp_path: Path) -> tuple[dict[str, object], Path, Path, Path]:
    source = tmp_path / "astrid"
    packs = source / "astrid" / "packs"
    packs.mkdir(parents=True)
    support = tmp_path / "support"
    support.mkdir()
    boot = support / "boot.json"
    boot.write_text("{}", encoding="utf-8")
    document = {
        "profile_id": "astrid",
        "machine_id": "fixture-machine",
        "worker_environment": sys.prefix,
        "worker_executable": str(Path(sys.executable).resolve()),
        "host_executable": str(Path(sys.executable).resolve()),
        "engine_executable": str(Path(sys.executable).resolve()),
        "engine_listener_executable": str(Path(sys.executable).resolve()),
        "worker_artifact_digest": _digest("1"),
        "host_artifact_digest": _digest("2"),
        "engine_artifact_digest": _digest("3"),
        "engine_listener_artifact_digest": _digest("4"),
        "session_config_digest": _digest("5"),
        "profile_revision": "fixture-r1",
        "profile_digest": _digest("6"),
        "release_digest": _digest("7"),
        "source_checkout": str(source),
        "pack_root": str(packs),
        "boot_manifest_path": str(boot),
        "boot_manifest_hash": _digest("8"),
        "environment": {},
    }
    return document, source, support, packs


def test_factory_derives_runtime_identity_and_roots(tmp_path: Path) -> None:
    document, source, support, _packs = _profile_document(tmp_path)
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    composition = load_local_worker_composition(
        path,
        workspace_uuid="realm-from-runtime",
        realm_root=tmp_path / "runtime-realm",
        support_root=support,
        runtime_instance_id="instance-1",
    )
    profile = composition.profiles["astrid"]
    assert profile.workspace_uuid == "realm-from-runtime"
    assert profile.realm_root == (tmp_path / "runtime-realm").resolve()
    assert profile.support_root == support.resolve()
    assert profile.realm_root != source.resolve()
    composition.bind_runtime(endpoint="http://127.0.0.1:1234", runtime_instance_id="instance-2", credential_file=support / "worker.token")
    assert composition.preparer.config["runtime_endpoint"] == "http://127.0.0.1:1234"
    assert composition.preparer.config["runtime_instance_id"] == "instance-2"


def test_factory_rejects_unknown_authority_fields(tmp_path: Path) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    document["realm_root"] = "/attacker/realm"
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(Exception, match="unsupported fields"):
        load_local_worker_composition(
            path,
            workspace_uuid="realm",
            realm_root=tmp_path / "realm",
            support_root=support,
            runtime_instance_id="instance",
        )


def test_independent_inspector_rejects_worker_birth_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    document, _source, support, _packs = _profile_document(tmp_path)
    path = tmp_path / "worker-profile.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    composition = load_local_worker_composition(
        path,
        workspace_uuid="realm",
        realm_root=tmp_path / "realm",
        support_root=support,
        runtime_instance_id="instance",
    )
    profile = composition.profiles["astrid"]
    inspector = OSProcessInspector(profile)
    pid = os.getpid()
    report = {
        "processes": {
            "worker": {"pid": pid, "birth_id": "worker-claim"},
            "host": {"pid": pid, "birth_id": "host-claim"},
            "engine": {"pid": pid, "birth_id": "engine-claim"},
            "engine_listener": {"pid": pid, "birth_id": "listener-claim"},
        },
        "engine_binding": {"socket_owner_pid": pid},
        "session_config_digest": profile.session_config_digest,
    }
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition.process_birth_identity",
        lambda observed_pid: "independently-observed-birth",
    )
    monkeypatch.setattr(
        "runtime_protocol.local_worker_composition._ps",
        lambda observed_pid, field: str(os.getpid()) if field == "ppid" else str(Path(sys.executable)),
    )
    handle = SimpleNamespace(report_value=report)
    with pytest.raises(ConflictError, match="birth identity"):
        inspector.observe(handle)
