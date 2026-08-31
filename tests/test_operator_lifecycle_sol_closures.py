from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from banodoco_local.bootstrap import BootstrapConfig, BootstrapError, SourceProfile, doctor, restart
from banodoco_local.paths import RuntimePaths
from banodoco_local.runtime_boundary import LocalRuntimeBoundary
from runtime_protocol.backup import verify_backup
from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService


def test_backup_tamper_with_recomputed_public_digest_still_requires_private_mac(tmp_path):
    service = RuntimeService(tmp_path / "realm")
    try:
        backup = tmp_path / "backup"
        service.backup(backup)
        path = backup / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["realm"]["display_name"] = "forged"
        payload = {key: value for key, value in manifest.items() if key not in {"manifest_sha256", "manifest_hmac"}}
        manifest["manifest_sha256"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        path.write_text(json.dumps(manifest))
        with pytest.raises(ConflictError, match="authentication"):
            verify_backup(backup)
    finally:
        service.close()


class _ForgedDiscoveryBoundary:
    def __init__(self, pid: int):
        self.pid = pid
        self.restart_calls = 0

    def is_pid_alive(self, pid):
        return int(pid) == self.pid

    def validate_owner(self, **_kwargs):
        return True

    def restart(self, **_kwargs):
        self.restart_calls += 1
        raise AssertionError("forged discovery reached the signal boundary")


def test_forged_current_pid_discovery_cannot_cross_lock_fence(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    pid = os.getpid()
    paths.discovery_path.write_text(json.dumps({
        "pid": pid,
        "process_birth_id": "forged-birth",
        "runtime_instance_id": "forged-instance",
        "endpoint": "http://127.0.0.1:1",
        "active_realm": "realm",
    }))
    paths.instance_lock_path.write_text(json.dumps({
        "pid": pid,
        "process_birth_id": "forged-birth",
        "runtime_instance_id": "different-owner",
        "realm_id": "realm",
    }))
    boundary = _ForgedDiscoveryBoundary(pid)
    with pytest.raises(BootstrapError, match="owner lock"):
        restart(paths, boundary, BootstrapConfig(source_profile=SourceProfile("astrid", "/runtime", "/source")))
    assert boundary.restart_calls == 0


def test_doctor_marks_dead_discovery_owner_unhealthy_and_nonzero_state(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    paths.catalog_path.write_text(json.dumps({"version": 1, "selected_realm_id": None, "realms": []}))
    paths.discovery_path.write_text(json.dumps({
        "pid": 2147483647,
        "process_birth_id": "dead",
        "runtime_instance_id": "dead-instance",
        "endpoint": "http://127.0.0.1:1",
        "active_realm": "dead-realm",
    }))
    report = doctor(paths)
    assert report["healthy"] is False
    assert "stale_discovery" in report["issues"]


def test_real_boundary_restart_rechecks_identity_before_signal(tmp_path, monkeypatch):
    boundary = LocalRuntimeBoundary()
    # No process handle/adopted owner means the boundary refuses before any
    # killpg call, even if a caller supplies a plausible current PID.
    monkeypatch.setattr(boundary, "_http_health", lambda _endpoint: True)
    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    pid = os.getpid()
    birth = boundary.process_birth_identity(pid)
    paths.discovery_path.write_text(json.dumps({"pid": pid, "process_birth_id": birth, "runtime_instance_id": "x", "endpoint": "http://127.0.0.1:1", "active_realm": "r"}))
    paths.instance_lock_path.write_text(json.dumps({"pid": pid, "process_birth_id": birth, "runtime_instance_id": "x", "realm_id": "r"}))
    boundary.prepare_restart(source_profile=SourceProfile("astrid", str(tmp_path), str(tmp_path)), realm_id="r", realm_root=tmp_path / "realm", support_root=paths.runtime_support, pid=pid)
    with pytest.raises(BootstrapError, match="current operator process|process-group leader|owned process handle"):
        boundary.restart(endpoint="http://127.0.0.1:1", pid=pid, process_birth_id=birth, instance_id="x", realm_id="r", owner_lock=paths.instance_lock_path, discovery_path=paths.discovery_path)
