from __future__ import annotations

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))

from banodoco_local import BootstrapConfig, LocalRuntimeBoundary, RuntimePaths, SourceProfile, bootstrap
from banodoco_local.bootstrap import restart
from banodoco_workspace_client import WorkspaceClient


def _config() -> BootstrapConfig:
    checkout = Path(__file__).parents[1].resolve()
    profile = SourceProfile(profile="astrid", runtime_checkout=str(checkout), source_checkout=str(checkout))
    return BootstrapConfig(source_profile=profile)


def test_real_subprocess_fresh_launch_reconnect_and_scoped_generated_client(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    boundary = LocalRuntimeBoundary()
    try:
        first = bootstrap(paths, boundary, _config())
        discovery = json.loads(paths.discovery_path.read_text())
        assert first.status == "started"
        assert discovery["protocol_version"] == "workspace-v1"
        assert discovery["schema_version"] == "workspace-schema-v1"
        assert discovery["active_realm"] == first.realm_id
        assert discovery["runtime_instance_id"]
        assert "token" not in json.dumps(discovery)

        credential = json.loads((paths.credentials_dir / "astrid.json").read_text())
        client = WorkspaceClient(first.endpoint, credential["token"])
        assert client.health()["protocol"] == "workspace-v1"
        assert client.get_realm().realm_id == first.realm_id
        project = client.create_project("real-bootstrap", idempotency_key="real-bootstrap-project")

        second = bootstrap(paths, LocalRuntimeBoundary(), _config())
        assert second.status == "reconnected"
        assert second.realm_id == first.realm_id
        assert client.get_project(project.project_id).name == "real-bootstrap"
    finally:
        boundary.stop()


def test_real_subprocess_restart_preserves_realm_and_credential(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    boundary = LocalRuntimeBoundary()
    try:
        first = bootstrap(paths, boundary, _config())
        token_before = json.loads((paths.credentials_dir / "astrid.json").read_text())["token"]
        result = restart(paths, boundary, _config())
        assert result.status == "restarted"
        assert result.realm_id == first.realm_id
        token_after = json.loads((paths.credentials_dir / "astrid.json").read_text())["token"]
        assert token_after == token_before
        assert WorkspaceClient(result.endpoint, token_after).get_realm().realm_id == first.realm_id
    finally:
        boundary.stop()


def test_real_subprocess_stale_discovery_recovers_without_new_realm(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    boundary = LocalRuntimeBoundary()
    try:
        first = bootstrap(paths, boundary, _config())
        assert boundary._process is not None
        os.kill(boundary._process.pid, 9)
        boundary._process.wait(timeout=3)
        recovered = bootstrap(paths, boundary, _config())
        assert recovered.status == "started"
        assert recovered.realm_id == first.realm_id
    finally:
        boundary.stop()
