from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import ApiError, WorkspaceClient


def test_generated_client_smoke_and_scoped_handshake() -> None:
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, body))
        if path == "/v1/health":
            return 200, {}, json.dumps({"status": "ok", "protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "runtime_epoch": 1}).encode()
        if path == "/v1/handshake":
            return 200, {}, json.dumps({"protocol": "workspace.v1", "schema_digest": "sha256:" + "a" * 64, "session_id": "session-1", "actor_id": "actor-1", "realm_id": "realm-1", "scopes": ["realm:read", "project:write"]}).encode()
        if path == "/v1/projects" and method == "POST":
            return 201, {}, json.dumps({"project_id": "project-1", "realm_id": "realm-1", "name": "Neutral", "version": 1, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}).encode()
        raise AssertionError((method, path))

    client = WorkspaceClient("http://runtime", "token", transport=transport)
    assert client.health()["protocol"] == "workspace.v1"
    session = client.handshake("second-product", "0.1.0", ["realm:read", "project:write"])
    assert session.realm_id == "realm-1"
    project = client.create_project("Neutral", idempotency_key="create-1")
    assert project.project_id == "project-1"
    assert calls[-1][2]["Authorization"] == "Bearer token"
    assert calls[-1][2]["Idempotency-Key"] == "create-1"


def test_object_byte_range_etag_and_head_are_preserved() -> None:
    payload = b"0123456789"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers))
        assert headers["Range"] == "bytes=2-5"
        result = {"ETag": f'"{digest}"', "Content-Range": "bytes 2-5/10", "Accept-Ranges": "bytes"}
        return 206, result, payload[2:6] if method == "GET" else b""

    client = WorkspaceClient("http://runtime", transport=transport)
    result = client.get_object("obj-1", byte_range=(2, 5))
    assert result.status == 206 and result.data == b"2345"
    assert result.etag == f'"{digest}"' and result.content_range == "bytes 2-5/10"
    head = client.head_object("obj-1", byte_range=(2, 5))
    assert head.status == 206 and calls[-1][0] == "HEAD"


def test_invalid_range_is_rejected_before_transport() -> None:
    client = WorkspaceClient("http://runtime", transport=lambda *args: (_ for _ in ()).throw(AssertionError("called")))
    try:
        client.get_object("obj", byte_range=(5, 2))
    except ValueError as exc:
        assert "range" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_api_error_preserves_conflict_and_version_details() -> None:
    def transport(*args):
        return 409, {}, json.dumps({"code": "version_conflict", "message": "stale", "request_id": "req-1", "details": {"expected": 2, "actual": 3}}).encode()

    try:
        WorkspaceClient("http://runtime", transport=transport).get_project("p")
    except ApiError as exc:
        assert exc.status == 409 and exc.code == "version_conflict" and exc.details["actual"] == 3
    else:
        raise AssertionError("expected ApiError")


def test_generator_is_reproducible() -> None:
    root = Path(__file__).parents[1]
    subprocess.run([sys.executable, str(root / "generators" / "generate.py")], check=True, cwd=root)
    subprocess.run([sys.executable, str(root / "generators" / "generate.py"), "--check"], check=True, cwd=root)
