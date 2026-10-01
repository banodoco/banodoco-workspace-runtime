from __future__ import annotations

import json
import io
from pathlib import Path
import urllib.error

from banodoco_local import cli
from banodoco_local.paths import RuntimePaths


class _TypedClient:
    def __init__(self):
        self.calls = []

    def checkpoint_attempt(self, *args, **kwargs):
        self.calls.append(("checkpoint", args, kwargs))
        return {"state": "durable", "nonce": kwargs["nonce"]}

    def request_reboot(self, **kwargs):
        self.calls.append(("reboot", (), kwargs))
        return {"status": "requested", **kwargs}

    def resume_attempt(self, **kwargs):
        self.calls.append(("resume", (), kwargs))
        return {"status": "resumed", **kwargs}

    def recover_realm(self, **kwargs):
        self.calls.append(("recover", (), kwargs))
        return {"state": "active", **kwargs}


def test_parser_exposes_operator_lifecycle_without_legacy_verbs():
    required = {
        "backup": ["--destination", "b"],
        "restore": ["backup", "--destination", "d"],
        "checkpoint": ["--attempt-id", "a", "--lease-id", "l", "--fence", "1", "--runtime-epoch", "1", "--nonce", "n", "--authorization", "n"],
        "prepare-reboot": ["--attempt-id", "a", "--lease-id", "l", "--fence", "1", "--runtime-epoch", "1"],
        "reboot": ["--checkpoint-id", "c", "--nonce", "n", "--authorization", "n", "--runtime-epoch", "1"],
        "resume": ["--checkpoint-id", "c", "--nonce", "n", "--authorization", "n", "--runtime-epoch", "1"],
        "recovery": [],
    }
    for command in ("up", "connect", "status", "restart", "backup", "restore", "checkpoint", "prepare-reboot", "reboot", "resume", "doctor", "recovery"):
        assert cli.parser().parse_args([command, *required.get(command, []), "--json"]).command == command
    upgrade = cli.parser().parse_args(["upgrade", "--profile", "astrid", "--data-root", "/tmp/astrid", "--json"])
    assert upgrade.command == "upgrade"
    assert upgrade.data_root == Path("/tmp/astrid")


def test_checkpoint_requires_and_forwards_exact_epoch_nonce_and_state(monkeypatch, tmp_path, capsys):
    paths = RuntimePaths.sandbox(tmp_path)
    fake = _TypedClient()
    monkeypatch.setattr(cli, "_client", lambda _paths: fake)
    assert cli.main([
        "checkpoint", "--home", str(tmp_path), "--attempt-id", "a", "--lease-id", "l",
        "--fence", "3", "--runtime-epoch", "7", "--nonce", "n", "--authorization", "n",
        "--state", '{"step": 4}', "--json",
    ]) == 0
    assert fake.calls == [("checkpoint", ("a",), {"lease_id": "l", "fence": 3, "nonce": "n", "authorization": "n", "state": {"step": 4}, "runtime_epoch": 7})]
    assert json.loads(capsys.readouterr().out)["state"] == "durable"


def test_reboot_is_safe_disabled_and_resume_is_typed(monkeypatch, tmp_path, capsys):
    fake = _TypedClient()
    monkeypatch.setattr(cli, "_client", lambda _paths: fake)
    reboot_args = ["reboot", "--home", str(tmp_path), "--checkpoint-id", "c", "--nonce", "n", "--authorization", "n", "--runtime-epoch", "7", "--json"]
    assert cli.main(reboot_args) == 1
    assert "safe-disabled" in capsys.readouterr().out
    resume_args = ["resume", "--home", str(tmp_path), "--checkpoint-id", "c", "--nonce", "n", "--authorization", "n", "--runtime-epoch", "7", "--json"]
    assert cli.main(resume_args) == 0
    assert fake.calls[-1][0] == "resume"


def test_start_worker_preserves_only_bounded_worker_rejection_diagnostic(monkeypatch, tmp_path, capsys):
    paths = RuntimePaths.sandbox(tmp_path)
    monkeypatch.setattr(cli, "_validate_support_paths", lambda _paths: None)
    monkeypatch.setattr(cli, "_read_support_json", lambda _path: {"endpoint": "http://127.0.0.1:4123"})
    monkeypatch.setattr(cli, "_credential", lambda _paths: "not-retained")
    detail = {
        "code": "conflict",
        "message": "prepared Worker rejected the operation",
        "details": {
            "handoff_error_code": "worker_configuration",
            "handoff_stage": "prepare",
            "secret": "must-not-cross-the-cli-boundary",
        },
    }
    error = urllib.error.HTTPError(
        "http://127.0.0.1:4123/v1/control/local-worker/start",
        409,
        "Conflict",
        {},
        io.BytesIO(json.dumps(detail).encode()),
    )
    monkeypatch.setattr(cli.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(error))
    monkeypatch.setattr(cli, "_paths", lambda _args: paths)

    assert cli.main([
        "start-worker", "--data-root", str(tmp_path), "--profile", "astrid",
        "--expected-workspace-uuid", "workspace", "--json",
    ]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "ok": False,
        "error": "prepared Worker rejected the operation",
        "error_code": "worker_configuration",
        "error_stage": "prepare",
        "operation": "start-worker",
    }


def test_start_worker_rejection_diagnostic_fails_closed_on_unbounded_values():
    error = cli._LocalWorkerStartError(
        "prepared Worker rejected the operation",
        error_code="secret: value",
        error_stage="prepare\nsecret",
    )
    assert error.error_code == "worker_rejected"
    assert error.error_stage == "worker_control"
