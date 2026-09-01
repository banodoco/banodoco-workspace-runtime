from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from runtime_protocol.daemon import RuntimeDaemon


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "conformance" / "second-client-core-v1.yaml"
CLIENT = ROOT / "packages" / "typescript"
ACTOR = ROOT / "conformance" / "dist" / "conformance" / "fake-second-product.js"


@pytest.fixture()
def daemon(tmp_path: Path):
    instance = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support", production_worker_credentials=True).start()
    try:
        yield instance
    finally:
        instance.stop()


def _build_actor() -> None:
    """Install and compile the checked-in client, without ambient module paths."""
    subprocess.run(
        ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=CLIENT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        ["npm", "run", "build"],
        cwd=CLIENT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        [str(CLIENT / "node_modules" / ".bin" / "tsc"), "-p", str(ROOT / "conformance" / "tsconfig.json")],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert ACTOR.is_file(), f"TypeScript actor was not emitted at {ACTOR}"


def test_second_client_core_journey_is_executable(daemon: RuntimeDaemon) -> None:
    _build_actor()
    fixture = yaml.safe_load(FIXTURE.read_text())
    assert fixture["fixture"] == "second-client-core-v1"
    assert fixture["protocol"] == "workspace.v1"
    expected_steps = [step["id"] for step in fixture["steps"]]

    # The actor receives the scoped credential explicitly, as a real client would;
    # no product-specific or ambient token injection is permitted for this journey.
    env = os.environ.copy()
    env.pop("BANODOCO_RUNTIME_OWNER_TOKEN", None)
    env.pop("BANODOCO_LOCAL_OWNER_TOKEN", None)
    completed = subprocess.run(
        ["node", str(ACTOR), "--endpoint", daemon.endpoint, "--token", daemon.token, "--worker-token", daemon.worker_token],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert result["product"] == fixture["actor"]["product_name"]
    assert result["realm_id"]
    assert result["steps"] == expected_steps
    assert result["project_id"] and result["object_id"] and result["task_id"]
