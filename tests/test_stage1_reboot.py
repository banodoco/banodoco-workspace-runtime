from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import time
import sqlite3

import pytest

from runtime_protocol.service import RuntimeService
from tools.astrid_migrate.migrator import MigrationError
from tools.astrid_migrate.stage1_reboot import (
    ARMED_NAME,
    PLIST_NAME,
    R2_NAME,
    arm_stage1_reboot,
    resume_stage1_reboot,
)
from tools.astrid_migrate.operator import _parser


def _completed_b12(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    evidence = tmp_path / "evidence"
    active = tmp_path / "active"
    support = tmp_path / "support"
    evidence.mkdir()
    support.mkdir()
    realm_id = "stage1-reboot-test"
    runtime = RuntimeService(active, realm_id=realm_id, support_root=support)
    runtime.close()
    catalog = {"format_version": 1, "realms": [{"realm_id": realm_id, "display_name": "Stage 1 reboot test", "data_root": str(active.resolve())}], "selected_realm_id": realm_id}
    (support / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
    (evidence / "migration-journal-b12.json").write_text(
        json.dumps({"format_version": 1, "generation": 0, "state": "reactivated", "entries": [], "effects": []}),
        encoding="utf-8",
    )
    (evidence / "activated-destination-b12.json").write_text(
        json.dumps({"packet": "B12.4", "realm_id": realm_id, "destination_root": str(active.resolve()), "runtime_epoch": 1, "catalog_identity": {"status": "ready", "sha256": hashlib.sha256((support / "catalog.json").read_bytes()).hexdigest(), "selected_realm_id": realm_id, "data_root": str(active.resolve())}}),
        encoding="utf-8",
    )
    return evidence, active, support, realm_id


def _arm(evidence: Path, active: Path, support: Path, realm_id: str, **kwargs):
    return arm_stage1_reboot(
        evidence,
        active,
        support,
        realm_id,
        launch_agents_dir=evidence.parent / "launch-agents",
        **kwargs,
    )


def test_stage1_reboot_commands_are_explicitly_named() -> None:
    parser = _parser()
    arm = parser.parse_args(["stage1-reboot-arm", "--evidence-root", "/e", "--active-root", "/a", "--support-root", "/s", "--realm-id", "r"])
    resume = parser.parse_args(["stage1-reboot-resume", "--evidence-root", "/e", "--active-root", "/a", "--support-root", "/s", "--realm-id", "r"])
    assert arm.command == "stage1-reboot-arm"
    assert resume.command == "stage1-reboot-resume"
    assert resume.wait_seconds == 0
    assert resume.poll_seconds == 5


def test_stage1_reboot_arm_then_resume_is_one_shot(tmp_path: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path)
    armed = _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before", python_executable=sys.executable)

    assert armed["packet"] == "B12.R1"
    assert armed["state"] == "armed"
    assert (evidence / ARMED_NAME).stat().st_mode & 0o777 == 0o600
    launchd = plistlib.loads((evidence / PLIST_NAME).read_bytes())
    assert launchd["RunAtLoad"] is True
    assert launchd["KeepAlive"] is False
    assert launchd["WorkingDirectory"] == str(Path(__file__).resolve().parents[1])
    assert launchd["ProgramArguments"][3] == "stage1-reboot-resume"
    assert launchd["ProgramArguments"][-4:] == ["--wait-seconds", "120", "--poll-seconds", "1"]
    stable_plist = Path(armed["launch_agent_path"])
    assert stable_plist.parent == tmp_path / "launch-agents"
    assert stable_plist.is_file()
    assert stable_plist.stat().st_mode & 0o777 == 0o600
    assert armed["launch_agent_sha256"] == hashlib.sha256(stable_plist.read_bytes()).hexdigest()

    # A second arm is a harmless replay of the same explicit checkpoint.
    assert _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "different") == armed

    with pytest.raises(MigrationError, match="cold-launched runtime epoch"):
        resume_stage1_reboot(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-after")

    # RuntimeService's normal startup is the existing cold-launch boundary.
    restarted = RuntimeService(active, realm_id=realm_id, support_root=support)
    restarted.close()
    launch_result = subprocess.run(plistlib.loads(stable_plist.read_bytes())["ProgramArguments"], cwd=launchd["WorkingDirectory"], capture_output=True, text=True, check=True)
    r2 = json.loads(launch_result.stdout)
    assert r2["packet"] == "B12.R2"
    assert r2["state"] == "completed"
    assert r2["boot_identity_before"] == "boot-before"
    assert r2["boot_identity_after"] != "boot-before"
    assert r2["runtime_epoch_after"] > r2["runtime_epoch_before"]
    assert (evidence / R2_NAME).is_file()
    assert r2["launch_agent_cleanup"] == {
        "status": "pending_bootout_and_remove",
        "path": str(stable_plist),
        "label": armed["launch_agent_label"],
    }
    assert stable_plist.is_file()

    # LaunchAgent retries and manual recovery return the durable receipt.
    stable_plist.unlink()
    assert resume_stage1_reboot(evidence, active, support, realm_id, boot_identity_provider=lambda: "later") == r2


def test_stage1_reboot_requires_terminal_b12_and_changed_os_boot(tmp_path: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path)
    journal = evidence / "migration-journal-b12.json"
    journal.write_text(json.dumps({"format_version": 1, "generation": 0, "state": "active", "entries": [], "effects": []}), encoding="utf-8")
    with pytest.raises(MigrationError, match="terminal B12 journal"):
        _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")

    journal.write_text(json.dumps({"format_version": 1, "generation": 0, "state": "reactivated", "entries": [], "effects": []}), encoding="utf-8")
    _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")
    with pytest.raises(MigrationError, match="changed host boot identity"):
        resume_stage1_reboot(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")


def test_stage1_reboot_rejects_changed_pinned_evidence_and_realm_binding(tmp_path: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path)
    original_journal = (evidence / "migration-journal-b12.json").read_bytes()
    _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")
    (evidence / "migration-journal-b12.json").write_bytes(original_journal + b" ")
    with pytest.raises(MigrationError, match="R1-pinned B12 evidence changed"):
        resume_stage1_reboot(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-after")

    (evidence / "migration-journal-b12.json").write_bytes(original_journal)
    connection = sqlite3.connect(active / "realm.sqlite3")
    try:
        connection.execute("UPDATE realm SET id=?", ("swapped-realm",))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(MigrationError, match="active realm identity"):
        resume_stage1_reboot(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-after")


def test_stage1_launchagent_waits_for_delayed_runtime_from_clean_environment(tmp_path: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path)
    _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before", python_executable=sys.executable)
    launchd = plistlib.loads((evidence / PLIST_NAME).read_bytes())
    child = subprocess.Popen(launchd["ProgramArguments"], cwd=launchd["WorkingDirectory"], env={"PATH": os.environ.get("PATH", "")}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.2)
    restarted = RuntimeService(active, realm_id=realm_id, support_root=support)
    restarted.close()
    stdout, stderr = child.communicate(timeout=10)
    assert child.returncode == 0, stderr
    assert json.loads(stdout)["state"] == "completed"
