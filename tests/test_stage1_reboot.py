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
from banodoco_local.paths import RuntimePaths
from banodoco_local.bootstrap import SourceProfile
from banodoco_local.io import atomic_write_json
from tools.astrid_migrate.migrator import MigrationError
from tools.astrid_migrate.stage1_reboot import (
    ARMED_NAME,
    PLIST_NAME,
    R2_NAME,
    arm_stage1_reboot,
    postboot_stage1_reboot,
    resume_stage1_reboot,
)
from tools.astrid_migrate.operator import _parser


@pytest.fixture(autouse=True)
def _stop_runtime_started_by_postboot(tmp_path: Path):
    """Postboot intentionally leaves the runtime up; stop this test owner."""
    yield
    discovery = tmp_path / "home" / "Library" / "Application Support" / "Banodoco" / "runtime" / "discovery.json"
    try:
        value = json.loads(discovery.read_text(encoding="utf-8"))
        pid = int(value.get("pid", 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pid = 0
    if pid > 0:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
        for _ in range(20):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
    discovery.unlink(missing_ok=True)
    (discovery.parent / "instance.lock").unlink(missing_ok=True)


def _completed_b12(tmp_path: Path, runtime_environment: Path) -> tuple[Path, Path, Path, str]:
    evidence = tmp_path / "evidence"
    home = tmp_path / "home"
    paths = RuntimePaths.current_mac(home)
    active = paths.realms_dir / "stage1-reboot-test"
    support = paths.runtime_support
    evidence.mkdir()
    paths.ensure_support_dirs()
    realm_id = "stage1-reboot-test"
    runtime = RuntimeService(active, realm_id=realm_id, support_root=support)
    runtime.close()
    manifest = {
        "profile": "astrid",
        "runtime_checkout": str(Path(__file__).resolve().parents[1]),
        "source_checkout": str(Path(__file__).resolve().parents[1]),
        "runtime_environment": str(runtime_environment),
    }
    manifest = SourceProfile.from_mapping(manifest).as_dict()
    catalog = {"version": 1, "realms": [{"realm_id": realm_id, "display_name": "Stage 1 reboot test", "data_root": str(active.resolve()), "source_profile": "astrid"}], "selected_realm_id": realm_id, "source_profiles": {"astrid": SourceProfile.from_mapping(manifest).as_dict()}}
    atomic_write_json(support / "catalog.json", catalog)
    (support / "activation-trust.json").write_text(json.dumps({"version": 1, "key_hex": "a" * 64}), encoding="utf-8")
    (support / "activation-trust.json").chmod(0o600)
    source_manifest = paths.source_profiles_dir / "astrid.json"
    atomic_write_json(source_manifest, manifest)
    source_manifest.chmod(0o600)
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
        neutral_home=evidence.parent / "home",
        source_manifest=evidence.parent / "home" / "Library" / "Application Support" / "Banodoco" / "runtime" / "source-profiles" / "astrid.json",
        **kwargs,
    )


def test_stage1_reboot_commands_are_explicitly_named() -> None:
    parser = _parser()
    arm = parser.parse_args(["stage1-reboot-arm", "--evidence-root", "/e", "--active-root", "/a", "--support-root", "/s", "--realm-id", "r"])
    resume = parser.parse_args(["stage1-reboot-resume", "--evidence-root", "/e", "--active-root", "/a", "--support-root", "/s", "--realm-id", "r"])
    postboot = parser.parse_args(["stage1-reboot-postboot", "--evidence-root", "/e", "--active-root", "/a", "--support-root", "/s", "--realm-id", "r", "--neutral-home", "/h", "--source-manifest", "/m"])
    assert arm.command == "stage1-reboot-arm"
    assert resume.command == "stage1-reboot-resume"
    assert resume.wait_seconds == 0
    assert resume.poll_seconds == 5
    assert postboot.command == "stage1-reboot-postboot"


def test_stage1_reboot_arm_then_resume_is_one_shot(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path, stage1_runtime_environment)
    armed = _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")

    assert armed["packet"] == "B12.R1"
    assert armed["state"] == "armed"
    assert (evidence / ARMED_NAME).stat().st_mode & 0o777 == 0o600
    launchd = plistlib.loads((evidence / PLIST_NAME).read_bytes())
    assert launchd["RunAtLoad"] is True
    assert launchd["KeepAlive"] is False
    assert launchd["WorkingDirectory"] == str(Path(__file__).resolve().parents[1])
    assert launchd["ProgramArguments"][3] == "stage1-reboot-postboot"
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

    launch_result = subprocess.run(plistlib.loads(stable_plist.read_bytes())["ProgramArguments"], cwd=launchd["WorkingDirectory"], capture_output=True, text=True, check=True)
    r2 = json.loads(launch_result.stdout)
    assert r2["packet"] == "B12.R2"
    assert r2["state"] == "completed"
    assert r2["boot_identity_before"] == "boot-before"
    assert r2["boot_identity_after"] != "boot-before"
    assert r2["runtime_epoch_after"] > r2["runtime_epoch_before"]
    assert r2["realm_id"] == realm_id
    assert r2["terminal_support_root"] == str(support)
    assert r2["runtime_bootstrap"]["status"] in {"started", "reconnected", "restarted"}
    assert (evidence / R2_NAME).is_file()
    assert r2["launch_agent_cleanup"] == {
        "status": "plist_removed_external_bootout_verification_required",
        "path": str(stable_plist),
        "label": armed["launch_agent_label"],
        "command": ["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{armed['launch_agent_label']}"],
    }
    assert not stable_plist.exists()

    # LaunchAgent retries and manual recovery return the durable receipt.
    assert resume_stage1_reboot(evidence, active, support, realm_id, boot_identity_provider=lambda: "later") == r2


def test_stage1_reboot_requires_terminal_b12_and_changed_os_boot(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path, stage1_runtime_environment)
    journal = evidence / "migration-journal-b12.json"
    journal.write_text(json.dumps({"format_version": 1, "generation": 0, "state": "active", "entries": [], "effects": []}), encoding="utf-8")
    with pytest.raises(MigrationError, match="terminal B12 journal"):
        _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")

    journal.write_text(json.dumps({"format_version": 1, "generation": 0, "state": "reactivated", "entries": [], "effects": []}), encoding="utf-8")
    _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")
    with pytest.raises(MigrationError, match="changed host boot identity"):
        resume_stage1_reboot(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")


def test_stage1_postboot_rejects_same_boot_before_start_or_cleanup(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path, stage1_runtime_environment)
    armed = _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")
    stable_plist = Path(armed["launch_agent_path"])

    with pytest.raises(MigrationError, match="changed host boot identity"):
        postboot_stage1_reboot(
            evidence,
            active,
            support,
            realm_id,
            neutral_home=tmp_path / "home",
            source_manifest=tmp_path / "home" / "Library" / "Application Support" / "Banodoco" / "runtime" / "source-profiles" / "astrid.json",
            boot_identity_provider=lambda: "boot-before",
        )

    assert stable_plist.is_file()
    assert not (evidence / R2_NAME).exists()
    assert not (tmp_path / "home" / "Library" / "Application Support" / "Banodoco" / "runtime" / "discovery.json").exists()


def test_stage1_reboot_rejects_changed_pinned_evidence_and_realm_binding(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path, stage1_runtime_environment)
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


def test_stage1_launchagent_waits_for_delayed_runtime_from_clean_environment(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path, stage1_runtime_environment)
    _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")
    launchd = plistlib.loads((evidence / PLIST_NAME).read_bytes())
    child = subprocess.Popen(launchd["ProgramArguments"], cwd=launchd["WorkingDirectory"], env={"PATH": os.environ.get("PATH", "")}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = child.communicate(timeout=10)
    assert child.returncode == 0, stderr
    result = json.loads(stdout)
    assert result["state"] == "completed"
    assert result["realm_id"] == realm_id
    assert result["runtime_bootstrap"]["status"] == "started"
    assert result["runtime_epoch_after"] > result["runtime_epoch_before"]
    assert not Path(json.loads((evidence / ARMED_NAME).read_text())["launch_agent_path"]).exists()


def test_stage1_postboot_replays_after_durable_plist_removal(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    evidence, active, support, realm_id = _completed_b12(tmp_path, stage1_runtime_environment)
    armed = _arm(evidence, active, support, realm_id, boot_identity_provider=lambda: "boot-before")
    # Model a process crash after the installed plist was durably removed but
    # before R2/marker finalization.  The evidence copy and R1 hash make this
    # replay unambiguous and the real neutral bootstrap still runs first.
    Path(armed["launch_agent_path"]).unlink()
    result = postboot_stage1_reboot(
        evidence,
        active,
        support,
        realm_id,
        neutral_home=tmp_path / "home",
        source_manifest=tmp_path / "home" / "Library" / "Application Support" / "Banodoco" / "runtime" / "source-profiles" / "astrid.json",
        wait_seconds=10,
        poll_seconds=1,
    )
    assert result["state"] == "completed"
    assert result["runtime_bootstrap"]["status"] == "started"
    assert result["launch_agent_cleanup"]["status"] == "plist_removed_external_bootout_verification_required"
