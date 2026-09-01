"""One-shot Stage 1 reboot continuity checkpoint for a completed B12 run.

This is deliberately not a migration runner or a daemon.  ``arm`` records a
read-only R1 checkpoint after B12 is terminal; ``resume`` is intended to be
called once by a user LaunchAgent after boot and records R2.  The durable JSON
marker is the source of truth, so a lost postboot process can be run again
without re-running migration or rebooting the host.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import subprocess
import sys
import time
from typing import Any, Callable, Mapping

from .boundary import atomic_json_write, capture_parent, close_pinned, write_bytes_at
from .migrator import MigrationError


ARMED_NAME = "stage1-b12-reboot.json"
R2_NAME = "stage1-b12-reboot-r2.json"
PLIST_NAME = "stage1-b12-reboot-resume.plist"


def _absolute(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise MigrationError(f"{label} must be an absolute path")
    path = Path(os.path.abspath(os.fspath(path)))
    if any(part.is_symlink() for part in _existing_parts(path)):
        raise MigrationError(f"{label} contains a symlink component: {path}")
    return path


def _existing_parts(path: Path):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() or current.is_symlink():
            yield current


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise MigrationError(f"{label} is missing or not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise MigrationError(f"{label} is not valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise MigrationError(f"{label} must contain an object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise MigrationError(f"cannot hash Stage 1 artifact: {path}") from exc
    return digest.hexdigest()


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise MigrationError(f"refusing to replace existing Stage 1 artifact: {path}")
    identity = capture_parent(path, require_fresh_target=True)
    try:
        atomic_json_write(path, dict(value), identity=identity)
    finally:
        close_pinned(identity)
    path.chmod(0o600)


def _replace_json(path: Path, value: Mapping[str, Any]) -> None:
    """Atomically replace one already-owned marker without a missing window."""
    temporary = path.with_name(f".{path.name}.{os.getpid()}.next")
    if temporary.exists() or temporary.is_symlink():
        raise MigrationError(f"stale Stage 1 marker replacement exists: {temporary}")
    identity = capture_parent(temporary, require_fresh_target=True)
    try:
        atomic_json_write(temporary, dict(value), identity=identity)
    finally:
        close_pinned(identity)
    temporary.chmod(0o600)
    identity = capture_parent(path)
    try:
        parent_fd = int(identity["_parent_fd"])
        os.replace(temporary.name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        close_pinned(identity)
    path.chmod(0o600)


def _write_bytes(path: Path, value: bytes) -> None:
    if path.exists() or path.is_symlink():
        if path.is_file() and not path.is_symlink() and path.read_bytes() == value:
            return
        raise MigrationError(f"refusing to replace existing Stage 1 artifact: {path}")
    identity = capture_parent(path, require_fresh_target=True)
    try:
        write_bytes_at(int(identity["_parent_fd"]), path.name, value)
    finally:
        close_pinned(identity)
    path.chmod(0o600)


def _runtime_state(active: Path) -> dict[str, Any]:
    database = active / "realm.sqlite3"
    if not database.is_file() or database.is_symlink():
        raise MigrationError(f"Stage 1 active realm database is missing: {database}")
    # Read-only URI avoids opening RuntimeService, whose normal constructor
    # advances the runtime epoch.  R1 must describe the pre-reboot state.
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT runtime_epoch, boot_id FROM runtime_lifecycle WHERE id=1").fetchone()
        realms = connection.execute("SELECT id FROM realm").fetchall()
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    except (OSError, sqlite3.DatabaseError) as exc:
        raise MigrationError(f"Stage 1 active realm cannot be read safely: {database}") from exc
    finally:
        try:
            connection.close()
        except UnboundLocalError:
            pass
    if row is None or len(realms) != 1:
        raise MigrationError("Stage 1 active realm failed read-only integrity checks")
    return {
        "runtime_epoch": int(row["runtime_epoch"]),
        "runtime_boot_id": str(row["boot_id"]),
        "realm_id": str(realms[0]["id"]),
        "quick_check": quick_check,
        "foreign_key_errors": len(foreign_keys),
    }


def _host_boot_identity() -> str:
    """Return the stable OS boot marker used by the postboot LaunchAgent."""
    marker = Path("/proc/sys/kernel/random/boot_id")
    try:
        value = marker.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    if value:
        return f"linux-boot:{value}"
    try:
        result = subprocess.run(
            ["sysctl", "-n", "kern.boottime"],
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        )
        value = result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        value = ""
    if value:
        return f"darwin-boot:{value}"
    raise MigrationError("Stage 1 cannot establish an OS boot identity")


def _verified_executable(value: str | None) -> str:
    executable = Path(value or sys.executable).expanduser()
    if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise MigrationError(f"LaunchAgent interpreter is not an executable absolute path: {executable}")
    return str(executable)


def _launch_agents_dir(value: str | Path | None, *, create: bool) -> Path:
    path = _absolute(value or (Path.home() / "Library" / "LaunchAgents"), "user LaunchAgents directory")
    if path.exists():
        if not path.is_dir() or path.is_symlink():
            raise MigrationError(f"user LaunchAgents directory is not a regular directory: {path}")
        return path
    if not create:
        raise MigrationError(f"user LaunchAgents directory is missing: {path}")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as exc:
        raise MigrationError(f"cannot create user LaunchAgents directory: {path}") from exc
    path.chmod(0o700)
    return path


def _launch_agent_label(payload: Mapping[str, Any]) -> str:
    return f"com.banodoco.stage1.b12.reboot.{payload['checkpoint_id']}"


def _verify_launch_agent(marker: Mapping[str, Any], evidence: Path) -> Path:
    evidence_plist = evidence / PLIST_NAME
    stable_value = marker.get("launch_agent_path")
    launch_agents_value = marker.get("launch_agents_dir")
    expected_hash = marker.get("launch_agent_sha256")
    label = marker.get("launch_agent_label")
    if not all(isinstance(value, str) and value for value in (stable_value, launch_agents_value, expected_hash, label)):
        raise MigrationError("Stage 1 reboot marker has no bound LaunchAgent")
    stable = _absolute(stable_value, "bound LaunchAgent")
    launch_agents = _absolute(launch_agents_value, "bound user LaunchAgents directory")
    if stable.parent != launch_agents or stable.name != f"{label}.plist":
        raise MigrationError("Stage 1 LaunchAgent path is not bound to its marker")
    if _sha256(evidence_plist) != expected_hash or _sha256(stable) != expected_hash:
        raise MigrationError("Stage 1 bound LaunchAgent changed")
    return stable


def _working_directory() -> Path:
    root = Path(__file__).resolve().parents[2]
    if not root.is_dir() or any(part.is_symlink() for part in _existing_parts(root)):
        raise MigrationError(f"Stage 1 LaunchAgent working directory is not a verified checkout: {root}")
    return root


def _source_binding(manifest: Path) -> dict[str, str]:
    """Validate the pinned profile and its installed runtime boundary."""
    value = _read_json(manifest, "neutral source manifest")
    if value.get("profile") != "astrid":
        raise MigrationError("Stage 1 source manifest must select the astrid profile")
    working = _working_directory()
    runtime_checkout = _absolute(str(value.get("runtime_checkout", "")), "runtime checkout")
    source_checkout = _absolute(str(value.get("source_checkout", "")), "source checkout")
    environment = _absolute(str(value.get("runtime_environment", "")), "runtime environment")
    if runtime_checkout != working or not runtime_checkout.is_dir() or not source_checkout.is_dir() or not environment.is_dir():
        raise MigrationError("Stage 1 source profile checkout binding is invalid")
    interpreter = environment / "bin" / "python"
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise MigrationError(f"Stage 1 runtime environment has no executable Python: {interpreter}")
    try:
        result = subprocess.run(
            [str(interpreter), "-c", "import sys; from pathlib import Path; import banodoco_local, banodoco_workspace_client; from banodoco_local.bootstrap import SourceProfile; SourceProfile.load(sys.argv[1]); root=Path(sys.executable).parent.parent; [Path(module.__file__).resolve().relative_to(root) for module in (banodoco_local, banodoco_workspace_client)]", str(manifest)],
            cwd=str(environment), env={"PATH": os.defpath}, capture_output=True, text=True,
            check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MigrationError("Stage 1 installed runtime environment could not be checked") from exc
    if result.returncode != 0:
        raise MigrationError("Stage 1 installed runtime environment must import banodoco_local and banodoco_workspace_client")
    return {
        "source_manifest_sha256": _sha256(manifest),
        "runtime_environment": str(environment),
        "runtime_environment_python": str(interpreter),
    }


def _terminal(evidence: Path, active: Path, support: Path, realm_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    journal = _read_json(evidence / "migration-journal-b12.json", "B12 migration journal")
    receipt = _read_json(evidence / "activated-destination-b12.json", "B12 terminal receipt")
    if journal.get("state") != "reactivated":
        raise MigrationError("Stage 1 reboot checkpoint requires a terminal B12 journal")
    if receipt.get("packet") != "B12.4" or receipt.get("realm_id") != realm_id:
        raise MigrationError("Stage 1 reboot checkpoint requires the selected terminal B12.4 realm")
    if receipt.get("destination_root") != str(active):
        raise MigrationError("Stage 1 terminal receipt is bound to a different active root")
    runtime = _runtime_state(active)
    if runtime["realm_id"] != realm_id:
        raise MigrationError("Stage 1 active realm identity does not match the selected realm")
    if runtime["quick_check"] != "ok" or runtime["foreign_key_errors"]:
        raise MigrationError("Stage 1 active realm failed read-only integrity checks")
    catalog = _read_json(support / "catalog.json", "Stage 1 realm catalog")
    rows = [row for row in catalog.get("realms", []) if isinstance(row, Mapping) and row.get("realm_id") == realm_id]
    if catalog.get("selected_realm_id") != realm_id or len(rows) != 1:
        raise MigrationError("Stage 1 catalog selection does not match the selected realm")
    if _absolute(rows[0].get("data_root", ""), "catalog data root") != active:
        raise MigrationError("Stage 1 catalog data root does not match the active realm")
    identity = receipt.get("catalog_identity")
    if not isinstance(identity, Mapping) or identity.get("status") != "ready" or identity.get("selected_realm_id") != realm_id or identity.get("data_root") != str(active) or identity.get("sha256") != _sha256(support / "catalog.json"):
        raise MigrationError("Stage 1 terminal catalog binding is missing or changed")
    return journal, receipt


def _provider(provider: Callable[[], str] | None) -> str:
    value = (provider or _host_boot_identity)()
    if not isinstance(value, str) or not value.strip():
        raise MigrationError("Stage 1 boot identity provider returned no identity")
    return value


def _r1_payload(evidence: Path, active: Path, support: Path, terminal_support: Path, realm_id: str, boot: str) -> dict[str, Any]:
    journal, terminal = _terminal(evidence, active, terminal_support, realm_id)
    neutral_catalog = _read_json(support / "catalog.json", "neutral realm catalog")
    rows = [row for row in neutral_catalog.get("realms", []) if isinstance(row, Mapping) and row.get("realm_id") == realm_id]
    if neutral_catalog.get("selected_realm_id") != realm_id or len(rows) != 1 or rows[0].get("data_root") != str(active):
        raise MigrationError("Stage 1 neutral catalog does not match the selected realm")
    runtime = _runtime_state(active)
    return {
        "packet": "B12.R1",
        "state": "armed",
        "checkpoint_id": hashlib.sha256(f"{time.time_ns()}:{os.getpid()}".encode()).hexdigest()[:24],
        "realm_id": realm_id,
        "active_root": str(active),
        "support_root": str(support),
        "terminal_support_root": str(terminal_support),
        "neutral_catalog_sha256": _sha256(support / "catalog.json"),
        "evidence_root": str(evidence),
        "working_directory": str(_working_directory()),
        "boot_identity_before": boot,
        "runtime_epoch_before": runtime["runtime_epoch"],
        "runtime_boot_id_before": runtime["runtime_boot_id"],
        "terminal_receipt_sha256": _sha256(evidence / "activated-destination-b12.json"),
        "journal_sha256": _sha256(evidence / "migration-journal-b12.json"),
        "terminal_runtime_epoch": terminal.get("runtime_epoch"),
        "armed_at": time.time(),
    }


def _plist(payload: Mapping[str, Any], python_executable: str) -> bytes:
    args = [
        python_executable,
        "-m",
        "tools.astrid_migrate.operator",
        "stage1-reboot-postboot",
        "--evidence-root",
        str(payload["evidence_root"]),
        "--active-root",
        str(payload["active_root"]),
        "--support-root",
        str(payload["support_root"]),
        "--terminal-support-root",
        str(payload["terminal_support_root"]),
        "--realm-id",
        str(payload["realm_id"]),
        "--neutral-home",
        str(payload["neutral_home"]),
        "--source-manifest",
        str(payload["source_manifest"]),
        "--wait-seconds",
        "120",
        "--poll-seconds",
        "1",
    ]
    value = {
        "Label": _launch_agent_label(payload),
        "ProgramArguments": args,
        "WorkingDirectory": str(payload["working_directory"]),
        "RunAtLoad": True,
        "KeepAlive": False,
        "ThrottleInterval": 120,
        "ProcessType": "Background",
        "StandardOutPath": str(Path(payload["evidence_root"]) / "stage1-reboot-resume.stdout.log"),
        "StandardErrorPath": str(Path(payload["evidence_root"]) / "stage1-reboot-resume.stderr.log"),
    }
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


def arm_stage1_reboot(evidence_root: str | Path, active_root: str | Path, support_root: str | Path, realm_id: str, *, neutral_home: str | Path | None = None, source_manifest: str | Path | None = None, terminal_support_root: str | Path | None = None, boot_identity_provider: Callable[[], str] | None = None, python_executable: str | None = None, launch_agents_dir: str | Path | None = None) -> dict[str, Any]:
    """Durably arm one postboot R2 capture; never invokes reboot or launchctl."""
    evidence = _absolute(evidence_root, "evidence root")
    active = _absolute(active_root, "active root")
    support = _absolute(support_root, "support root")
    terminal_support = _absolute(terminal_support_root or support, "terminal support root")
    neutral = _absolute(neutral_home or Path.home(), "neutral home")
    manifest = _absolute(source_manifest or (support / "source-profiles" / "astrid.json"), "neutral source manifest")
    if not evidence.is_dir() or not active.is_dir() or not support.is_dir():
        raise MigrationError("Stage 1 reboot arm requires existing evidence, active, and support directories")
    marker = evidence / ARMED_NAME
    if not neutral.is_dir() or not manifest.is_file() or manifest.is_symlink():
        raise MigrationError("Stage 1 reboot arm requires an existing neutral home and source manifest")
    binding = _source_binding(manifest)
    launch_agents = _launch_agents_dir(launch_agents_dir, create=True)
    interpreter = binding["runtime_environment_python"]
    if python_executable is not None and _verified_executable(python_executable) != interpreter:
        raise MigrationError("LaunchAgent interpreter must be the bound runtime environment Python")
    if marker.is_file():
        existing = _read_json(marker, "Stage 1 reboot marker")
        expected = {"active_root": str(active), "support_root": str(support), "terminal_support_root": str(terminal_support), "evidence_root": str(evidence), "realm_id": realm_id, "working_directory": str(_working_directory()), "python_executable": interpreter, "launch_agents_dir": str(launch_agents), "neutral_home": str(neutral), "source_manifest": str(manifest), **binding}
        if all(existing.get(key) == value for key, value in expected.items()):
            if existing.get("state") == "completed":
                raise MigrationError("Stage 1 reboot checkpoint is already completed")
            plist_path = evidence / PLIST_NAME
            if not plist_path.is_file():
                raise MigrationError("Stage 1 reboot evidence copy of LaunchAgent is missing")
            stable = _absolute(existing.get("launch_agent_path", ""), "bound LaunchAgent")
            if not stable.is_file():
                _write_bytes(stable, plist_path.read_bytes())
            _verify_launch_agent(existing, evidence)
            return existing | {"plist_path": str(plist_path), "launch_agent_path": str(stable)}
        raise MigrationError("Stage 1 reboot marker is bound to a different objective")
    if marker.exists() or marker.is_symlink():
        raise MigrationError("Stage 1 reboot marker is not a regular file")
    plist_path = evidence / PLIST_NAME
    payload = _r1_payload(evidence, active, support, terminal_support, realm_id, _provider(boot_identity_provider)) | {"plist_path": str(plist_path), "launch_agents_dir": str(launch_agents), "python_executable": interpreter, "neutral_home": str(neutral), "source_manifest": str(manifest), **binding}
    payload = payload | {"launch_agent_label": _launch_agent_label(payload), "launch_agent_path": str(launch_agents / f"{_launch_agent_label(payload)}.plist")}
    plist_bytes = _plist(payload, interpreter)
    payload = payload | {"launch_agent_sha256": hashlib.sha256(plist_bytes).hexdigest()}
    _write_new(marker, payload)
    _write_bytes(plist_path, plist_bytes)
    _write_bytes(Path(payload["launch_agent_path"]), plist_bytes)
    return payload


def resume_stage1_reboot(evidence_root: str | Path, active_root: str | Path, support_root: str | Path, realm_id: str, *, terminal_support_root: str | Path | None = None, boot_identity_provider: Callable[[], str] | None = None, wait_seconds: int = 0, poll_seconds: int = 5, runtime_bootstrap: Mapping[str, Any] | None = None, launch_agent_cleanup: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Capture R2 after a changed host boot and runtime cold launch."""
    evidence = _absolute(evidence_root, "evidence root")
    active = _absolute(active_root, "active root")
    support = _absolute(support_root, "support root")
    terminal_support = _absolute(terminal_support_root or support, "terminal support root")
    marker = _read_json(evidence / ARMED_NAME, "Stage 1 reboot marker")
    expected = {"active_root": str(active), "support_root": str(support), "terminal_support_root": str(terminal_support), "evidence_root": str(evidence), "realm_id": realm_id, "working_directory": str(_working_directory())}
    if any(marker.get(key) != value for key, value in expected.items()):
        raise MigrationError("Stage 1 reboot marker is bound to a different objective")
    r2_path = evidence / R2_NAME
    if marker.get("state") == "completed" and r2_path.is_file():
        existing = _read_json(r2_path, "Stage 1 R2 receipt")
        if existing.get("packet") != "B12.R2" or existing.get("state") != "completed" or existing.get("checkpoint_id") != marker.get("checkpoint_id"):
            raise MigrationError("Stage 1 completed marker does not match its R2 receipt")
        if marker.get("r2_receipt_sha256") != _sha256(r2_path):
            raise MigrationError("Stage 1 R2 receipt digest changed")
        if marker.get("neutral_catalog_sha256") != _sha256(support / "catalog.json"):
            raise MigrationError("Stage 1 neutral catalog changed after R1")
        binding = _source_binding(_absolute(str(marker.get("source_manifest", "")), "neutral source manifest"))
        if any(marker.get(key) != value for key, value in binding.items()):
            raise MigrationError("Stage 1 source profile binding changed after R1")
        _terminal(evidence, active, terminal_support, realm_id)
        return existing
    if marker.get("state") != "armed":
        raise MigrationError("Stage 1 reboot marker is neither armed nor completed")
    binding = _source_binding(_absolute(str(marker.get("source_manifest", "")), "neutral source manifest"))
    if any(marker.get(key) != value for key, value in binding.items()):
        raise MigrationError("Stage 1 source profile binding changed after R1")
    if launch_agent_cleanup is None:
        launch_agent = _verify_launch_agent(marker, evidence)
    else:
        launch_agent = _absolute(str(launch_agent_cleanup.get("path", "")), "bound LaunchAgent")
        if launch_agent_cleanup.get("status") != "plist_removed_external_bootout_verification_required" or launch_agent != _absolute(str(marker.get("launch_agent_path", "")), "bound LaunchAgent") or _sha256(evidence / PLIST_NAME) != str(marker.get("launch_agent_sha256", "")):
            raise MigrationError("Stage 1 removed LaunchAgent cleanup is not bound to R1")
    journal_path = evidence / "migration-journal-b12.json"
    terminal_path = evidence / "activated-destination-b12.json"
    if marker.get("journal_sha256") != _sha256(journal_path) or marker.get("terminal_receipt_sha256") != _sha256(terminal_path):
        raise MigrationError("Stage 1 R1-pinned B12 evidence changed")
    if marker.get("neutral_catalog_sha256") != _sha256(support / "catalog.json"):
        raise MigrationError("Stage 1 neutral catalog changed after R1")
    journal, terminal = _terminal(evidence, active, terminal_support, realm_id)
    current_boot = _provider(boot_identity_provider)
    if current_boot == marker.get("boot_identity_before"):
        raise MigrationError("Stage 1 R2 requires a changed host boot identity")
    if wait_seconds < 0 or poll_seconds <= 0:
        raise MigrationError("Stage 1 R2 wait and poll seconds must be non-negative and positive")
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            runtime = _runtime_state(active)
        except MigrationError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))
            continue
        if runtime["realm_id"] != realm_id:
            raise MigrationError("Stage 1 active realm identity changed during R2")
        if runtime["quick_check"] != "ok" or runtime["foreign_key_errors"]:
            raise MigrationError("Stage 1 active realm failed read-only integrity checks")
        if runtime["runtime_epoch"] > int(marker["runtime_epoch_before"]) and runtime["runtime_boot_id"] != marker.get("runtime_boot_id_before"):
            break
        if time.monotonic() >= deadline:
            raise MigrationError("Stage 1 R2 requires a cold-launched runtime epoch")
        time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))
    payload = {
        "packet": "B12.R2",
        "state": "completed",
        "checkpoint_id": marker["checkpoint_id"],
        "realm_id": realm_id,
        "active_root": str(active),
        "support_root": str(support),
        "terminal_support_root": str(terminal_support),
        "evidence_root": str(evidence),
        "boot_identity_before": marker["boot_identity_before"],
        "boot_identity_after": current_boot,
        "runtime_epoch_before": int(marker["runtime_epoch_before"]),
        "runtime_epoch_after": runtime["runtime_epoch"],
        "runtime_boot_id_before": marker["runtime_boot_id_before"],
        "runtime_boot_id_after": runtime["runtime_boot_id"],
        "terminal_receipt_sha256": _sha256(evidence / "activated-destination-b12.json"),
        "journal_sha256": _sha256(evidence / "migration-journal-b12.json"),
        "terminal_runtime_epoch": terminal.get("runtime_epoch"),
        "journal_state": journal.get("state"),
        "quick_check": runtime["quick_check"],
        "foreign_key_errors": runtime["foreign_key_errors"],
        "launch_agent_path": str(launch_agent),
        "launch_agent_label": marker["launch_agent_label"],
        "launch_agent_sha256": marker["launch_agent_sha256"],
        "launch_agent_cleanup": dict(launch_agent_cleanup or {
            "status": "pending_plist_removal_and_external_bootout_verification",
            "path": str(launch_agent),
            "label": marker["launch_agent_label"],
        }),
        "runtime_bootstrap": dict(runtime_bootstrap or {"status": "not_invoked_by_direct_resume"}),
        "captured_at": time.time(),
    }
    if r2_path.exists() or r2_path.is_symlink():
        existing = _read_json(r2_path, "Stage 1 R2 receipt")
        for key in ("packet", "state", "checkpoint_id", "realm_id", "active_root", "boot_identity_before", "boot_identity_after", "runtime_epoch_before", "runtime_epoch_after", "runtime_boot_id_before", "runtime_boot_id_after"):
            if existing.get(key) != payload.get(key):
                raise MigrationError("Stage 1 R2 receipt conflicts with the armed checkpoint")
        payload = existing
    else:
        _write_new(r2_path, payload)
    marker_completed = dict(marker) | {"state": "completed", "r2_receipt": str(r2_path), "r2_receipt_sha256": _sha256(r2_path)}
    _replace_json(evidence / ARMED_NAME, marker_completed)
    return payload


def _neutral_bootstrap(marker: Mapping[str, Any], realm_id: str, *, wait_seconds: int) -> dict[str, Any]:
    command = [
        str(marker["runtime_environment_python"]),
        "-m",
        "banodoco_local",
        "up",
        "--profile",
        "astrid",
        "--source-manifest",
        str(marker["source_manifest"]),
        "--json",
    ]
    # launchd does not promise the interactive shell environment.  Bind the
    # selected support home and manifest explicitly while keeping the launch
    # authority in the existing neutral ``banodoco-local up`` boundary.
    environment = {
        "BANODOCO_LOCAL_HOME": str(marker["neutral_home"]),
        "BANODOCO_LOCAL_SOURCE_MANIFEST": str(marker["source_manifest"]),
        "PATH": os.defpath,
    }
    try:
        result = subprocess.run(command, cwd=str(marker["neutral_home"]), env=environment, capture_output=True, text=True, check=False, timeout=max(1, wait_seconds))
    except (OSError, subprocess.SubprocessError) as exc:
        raise MigrationError("Stage 1 neutral runtime bootstrap failed") from exc
    if result.returncode != 0:
        detail = result.stderr.strip()
        if not detail:
            try:
                error = json.loads(result.stdout).get("error")
            except (ValueError, AttributeError, TypeError):
                error = ""
            detail = str(error or result.stdout.strip() or "no diagnostic returned")
        raise MigrationError(f"Stage 1 neutral runtime bootstrap failed: {detail}")
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MigrationError("Stage 1 neutral runtime bootstrap returned invalid JSON") from exc
    if not isinstance(value, Mapping) or value.get("realm_id") != realm_id or value.get("status") not in {"started", "reconnected", "restarted"}:
        raise MigrationError("Stage 1 neutral runtime bootstrap selected the wrong realm")
    return dict(value)


def _remove_launch_agent(marker: Mapping[str, Any], launch_agent: Path) -> dict[str, Any]:
    label = str(marker["launch_agent_label"])
    command = ["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{label}"]
    if launch_agent.exists() or launch_agent.is_symlink():
        try:
            launch_agent.unlink()
            parent_fd = os.open(launch_agent.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError as exc:
            raise MigrationError("Stage 1 postboot could not durably remove its LaunchAgent plist") from exc
    return {
        "status": "plist_removed_external_bootout_verification_required",
        "path": str(launch_agent),
        "label": label,
        "command": command,
    }


def postboot_stage1_reboot(evidence_root: str | Path, active_root: str | Path, support_root: str | Path, realm_id: str, *, neutral_home: str | Path | None = None, source_manifest: str | Path | None = None, terminal_support_root: str | Path | None = None, wait_seconds: int = 120, poll_seconds: int = 1, boot_identity_provider: Callable[[], str] | None = None) -> dict[str, Any]:
    evidence = _absolute(evidence_root, "evidence root")
    active = _absolute(active_root, "active root")
    support = _absolute(support_root, "support root")
    terminal_support = _absolute(terminal_support_root or support, "terminal support root")
    marker = _read_json(evidence / ARMED_NAME, "Stage 1 reboot marker")
    expected = {"active_root": str(active), "support_root": str(support), "terminal_support_root": str(terminal_support), "evidence_root": str(evidence), "realm_id": realm_id}
    if any(marker.get(key) != value for key, value in expected.items()):
        raise MigrationError("Stage 1 postboot arguments do not match R1")
    neutral = _absolute(neutral_home or str(marker.get("neutral_home", "")), "neutral home")
    manifest = _absolute(source_manifest or str(marker.get("source_manifest", "")), "neutral source manifest")
    if neutral != Path(str(marker.get("neutral_home", ""))):
        raise MigrationError("Stage 1 postboot neutral home does not match R1")
    if manifest != Path(str(marker.get("source_manifest", ""))):
        raise MigrationError("Stage 1 postboot source manifest does not match R1")
    if _provider(boot_identity_provider) == marker.get("boot_identity_before"):
        raise MigrationError("Stage 1 R2 requires a changed host boot identity")
    if marker.get("state") == "completed":
        return resume_stage1_reboot(evidence, active, support, realm_id, terminal_support_root=terminal_support)
    try:
        launch_agent = _verify_launch_agent(marker, evidence)
    except MigrationError:
        # A crash after durable plist removal but before R2 must remain
        # recoverable.  The immutable evidence copy still proves which plist
        # was armed; resume can safely finish the one-shot receipt.
        launch_agent = _absolute(str(marker.get("launch_agent_path", "")), "bound LaunchAgent")
        if launch_agent.exists() or _sha256(evidence / PLIST_NAME) != str(marker.get("launch_agent_sha256", "")):
            raise
    bootstrap = _neutral_bootstrap(marker, realm_id, wait_seconds=wait_seconds)
    cleanup = _remove_launch_agent(marker, launch_agent)
    return resume_stage1_reboot(evidence, active, support, realm_id, terminal_support_root=terminal_support, wait_seconds=wait_seconds, poll_seconds=poll_seconds, runtime_bootstrap=bootstrap, launch_agent_cleanup=cleanup)


__all__ = ["ARMED_NAME", "R2_NAME", "PLIST_NAME", "arm_stage1_reboot", "resume_stage1_reboot", "postboot_stage1_reboot"]
