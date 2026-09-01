from __future__ import annotations

import json
from pathlib import Path
import os
import subprocess
import sys

from banodoco_local.tiny_acceptance import run_tiny_acceptance


def _astrid_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "astrid-checkout"
    checkout.mkdir()
    return checkout


def test_tiny_acceptance_runs_real_compact_b12_and_cold_opens(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    output = tmp_path / "tiny-b12"
    result = run_tiny_acceptance(output, _astrid_checkout(tmp_path), stage1_runtime_environment)

    assert result["ok"] is True
    assert result["redundancy"] == "compact"
    assert result["journal_state"] == "reactivated"
    assert result["source_bytes"] < 1024 * 1024
    assert result["cold_open"]["ok"] is True
    assert result["cold_open"]["project_count"] >= 1
    assert result["cold_open"]["object_count"] >= 1
    assert "/Library/Application Support/Banodoco/runtime/realms/" in result["active_root"]
    assert Path(result["migration_support_root"]).is_dir()
    assert result["migration_support_root"] != result["support_root"]
    profile = json.loads(Path(result["source_manifest"]).read_text())
    assert profile["profile"] == "astrid"
    assert Path(profile["source_checkout"]).is_dir()

    evidence = output / "evidence"
    capacity = json.loads((evidence / "capacity-receipt-b12.json").read_text())
    assert capacity["redundancy"] == "compact"
    assert capacity["candidate_bytes"] == 0
    assert capacity["reactivation_bytes"] == 0
    assert capacity["margin_bytes"] == int(result["source_bytes"] * 0.2)
    assert capacity["required_bytes"] < 10 * 1024 * 1024
    assert (evidence / "activated-destination-b12.json").is_file()
    assert (evidence / "activated-destination-b12-rollback.json").is_file()
    assert (evidence / "activated-destination-b12-reactivated.json").is_file()
    assert (evidence / "writer-stop-completion-b12.json").is_file()
    assert (output / "b12-authorizations.json").stat().st_mode & 0o777 == 0o600
    assert (output / "writer-stop.json").stat().st_mode & 0o777 == 0o600
    assert json.loads((output / "tiny-acceptance.json").read_text())["terminal_receipt"] == str(evidence / "activated-destination-b12.json")


def test_tiny_acceptance_requires_a_fresh_output_root(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    output = tmp_path / "tiny-b12"
    output.mkdir()
    (output / "keep.txt").write_text("user data", encoding="utf-8")
    checkout = _astrid_checkout(tmp_path)

    try:
        run_tiny_acceptance(output, checkout, stage1_runtime_environment)
    except ValueError as exc:
        assert "not empty" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("tiny acceptance replaced an existing output root")


def test_tiny_acceptance_cli_has_no_runpy_warning(tmp_path: Path, stage1_runtime_environment: Path) -> None:
    output = tmp_path / "tiny-b12-cli"
    checkout = _astrid_checkout(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.astrid_migrate.operator",
            "tiny-acceptance",
            "--output-root",
            str(output),
            "--source-checkout",
            str(checkout),
            "--runtime-environment",
            str(stage1_runtime_environment),
        ],
        cwd=Path(__file__).parents[1],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1])},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "RuntimeWarning" not in result.stderr
    assert json.loads(result.stdout)["redundancy"] == "compact"
