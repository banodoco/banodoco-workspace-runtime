from __future__ import annotations

import json
from pathlib import Path

from tools.astrid_migrate.tiny_acceptance import run_tiny_acceptance


def test_tiny_acceptance_runs_real_compact_b12_and_cold_opens(tmp_path: Path) -> None:
    output = tmp_path / "tiny-b12"
    result = run_tiny_acceptance(output)

    assert result["ok"] is True
    assert result["redundancy"] == "compact"
    assert result["journal_state"] == "reactivated"
    assert result["source_bytes"] < 1024 * 1024
    assert result["cold_open"]["ok"] is True
    assert result["cold_open"]["project_count"] >= 1
    assert result["cold_open"]["object_count"] >= 1

    evidence = output / "evidence"
    assert (evidence / "activated-destination-b12.json").is_file()
    assert (evidence / "activated-destination-b12-rollback.json").is_file()
    assert (evidence / "activated-destination-b12-reactivated.json").is_file()
    assert (evidence / "writer-stop-completion-b12.json").is_file()
    assert (output / "b12-authorizations.json").stat().st_mode & 0o777 == 0o600
    assert (output / "writer-stop.json").stat().st_mode & 0o777 == 0o600
    assert json.loads((output / "tiny-acceptance.json").read_text())["terminal_receipt"] == str(evidence / "activated-destination-b12.json")


def test_tiny_acceptance_requires_a_fresh_output_root(tmp_path: Path) -> None:
    output = tmp_path / "tiny-b12"
    output.mkdir()
    (output / "keep.txt").write_text("user data", encoding="utf-8")

    try:
        run_tiny_acceptance(output)
    except ValueError as exc:
        assert "not empty" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("tiny acceptance replaced an existing output root")
