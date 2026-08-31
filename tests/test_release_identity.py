from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from runtime_protocol.release_identity import ReleaseIdentityError, build_prelive_manifest, create_candidate_core_identity, create_pre_live_identity, load_receipt, main, resolve_component, run_b11_1

def _seeds() -> dict[str, bytes]:
    from runtime_protocol.release_identity import PRELIVE_SEEDS
    return {seed: seed.encode() for seed in PRELIVE_SEEDS}


def _git_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    repo = root / "component"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Release Test"], check=True)
    (repo / "contract.json").write_text('{"version":1}\n')
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
    return repo


def test_runtime_identity_round_trip(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    path = tmp_path / "pre.json"
    pre = create_pre_live_identity({"NEUTRAL-RUNTIME": repo}, output=path, seed_outputs=_seeds())
    assert load_receipt(path)["identity"] == pre["identity"]
    core = create_candidate_core_identity(path, {"NEUTRAL-RUNTIME": repo})
    assert core["candidate_core"]["pre_live_evidence_root"] == pre["identity"]


def test_runtime_identity_rejects_dirty_checkout(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    (repo / "dirty.txt").write_text("pending\n")
    with pytest.raises(ReleaseIdentityError, match="uncommitted"):
        create_pre_live_identity({"NEUTRAL-RUNTIME": repo})


def test_runtime_manifest_rejects_missing_seeds(tmp_path: Path) -> None:
    with pytest.raises(ReleaseIdentityError, match="actual"):
        build_prelive_manifest({})


def test_runtime_receipt_cannot_be_written_inside_component(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    with pytest.raises(ReleaseIdentityError, match="inside"):
        create_pre_live_identity({"NEUTRAL-RUNTIME": repo}, output=repo / "receipt.json")

def test_runtime_cli_consumes_exact_seed_directory_manifest(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path); seed_dir = tmp_path / "seed-bytes"; seed_dir.mkdir(); manifest = {}
    from runtime_protocol.release_identity import PRELIVE_SEEDS
    for index, seed in enumerate(PRELIVE_SEEDS):
        name = f"{index:02d}.bin"; (seed_dir / name).write_bytes(seed.encode()); manifest[seed] = {"path": name, "media_type": "application/octet-stream", "producer_id": "FIXTURE-PRODUCER"}
    manifest_path = tmp_path / "seeds.json"; manifest_path.write_text(__import__("json").dumps(manifest), encoding="utf-8"); output = tmp_path / "cli-pre.json"
    assert main(["pre-live", "--component", f"NEUTRAL-RUNTIME={repo}", "--seed-dir", str(seed_dir), "--seed-manifest", str(manifest_path), "--output", str(output)]) == 0
    assert load_receipt(output)["pre_live_seed_payloads"][0]["media_type"] == "application/octet-stream"

def test_runtime_b11_local_submodule_is_pinned(tmp_path: Path) -> None:
    sub = _git_repo(tmp_path / "sub-root"); checkout = _git_repo(tmp_path / "main-root")
    subprocess.run(["git", "-C", str(checkout), "-c", "protocol.file.allow=always", "submodule", "add", str(sub), "vendor/sub"], check=True, stdout=subprocess.DEVNULL)
    (checkout / "generator.py").write_text("import argparse, pathlib\np=argparse.ArgumentParser(); p.add_argument('--contract'); p.add_argument('--schema-manifest'); p.add_argument('--output-root'); a=p.parse_args(); pathlib.Path(a.output_root, 'out').write_bytes(b'ok')\n")
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True); subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "submodule generator"], check=True)
    row = resolve_component("NEUTRAL-RUNTIME", checkout)
    observed = run_b11_1([row], [{"generator_id": "GEN", "component_id": "NEUTRAL-RUNTIME", "checkout": str(checkout), "entrypoint_path": "generator.py"}], contract_bytes=b"{}", schema_manifest_bytes=b"{}", output_root=tmp_path)
    assert observed[0]["generator_observation_rows"][0]["output_digests"]
    outside = tmp_path.parent / "runtime-b11-outside-submodule"
    subprocess.run(["git", "-C", str(checkout), "config", "-f", ".gitmodules", "submodule.vendor/sub.url", str(outside)], check=True)
    subprocess.run(["git", "-C", str(checkout), "add", ".gitmodules"], check=True); subprocess.run(["git", "-C", str(checkout), "commit", "-qm", "malicious submodule url"], check=True)
    with pytest.raises(ReleaseIdentityError, match="approved source root"):
        run_b11_1([resolve_component("NEUTRAL-RUNTIME", checkout)], [{"generator_id": "GEN", "component_id": "NEUTRAL-RUNTIME", "checkout": str(checkout), "entrypoint_path": "generator.py"}], contract_bytes=b"{}", schema_manifest_bytes=b"{}", output_root=tmp_path)
