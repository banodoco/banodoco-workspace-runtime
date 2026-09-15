"""Disposable real-daemon coverage for the launcher support-root cutover."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

from banodoco_local.bootstrap import BootstrapConfig, SourceProfile, bootstrap
from banodoco_local.relocation import RelocationError, relocate
from banodoco_local.runtime_boundary import LocalRuntimeBoundary
from banodoco_local import RuntimePaths


def _config(repo: Path) -> BootstrapConfig:
    packages = repo / "packages" / "python"
    if str(packages) not in sys.path:
        sys.path.insert(0, str(packages))
    return BootstrapConfig(source_profile=SourceProfile(
        profile="astrid",
        runtime_checkout=str(repo),
        source_checkout=str(repo),
    ))


def test_real_runtime_daemon_cutover_starts_from_new_support_root(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    old_support = tmp_path / "old-support"
    new_support = tmp_path / "new-support"
    new_support.mkdir()
    (new_support / "existing-auxiliary").mkdir()
    (new_support / "existing-auxiliary" / "keep.txt").write_text("keep", encoding="utf-8")
    paths = RuntimePaths.current_mac(data_root=old_support)
    boundary = LocalRuntimeBoundary(wait_seconds=8)
    config = _config(repo)

    try:
        first = bootstrap(paths, boundary, config)
        assert first.ready
        marker = old_support / "auxiliary-preserved.txt"
        marker.write_text("preserve", encoding="utf-8")
        result = relocate(
            paths,
            boundary,
            config,
            client=None,
            destination=new_support,
            confirmation=f"RELOCATE {first.realm_id}",
        )
        assert result["status"] == "relocated"
        assert (new_support / marker.relative_to(old_support)).read_text(encoding="utf-8") == "preserve"
        assert (new_support / "existing-auxiliary" / "keep.txt").read_text(encoding="utf-8") == "keep"
        moved = RuntimePaths.current_mac(data_root=new_support)
        assert moved.catalog_path.is_file()
        assert result["data_root"] == str(moved.realms_dir / first.realm_id)
        import json
        discovery = json.loads(moved.discovery_path.read_text(encoding="utf-8"))
        assert boundary.health(
            endpoint=discovery["endpoint"],
            pid=int(discovery["pid"]),
            instance_id=discovery["runtime_instance_id"],
        ) is True
    finally:
        boundary.stop()
def test_real_runtime_cutover_failure_rolls_back_tree_and_metadata(tmp_path, monkeypatch):
    repo = Path(__file__).resolve().parents[1]
    old_support = tmp_path / "old-support"
    new_support = tmp_path / "new-support"
    paths = RuntimePaths.current_mac(data_root=old_support)
    boundary = LocalRuntimeBoundary(wait_seconds=8)
    config = _config(repo)
    try:
        first = bootstrap(paths, boundary, config)
        before = paths.catalog_path.read_bytes()
        original_start = boundary.start

        def fail_candidate(*args, **kwargs):
            if Path(kwargs["owner_lock"]).is_relative_to(new_support):
                raise RuntimeError("injected candidate start failure")
            return original_start(*args, **kwargs)

        monkeypatch.setattr(boundary, "start", fail_candidate)
        with pytest.raises(RelocationError, match="rolled back"):
            relocate(paths, boundary, config, client=None, destination=new_support, confirmation=f"RELOCATE {first.realm_id}")
        assert old_support.is_dir()
        assert not new_support.exists()
        assert paths.catalog_path.read_bytes() == before
        import json
        restored = json.loads(paths.discovery_path.read_text(encoding="utf-8"))
        assert boundary.health(
            endpoint=restored["endpoint"],
            pid=int(restored["pid"]),
            instance_id=restored["runtime_instance_id"],
        ) is True
        monkeypatch.setattr(boundary, "start", original_start)
    finally:
        boundary.stop()
