"""Adversarial proofs for the offline migration/operator boundary."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess
import sys

from banodoco_local.bootstrap import BootstrapConfig, LegacyRootCollisionError, SourceProfile, bootstrap
from banodoco_local.paths import RuntimePaths


ROOT = Path(__file__).parents[1]


def test_whole_migrator_package_imports_under_product_deny_hook():
    code = """
import sys
blocked = ('astrid', 'reigh', 'runtime_protocol')
class Deny:
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == item or fullname.startswith(item + '.') for item in blocked):
            raise ImportError('migration boundary denied: ' + fullname)
        return None
sys.meta_path.insert(0, Deny())
import tools.astrid_migrate as package
assert package.Migrator and package.run_rehearsal and package.run_live_migration
assert package.verify_trusted_disposition and package.B13Recovery
print('ok')
"""
    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_migrator_transitive_import_closure_is_neutral():
    forbidden = {"astrid", "reigh", "runtime_protocol"}
    for path in (ROOT / "tools" / "astrid_migrate").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots = [node.module.split(".")[0]]
            else:
                continue
            assert not forbidden.intersection(roots), (path, roots)


def _config(paths: RuntimePaths) -> BootstrapConfig:
    return BootstrapConfig(source_profile=SourceProfile(
        profile="astrid", runtime_checkout="/runtime", source_checkout="/astrid"))


class _Boundary:
    def __init__(self): self.starts = 0
    def start(self, **kwargs):
        self.starts += 1
        root = kwargs["realm_root"]; root.mkdir(parents=True, exist_ok=True)
        return {"endpoint": "http://127.0.0.1:1", "pid": 1, "runtime_instance_id": "i", "coordinator_epoch": 1, "protocol_version": "workspace.v1", "schema_version": "workspace-schema-v1"}
    def is_pid_alive(self, pid): return False


def test_empty_catalog_cannot_bypass_real_legacy_root(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    legacy = paths.home / ".astrid"; legacy.mkdir(parents=True)
    paths.runtime_support.mkdir(parents=True)
    paths.catalog_path.write_text(json.dumps({"version": 1, "realms": [], "selected_realm_id": None}))
    boundary = _Boundary()
    try:
        bootstrap(paths, boundary, _config(paths))
    except LegacyRootCollisionError as exc:
        assert "banodoco-local migrate --profile astrid --source" in str(exc)
    else:
        raise AssertionError("empty catalog bypassed legacy collision")
    assert boundary.starts == 0


def test_dangling_legacy_symlink_is_a_collision(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path)
    legacy = paths.home / ".astrid"; legacy.symlink_to(paths.home / "missing-legacy-root")
    boundary = _Boundary()
    try:
        bootstrap(paths, boundary, _config(paths))
    except LegacyRootCollisionError as exc:
        assert "banodoco-local migrate --profile astrid --source" in str(exc)
    else:
        raise AssertionError("dangling legacy symlink bypassed collision")
    assert boundary.starts == 0
