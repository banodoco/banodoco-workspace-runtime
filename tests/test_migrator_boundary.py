"""Lane 9 boundaries: source readers are standalone and migration is opt-in."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

from tools.astrid_migrate.source_readers import manifest_to_transitions


ROOT = Path(__file__).parents[1]
SOURCE_READERS = ROOT / "tools" / "astrid_migrate" / "source_readers.py"


def test_source_readers_are_stdlib_only_and_have_no_path_injection() -> None:
    tree = ast.parse(SOURCE_READERS.read_text(encoding="utf-8"))
    imported = {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imported.update(
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert imported <= {"__future__", "json", "pathlib", "typing"}
    text = SOURCE_READERS.read_text(encoding="utf-8")
    assert "sys.path" not in text
    assert "PYTHONPATH" not in text
    assert "importlib" not in text
    assert "from astrid" not in text
    assert "import astrid" not in text
    assert "from reigh" not in text
    assert "import reigh" not in text
    assert "runtime_protocol" not in text


def test_source_reader_import_hook_denies_product_and_runtime_modules() -> None:
    # Load the source-reader file as a standalone module so the package's
    # runtime-facing orchestration is not part of this proof.
    code = "\n".join([
        "import importlib.util, sys",
        "from pathlib import Path",
        "blocked = ('astrid', 'reigh', 'runtime_protocol')",
        "class Deny:",
        "    def find_spec(self, fullname, path=None, target=None):",
        "        if any(fullname == item or fullname.startswith(item + '.') for item in blocked):",
        "            raise ImportError('boundary import denied')",
        "        return None",
        "sys.meta_path.insert(0, Deny())",
        "source = Path(sys.argv[1])",
        "spec = importlib.util.spec_from_file_location('neutral_source_reader', source)",
        "module = importlib.util.module_from_spec(spec)",
        "spec.loader.exec_module(module)",
        "assert module.manifest_to_transitions",
        "print('ok')",
    ])
    result = subprocess.run(
        [sys.executable, "-c", code, str(SOURCE_READERS)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "ok"


def test_timing_source_mapping_remains_available_without_product_imports(tmp_path: Path) -> None:
    manifest = {
        "transition_count": 2,
        "clock": {"fps": 24},
        "transitions": [
            {"frame": 0, "colour_name": "rose", "segment_id": "S01"},
            {"frame": 12, "colour_name": "teal", "segment_id": "S01"},
        ],
        "segments": [{"id": "S01", "transition_count": 2}],
    }
    audio = {"timebase": {"fps": 24, "range_end_frame": 24}}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    rows = manifest_to_transitions(manifest, audio)
    assert [row["ordinal"] for row in rows] == [0, 1]
    assert rows[0]["duration_ms"] == 500
    assert "complementary colour teal" in rows[0]["prompt"]
    assert "hold" in rows[1]["prompt"]


def test_normal_runtime_and_generated_client_imports_never_load_migrator() -> None:
    env = dict(os.environ)
    client_root = str(ROOT / "packages" / "python")
    env["PYTHONPATH"] = client_root + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import runtime_protocol; import banodoco_workspace_client; "
                "print([name for name in sys.modules if name.startswith('tools.astrid_migrate')])"
            ),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "[]"


def test_migrator_tree_has_no_checkout_or_dynamic_import_path_mutation() -> None:
    for path in (ROOT / "tools" / "astrid_migrate").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "sys.path" not in text, path
        assert "PYTHONPATH" not in text, path
        assert "importlib.import_module" not in text, path
        assert "__import__(" not in text, path
