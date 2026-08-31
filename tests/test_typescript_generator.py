from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess


def test_typescript_conformance_generator_is_byte_stable(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    script = root / "tools" / "generate_typescript_conformance.mjs"
    contract = root / "contract" / "openapi" / "workspace-v1.yaml"
    schema = root / "contract" / "manifest.json"
    first, second = tmp_path / "first", tmp_path / "second"
    command = ["node", str(script), "--contract", str(contract), "--schema-manifest", str(schema)]
    subprocess.run([*command, "--output-root", str(first)], check=True)
    subprocess.run([*command, "--output-root", str(second)], check=True)
    def inventory(path: Path) -> dict[str, str]:
        return {item.relative_to(path).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest() for item in path.rglob("*") if item.is_file()}
    assert inventory(first) == inventory(second)
    manifest = json.loads((first / "manifest.json").read_text())
    assert manifest["generator"] == "GENERATOR-TYPESCRIPT-CONFORMANCE"
    assert manifest["operations"]
