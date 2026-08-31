from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import shutil


def test_typescript_conformance_generator_is_byte_stable(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    script = root / "tools" / "generate_typescript_conformance.mjs"
    contract = root / "contract" / "openapi" / "workspace-v1.yaml"
    schema = root / "contract" / "manifest.json"
    component = root / "contract" / "component-manifest.json"
    first, second = tmp_path / "first", tmp_path / "second"
    command = ["node", str(script), "--contract", str(contract), "--schema-manifest", str(schema), "--component-manifest", str(component)]
    subprocess.run([*command, "--output-root", str(first)], check=True)
    subprocess.run([*command, "--output-root", str(second)], check=True)
    def inventory(path: Path) -> dict[str, str]:
        return {item.relative_to(path).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest() for item in path.rglob("*") if item.is_file()}
    assert inventory(first) == inventory(second)
    manifest = json.loads((first / "manifest.json").read_text())
    assert manifest["generator"] == "GENERATOR-TYPESCRIPT-CONFORMANCE"
    assert manifest["component_manifest_id"] == "GENERATOR-CONFORMANCE-ID"
    client_source = (first / "generated.ts").read_text()
    assert "class WorkspaceClient" in client_source
    assert "async call(" in client_source
    assert "Authorization" in client_source
    assert (first / "fixture-handshake.json").read_bytes() == (root / "conformance" / "fixtures" / "handshake.json").read_bytes()
    check = [*command, "--check", "--source-root", str(root), "--fixture-root", str(root / "conformance" / "fixtures")]
    assert subprocess.run(check, capture_output=True, text=True).returncode == 0
    assert manifest["operations"]


def test_typescript_generator_check_rejects_client_and_manifest_mutation(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    script = root / "tools" / "generate_typescript_conformance.mjs"
    contract = root / "contract" / "openapi" / "workspace-v1.yaml"
    schema = root / "contract" / "manifest.json"
    component = root / "contract" / "component-manifest.json"
    source = tmp_path / "source"
    (source / "clients" / "typescript").mkdir(parents=True)
    shutil.copyfile(root / "clients" / "typescript" / "generated.ts", source / "clients" / "typescript" / "generated.ts")
    shutil.copyfile(root / "clients" / "typescript" / "contract-metadata.ts", source / "clients" / "typescript" / "contract-metadata.ts")
    check = ["node", str(script), "--contract", str(contract), "--schema-manifest", str(schema), "--component-manifest", str(component), "--check", "--source-root", str(source)]
    assert subprocess.run(check, capture_output=True, text=True).returncode == 0
    client = source / "clients" / "typescript" / "generated.ts"
    client.write_text(client.read_text() + "// mutation\n")
    assert subprocess.run(check, capture_output=True, text=True).returncode != 0
    shutil.copyfile(root / "clients" / "typescript" / "generated.ts", client)
    changed = json.loads(component.read_text())
    changed["fixtures"][0]["value"]["sequence"] = 2
    mutated_component = tmp_path / "component-manifest.json"
    mutated_component.write_text(json.dumps(changed, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    changed_check = ["node", str(script), "--contract", str(contract), "--schema-manifest", str(schema), "--component-manifest", str(mutated_component), "--check", "--source-root", str(source)]
    assert subprocess.run(changed_check, capture_output=True, text=True).returncode != 0
