from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "packages" / "python"))
from banodoco_workspace_client.generated import OPERATIONS as PYTHON_OPERATIONS  # noqa: E402
from banodoco_workspace_client.generated import PROTOCOL as PYTHON_PROTOCOL  # noqa: E402
from banodoco_workspace_client.generated import SCHEMA_DIGEST as PYTHON_SCHEMA_DIGEST  # noqa: E402


def _operation_ids() -> list[str]:
    return [
        line.split(":", 1)[1].strip()
        for line in (ROOT / "contract" / "openapi" / "workspace-v1.yaml").read_text().splitlines()
        if re.match(r"^\s+operationId:", line)
    ]


def _typescript_operations() -> list[str]:
    source = (ROOT / "packages" / "typescript" / "src" / "contract-metadata.ts").read_text()
    match = re.search(r"^export const OPERATIONS = (\[.*\]) as const;$", source, re.MULTILINE)
    assert match, "TypeScript contract metadata must export generated operations"
    return json.loads(match.group(1))


def _python_methods() -> set[str]:
    source = (ROOT / "packages" / "python" / "banodoco_workspace_client" / "generated.py").read_text()
    module = ast.parse(source)
    client = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "WorkspaceClient")
    return {
        node.name
        for node in client.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    }


def _snake_case(operation: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", operation).lower()


def test_product_clients_match_canonical_contract_projection() -> None:
    manifest = json.loads((ROOT / "contract" / "manifest.json").read_text())
    component = json.loads((ROOT / "contract" / "component-manifest.json").read_text())
    typescript_source = (ROOT / "packages" / "typescript" / "src" / "generated.ts").read_text()
    typescript_methods = set(re.findall(r"^  async (\w+)\(", typescript_source, re.MULTILINE))
    operation_ids = _operation_ids()

    assert manifest["protocol"] == component["protocol"] == "workspace.v1"
    assert manifest["generated"]["python"] == "packages/python/banodoco_workspace_client/generated.py"
    assert manifest["generated"]["typescript"] == "packages/typescript/src/generated.ts"
    assert list(PYTHON_OPERATIONS) == operation_ids
    assert _typescript_operations() == operation_ids
    # The product-facing clients retain one typed composition helper for the
    # cold-launch timeline save journey. It is implemented in terms of the
    # canonical document/timeline operations and is not an extra wire route.
    assert _python_methods() - {_snake_case(operation) for operation in operation_ids} == {
        "update_timeline_document"
    }
    assert typescript_methods - set(operation_ids) == {"updateTimelineDocument"}

    component_digest = "sha256:" + hashlib.sha256((ROOT / "contract" / "component-manifest.json").read_bytes()).hexdigest()
    from generators.generate import contract_digest

    contract_digest_value = contract_digest()
    typescript_metadata = (ROOT / "packages" / "typescript" / "src" / "contract-metadata.ts").read_text()
    assert PYTHON_PROTOCOL == "workspace.v1"
    assert PYTHON_SCHEMA_DIGEST == contract_digest_value
    assert f'COMPONENT_MANIFEST_SHA256 = "{component_digest}"' in typescript_metadata
    assert f'SCHEMA_DIGEST = "{contract_digest_value}"' in typescript_metadata
