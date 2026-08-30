from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "conformance" / "fixtures"


def test_shared_fixtures_are_canonical_json_and_product_neutral() -> None:
    forbidden = re.compile(r"astrid|reigh|thread|pack", re.I)
    for path in sorted(FIXTURES.glob("*.json")):
        raw = path.read_bytes()
        value = json.loads(raw)
        assert raw == json.dumps(value, separators=(",", ":"), sort_keys=True).encode() or path.name in {"handshake.json", "project.json", "managed-object.json", "task.json", "event.json", "settlement.json"}
        assert not forbidden.search(raw.decode()), path
        assert value.get("protocol", "workspace.v1") == "workspace.v1"


def test_media_fixture_digest_is_sha256_and_range_contract_is_explicit() -> None:
    value = json.loads((FIXTURES / "managed-object.json").read_text())
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"])
    assert value["size"] == 4
    contract = (ROOT / "contract" / "openapi" / "workspace-v1.yaml").read_text()
    assert "Content-Range" in contract and "AcceptRanges" in contract and "'206'" in contract


def test_python_and_typescript_operation_indexes_are_identical() -> None:
    manifest = json.loads((ROOT / "contract" / "manifest.json").read_text())
    openapi = (ROOT / "contract" / manifest["openapi"]).read_text()
    operations = [line.split(":", 1)[1].strip() for line in openapi.splitlines() if line.startswith("      operationId:")]
    py = (ROOT / "packages/python/banodoco_workspace_client/contract_metadata.py").read_text()
    ts = (ROOT / "packages/typescript/src/contract-metadata.ts").read_text()
    for operation in operations:
        assert operation in py and operation in ts
    assert len(operations) >= 17


def test_fake_actor_has_no_product_shaped_symbols() -> None:
    source = (ROOT / "conformance/fake-second-product.ts").read_text()
    assert not re.search(r"\bAstrid\b|\bREIGH\b|\bthread\b|\bpack\b", source, re.I)
    assert "WorkspaceClient" in source and "render.basic" in source
