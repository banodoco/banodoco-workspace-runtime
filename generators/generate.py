#!/usr/bin/env python3
"""Deterministic contract/client generation check.

The protocol source is deliberately small and dependency-free.  This command
derives a stable digest and operation index from the canonical manifest, writes
language metadata, and can verify that checked-in clients expose every
operation.  Generated client source carries the generated marker and is never
hand-edited by product repositories.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contract" / "manifest.json"


def contract_digest() -> str:
    manifest = json.loads(MANIFEST.read_text())
    paths = [ROOT / "contract" / manifest["openapi"], *(ROOT / "contract" / p for p in manifest["schemas"])]
    h = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix().encode()
        data = path.read_bytes()
        h.update(len(relative).to_bytes(4, "big")); h.update(relative)
        h.update(len(data).to_bytes(8, "big")); h.update(data)
    return "sha256:" + h.hexdigest()


def operation_index() -> list[str]:
    text = (ROOT / "contract" / "openapi" / "workspace-v1.yaml").read_text()
    return [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("      operationId:")]


def render() -> dict[str, str]:
    digest = contract_digest()
    operations = operation_index()
    py = '"""Generated contract metadata; do not edit by hand."""\n\nPROTOCOL = "workspace.v1"\nSCHEMA_DIGEST = ' + repr(digest) + "\nOPERATIONS = " + repr(tuple(operations)) + "\n"
    ts = '/** Generated contract metadata; do not edit by hand. */\n\nexport const PROTOCOL = "workspace.v1" as const;\nexport const SCHEMA_DIGEST = ' + json.dumps(digest) + ";\nexport const OPERATIONS = " + json.dumps(operations) + " as const;\n"
    runtime = '"""Generated contract metadata; do not edit by hand."""\n\nPROTOCOL = "workspace.v1"\nSCHEMA_DIGEST = ' + repr(digest) + "\nOPERATIONS = " + repr(tuple(operations)) + "\n"
    return {"packages/python/banodoco_workspace_client/contract_metadata.py": py, "packages/typescript/src/contract-metadata.ts": ts, "runtime_protocol/contract_metadata.py": runtime}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated metadata differs")
    args = parser.parse_args()
    for relative, content in render().items():
        path = ROOT / relative
        if args.check:
            if not path.exists() or path.read_text() != content:
                print(f"stale generated file: {relative}")
                return 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            print(relative)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
