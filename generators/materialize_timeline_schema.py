"""Materialize the pinned canonical TimelineConfig schema for Runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT.parent.parent / "banodoco-workspace" / "packages" / "timeline-schema"
PIN = "242f9c4306bf3b501222cb041a9eb246ef47bc85"
SCHEMA_RELATIVE = Path("python/banodoco_timeline_schema/timeline.schema.json")
OUTPUT = ROOT / "contract/schemas/timeline-config.schema.json"
PROVENANCE = ROOT / "contract/schemas/timeline-config.schema.provenance.json"
EXPECTED_SHA256 = "5592a6bb4376b9b9b84d66897b17f058eed5f0176d3c9ead262e19283fc86f25"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--source", type=Path, default=Path(os.environ.get("BANODOCO_TIMELINE_SCHEMA_ROOT", DEFAULT_SOURCE)))
    args = parser.parse_args()
    source = args.source.resolve()
    schema_source = source / SCHEMA_RELATIVE
    manifest = {
        "owner": "@banodoco/timeline-schema#TimelineConfig",
        "package": "@banodoco/timeline-schema",
        "version": "0.0.2",
        "source_commit": PIN,
        "source_tree": "75a5a697f630affee40632e500b3f5b704a9b834",
        "source_artifact": str(SCHEMA_RELATIVE),
        "sha256": EXPECTED_SHA256,
    }
    if not schema_source.is_file() or sha256(schema_source) != EXPECTED_SHA256:
        raise SystemExit(f"canonical schema artifact missing or differs from pinned {PIN}: {schema_source}")
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != schema_source.read_bytes():
            raise SystemExit("Runtime TimelineConfig materialization is stale; rerun this generator")
        if not PROVENANCE.is_file() or json.loads(PROVENANCE.read_text()) != manifest:
            raise SystemExit("Runtime TimelineConfig provenance is stale; rerun this generator")
        print(f"canonical TimelineConfig materialization clean: {PIN} sha256:{EXPECTED_SHA256}")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(schema_source, OUTPUT)
    PROVENANCE.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"materialized {OUTPUT.relative_to(ROOT)} from {PIN} sha256:{EXPECTED_SHA256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
