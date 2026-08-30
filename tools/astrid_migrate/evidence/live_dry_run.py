"""Capture a redacted, read-only T5 rehearsal for the documented live source."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from ..migrator import MigrationConfig, MigrationError, Migrator


def _redact(value, source: Path):
    if isinstance(value, dict):
        return {key: _redact(item, source) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, source) for item in value]
    if isinstance(value, str):
        text = value.replace(str(source), "<documented-astrid-projects-root>")
        return text.replace(str(source.parent), "<documented-astrid-parent>")
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path("/Users/peteromalley/Documents/reigh-workspace/Astrid-live-main/projects"))
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("live-dry-run.json"))
    args = parser.parse_args(argv)
    source = args.source_root.expanduser().resolve()
    # These paths are intentionally unused in dry-run mode; keeping them
    # outside the source makes accidental mode changes fail closed.
    config = MigrationConfig(source, source.parent.parent / ".astrid-t5-archive-disabled", source.parent.parent / ".astrid-t5-destination-disabled", dry_run=True)
    result = {"mode": "dry-run", "archive_import_activation": "disabled", "source_reference": "Astrid-live-main/projects", "source_root": str(source)}
    try:
        report = Migrator(config).migrate()
        result["ok"] = bool(report.get("reconciliation", {}).get("ok", False))
        result["report"] = report
    except MigrationError as exc:
        result.update({"ok": False, "error": str(exc), "source_untouched": True})
    result = _redact(result, source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": result["ok"], "output": str(args.output), "mode": "dry-run"}, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
