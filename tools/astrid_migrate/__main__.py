from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .migrator import MigrationConfig, MigrationError, migrate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="astrid-migrate", description="Offline Astrid-to-workspace migration")
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--archive-root", required=True, type=Path)
    parser.add_argument("--destination-root", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--runtime-endpoint")
    parser.add_argument("--credential-file", type=Path)
    args = parser.parse_args(argv)
    client = None
    if args.runtime_endpoint:
        if not args.credential_file:
            parser.error("--credential-file is required with --runtime-endpoint")
        client_root = Path(__file__).parents[2] / "packages" / "python"
        sys.path.insert(0, str(client_root))
        from banodoco_workspace_client import WorkspaceClient
        client = WorkspaceClient(args.runtime_endpoint, args.credential_file.read_text(encoding="utf-8").strip())
    try:
        report = migrate(MigrationConfig(args.source_root, args.archive_root, args.destination_root, dry_run=args.dry_run), client)
    except MigrationError as exc:
        print(json.dumps({"ok": False, "error": str(exc), "source_untouched": True}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, **report}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
