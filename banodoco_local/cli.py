"""The intentionally thin ``banodoco-local`` command surface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .bootstrap import BootstrapConfig, BootstrapError, SourceProfile, bootstrap, doctor
from .paths import RuntimePaths
from .runtime_boundary import LocalRuntimeBoundary


class UnconfiguredBoundary:
    """Prevent accidental authority creation when no generated client is wired."""

    def start(self, **kwargs):
        raise BootstrapError("No runtime client is configured. Set BANODOCO_LOCAL_SOURCE_MANIFEST and provide the runtime client.")

    def connect(self, **kwargs):
        raise BootstrapError("No runtime client is configured.")

    def health(self, **kwargs):
        return False

    def validate_owner(self, **kwargs):
        return False

    def is_pid_alive(self, pid):
        return False


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="banodoco-local", description="Neutral Banodoco local workspace bootstrap")
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command")
    up = sub.add_parser("up", help="start or reconnect the selected runtime")
    up.add_argument("--profile", default="astrid", choices=["astrid"])
    up.add_argument("--display-name", default="Astrid Workspace")
    up.add_argument("--source-manifest", type=Path)
    doc = sub.add_parser("doctor", help="read-only support-state diagnostics")
    doc.add_argument("--json", action="store_true")
    doc.add_argument("--profile", default="astrid", choices=["astrid"])
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    paths = RuntimePaths.current_mac()
    if args.command == "doctor":
        result = doctor(paths)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("healthy" if result["healthy"] else "unhealthy")
            for issue in result["issues"]:
                print(f"- {issue}")
        return 0 if result["healthy"] else 1
    if args.command == "up":
        manifest = args.source_manifest
        if manifest is None:
            configured = __import__("os").environ.get("BANODOCO_LOCAL_SOURCE_MANIFEST")
            manifest = Path(configured) if configured else None
        config = BootstrapConfig(profile=args.profile, display_name=args.display_name, source_manifest=manifest)
        try:
            result = bootstrap(paths, LocalRuntimeBoundary(), config)
        except BootstrapError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"{result.status}: realm {result.realm_id} ({result.endpoint})")
        return 0
    parser().print_help()
    return 0
