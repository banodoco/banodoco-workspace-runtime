"""Console entrypoints for Astrid Local and migration aliases."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Sequence

from .cli import main as cli_main
from .compatibility import apply_legacy_environment, emit_environment_warnings
from .provenance import identity


CANONICAL_COMMAND = "astrid-local"
LEGACY_COMMANDS = frozenset({"banodoco-local", "astrid-runtime"})


def _command_name() -> str:
    name = Path(sys.argv[0]).name
    if name in {"__main__.py", "entrypoint.py"}:
        return CANONICAL_COMMAND
    return name


def main(argv: Sequence[str] | None = None) -> int:
    command = _command_name()
    resolution = apply_legacy_environment()
    emit_environment_warnings(resolution)
    if command in LEGACY_COMMANDS:
        print(
            f"{command}: deprecated; use {CANONICAL_COMMAND} instead",
            file=sys.stderr,
        )
    args = list(argv) if argv is not None else list(sys.argv[1:])
    if args == ["--provenance"]:
        print(json.dumps(identity(command_alias=command), sort_keys=True))
        return 0
    return cli_main(args)
