"""Compatibility names for the Astrid local operator surface.

The Runtime package remains the only owner of local lifecycle state.  This
module only translates environment names from the Banodoco Local migration
period into the canonical Astrid names before the existing CLI sees them.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sys
from typing import Mapping, MutableMapping


class EnvironmentMigrationError(ValueError):
    """A canonical and legacy setting disagree or violates a path contract."""


# The canonical names are deliberately scoped to the local operator.  The
# legacy names remain readable for the migration window and are never allowed
# to select a second implementation or support root.
ENVIRONMENT_ALIASES: dict[str, str] = {
    "ASTRID_LOCAL_DATA_ROOT": "BANODOCO_LOCAL_DATA_ROOT",
    "ASTRID_LOCAL_HOME": "BANODOCO_LOCAL_HOME",
    "ASTRID_LOCAL_SOURCE_MANIFEST": "BANODOCO_LOCAL_SOURCE_MANIFEST",
    "ASTRID_LOCAL_LAUNCHER": "BANODOCO_LOCAL_LAUNCHER",
    "ASTRID_LOCAL_ENABLE_REAL_REBOOT": "BANODOCO_LOCAL_ENABLE_REAL_REBOOT",
    "ASTRID_RUNTIME_ADMISSION_TIMEOUT_SECONDS": "BANODOCO_RUNTIME_ADMISSION_TIMEOUT_SECONDS",
    "ASTRID_LOCAL_CLI": "ASTRID_RUNTIME_CLI",
    "ASTRID_RUNTIME_ENDPOINT": "BANODOCO_RUNTIME_ENDPOINT",
    "ASTRID_RUNTIME_CREDENTIAL": "BANODOCO_RUNTIME_CREDENTIAL",
}

_EMITTED_WARNINGS: set[str] = set()


@dataclass(frozen=True)
class EnvironmentResolution:
    """Resolved canonical values and compatibility warnings."""

    values: dict[str, str]
    warnings: tuple[str, ...]


def resolve_environment(
    environ: Mapping[str, str] | None = None,
) -> EnvironmentResolution:
    """Resolve canonical variables without adopting the current directory.

    A conflicting pair fails closed.  A legacy-only value is accepted and is
    reported so callers can show one explicit deprecation warning.  Empty
    values are treated as unset, matching the existing CLI's behavior.
    """

    source = os.environ if environ is None else environ
    values: dict[str, str] = {}
    warnings: list[str] = []
    for canonical, legacy in ENVIRONMENT_ALIASES.items():
        canonical_value = str(source.get(canonical, "") or "")
        legacy_value = str(source.get(legacy, "") or "")
        if canonical_value and legacy_value and canonical_value != legacy_value:
            raise EnvironmentMigrationError(
                f"conflicting environment values for {canonical} and {legacy}"
            )
        value = canonical_value or legacy_value
        if value:
            if canonical.endswith(("_DATA_ROOT", "_HOME", "_SOURCE_MANIFEST")):
                if not Path(value).expanduser().is_absolute():
                    raise EnvironmentMigrationError(
                        f"{canonical} must be an absolute path"
                    )
            values[canonical] = value
        if legacy_value and not canonical_value:
            warnings.append(
                f"{legacy} is deprecated; use {canonical} instead"
            )
    return EnvironmentResolution(values=values, warnings=tuple(warnings))


def apply_legacy_environment(
    environ: MutableMapping[str, str] | None = None,
) -> EnvironmentResolution:
    """Resolve migration names and feed canonical values to the old CLI.

    Existing Runtime code still reads the legacy names.  Setting those names
    in this process keeps one implementation while allowing new installations
    to use the canonical variables.  No process-global environment is changed
    when an explicit mapping is supplied.
    """

    target = os.environ if environ is None else environ
    resolution = resolve_environment(target)
    for canonical, legacy in ENVIRONMENT_ALIASES.items():
        value = resolution.values.get(canonical)
        if value:
            target[legacy] = value
    return resolution


def emit_environment_warnings(
    resolution: EnvironmentResolution | None = None,
) -> None:
    """Print each migration warning at most once per process."""

    current = resolution or resolve_environment()
    for warning in current.warnings:
        if warning in _EMITTED_WARNINGS:
            continue
        print(f"astrid-local: warning: {warning}", file=sys.stderr)
        _EMITTED_WARNINGS.add(warning)


def canonical_value(
    name: str,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Read a canonical setting through the same migration resolver."""

    canonical = name
    if name in ENVIRONMENT_ALIASES.values():
        canonical = next(key for key, value in ENVIRONMENT_ALIASES.items() if value == name)
    resolution = resolve_environment(environ)
    emit_environment_warnings(resolution)
    return resolution.values.get(canonical, "")


def canonical_environment_names() -> tuple[str, ...]:
    """Return the stable ordered canonical environment contract."""

    return tuple(ENVIRONMENT_ALIASES)
