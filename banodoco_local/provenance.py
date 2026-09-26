"""Bounded installed identity for the canonical local operator."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .bootstrap import _read_catalog, _validate_support_paths
from .compatibility import resolve_environment
from .paths import RuntimePaths


IMPLEMENTATION_OWNER = "banodoco_local.cli:main"
PROVENANCE_SCHEMA = "astrid-local-provenance-v1"
_RECEIPT_FIELDS = (
    "mode",
    "profile",
    "runtime_module",
    "runtime_module_origin",
    "runtime_artifact_sha256",
    "runtime_distribution_version",
    "source_digest",
    "capability_digest",
    "selected_realm_id",
)


def _module_origin() -> Path:
    spec = importlib.util.find_spec("banodoco_local.cli")
    if spec is None or not spec.origin:
        raise RuntimeError("banodoco_local.cli module origin is unavailable")
    return Path(spec.origin).expanduser().resolve(strict=True)


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _receipt(path_value: str) -> dict[str, Any]:
    if not path_value:
        return {}
    path = Path(path_value).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        return {"source_manifest_path": str(path)}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {"source_manifest_path": str(path), "source_manifest_sha256": _sha256(path)}
    result: dict[str, Any] = {
        "source_manifest_path": str(path),
        "source_manifest_sha256": _sha256(path),
    }
    if isinstance(raw, Mapping):
        for key in _RECEIPT_FIELDS:
            if key in raw and isinstance(raw[key], (str, int, float, bool)):
                result[key] = raw[key]
    return result


def identity(*, command_alias: str = "astrid-local") -> dict[str, Any]:
    """Return a JSON-safe identity shared by canonical and legacy aliases.

    The optional source manifest is an inert provenance receipt.  It cannot
    redirect imports or lifecycle ownership; X2 remains responsible for
    validating the receipt before launch.
    """

    origin = _module_origin()
    env = resolve_environment()
    data_root = env.values.get("ASTRID_LOCAL_DATA_ROOT")
    home = env.values.get("ASTRID_LOCAL_HOME")
    manifest = env.values.get("ASTRID_LOCAL_SOURCE_MANIFEST")
    paths = RuntimePaths.current_mac(home or None, data_root=data_root or None)
    _validate_support_paths(paths)
    catalog = _read_catalog(paths)
    receipt = _receipt(manifest)
    try:
        distribution_version = importlib.metadata.version("banodoco-workspace-runtime")
    except importlib.metadata.PackageNotFoundError:
        distribution_version = __version__
    return {
        "schema": PROVENANCE_SCHEMA,
        "command_alias": command_alias,
        "deprecated": command_alias in {"banodoco-local", "astrid-runtime"},
        "deprecation_target": "astrid-local" if command_alias != "astrid-local" else None,
        "implementation_owner": IMPLEMENTATION_OWNER,
        "module_origin": str(origin),
        "artifact_sha256": _sha256(origin),
        "distribution": "banodoco-workspace-runtime",
        "distribution_version": distribution_version,
        "package_version": __version__,
        "support_root": str(paths.app_support),
        "realm_id": catalog.get("selected_realm_id"),
        "receipt": receipt,
    }
