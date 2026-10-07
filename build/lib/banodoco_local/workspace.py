"""Explicit create/attach/inspect configuration for the sole local workspace."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from typing import Any, Mapping

from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    RuntimeBoundary,
    _bootstrap_mutex,
    _commit_source_profile_metadata,
    _has_symlink_component,
    _new_realm_id,
    _read_catalog,
    _selected_realm,
    _validate_source_profile,
    _validate_support_paths,
)
from .paths import RuntimePaths


def _root(value: str | Path, *, must_exist: bool, empty: bool = False) -> Path:
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise BootstrapError("realm root must be an explicit absolute path")
    result = Path(os.path.abspath(raw))
    if _has_symlink_component(result) or result.is_symlink():
        raise BootstrapError("realm root must be symlink-free")
    if must_exist and not result.is_dir():
        raise BootstrapError(f"realm root is unavailable: {result}")
    if empty and result.exists() and (not result.is_dir() or any(result.iterdir())):
        raise BootstrapError("fresh realm root must be absent or an empty directory")
    return result.resolve()


def _opaque_realm_id(value: str | None, *, generate: bool) -> str:
    if value is None and generate:
        return _new_realm_id()
    candidate = "" if value is None else str(value)
    if (
        not candidate
        or len(candidate.encode("utf-8")) > 255
        or candidate != candidate.strip()
        or any(ch in candidate for ch in "/\\\x00\r\n")
    ):
        raise BootstrapError("realm id must be a non-empty bounded opaque identifier")
    return candidate


def _inspect(boundary: RuntimeBoundary, root: Path) -> tuple[str, dict[str, Any]]:
    inspect = getattr(boundary, "inspect", None)
    if not callable(inspect):
        raise BootstrapError("runtime boundary cannot inspect a canonical realm")
    report = inspect(realm_root=root)
    if not isinstance(report, Mapping):
        raise BootstrapError("runtime realm inspection returned invalid metadata")
    report = dict(report)
    identity = report.get("checks", {}).get("realm_identity", {})
    observed = str(identity.get("realm_id") or "") if isinstance(identity, Mapping) else ""
    if report.get("state") == "uninitialized" or not report.get("ok") or not identity.get("ok") or not observed:
        raise BootstrapError("realm root is not one healthy unambiguous canonical workspace")
    return observed, report


def inspect_workspace(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    *,
    realm_root: str | Path | None = None,
    expected_realm_id: str | None = None,
) -> dict[str, Any]:
    """Observe configured or candidate identity without creating support state."""
    _validate_support_paths(paths)
    configured = _selected_realm(_read_catalog(paths))
    if realm_root is None:
        if configured is None:
            return {"ok": False, "state": "workspace_missing", "effects": ["observe"]}
        root = _root(str(configured["data_root"]), must_exist=True)
        expected = str(configured["realm_id"])
    else:
        root = _root(realm_root, must_exist=True)
        expected = (
            _opaque_realm_id(expected_realm_id, generate=False)
            if expected_realm_id is not None
            else None
        )
    observed, report = _inspect(boundary, root)
    if expected is not None and observed != expected:
        raise BootstrapError(f"workspace identity mismatch: expected {expected}, observed {observed}")
    if configured is not None and realm_root is not None:
        if observed != str(configured["realm_id"]) or root != Path(str(configured["data_root"])):
            raise BootstrapError("candidate conflicts with the configured workspace")
    return {
        "ok": True,
        "state": "configured" if configured is not None else "inspectable",
        "realm_id": observed,
        "realm_root": str(root),
        "effects": ["observe"],
        "inspection": report,
    }


def configure_workspace(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    config: BootstrapConfig,
    *,
    mode: str,
    realm_root: str | Path,
    realm_id: str | None,
) -> dict[str, Any]:
    """Explicitly create or attach and select exactly one canonical realm."""
    if mode not in {"create", "attach"}:
        raise ValueError("workspace mode must be create or attach")
    _validate_support_paths(paths)
    source = config.resolve_source_profile(paths)
    _validate_source_profile(source, expected_profile=config.profile)
    root = _root(realm_root, must_exist=(mode == "attach"))
    requested = _opaque_realm_id(realm_id, generate=(mode == "create"))
    if mode == "attach":
        observed, _ = _inspect(boundary, root)
        if observed != requested:
            raise BootstrapError(f"workspace identity mismatch: expected {requested}, observed {observed}")

    with _bootstrap_mutex(paths):
        paths.ensure_support_dirs()
        existing = _selected_realm(_read_catalog(paths))
        if existing is not None:
            if str(existing["realm_id"]) != requested or Path(str(existing["data_root"])) != root:
                raise BootstrapError("workspace selection conflicts with the configured identity")
            observed, _ = _inspect(boundary, root)
            if observed != requested:
                raise BootstrapError("configured workspace identity does not match its canonical realm")
            return {"ok": True, "status": "unchanged", "realm_id": requested, "realm_root": str(root)}

        created_here = False
        try:
            if mode == "create":
                _root(root, must_exist=False, empty=True)
                created = boundary.create(
                    realm_id=requested,
                    realm_root=root,
                    display_name=config.display_name,
                    source_profile=source,
                )
                if not isinstance(created, Mapping) or str(created.get("realm_id")) != requested:
                    raise BootstrapError("runtime realm creation returned mismatched identity")
                created_here = True
            observed, _ = _inspect(boundary, root)
            if observed != requested:
                raise BootstrapError(f"workspace identity mismatch: expected {requested}, observed {observed}")
            catalog = {
                "version": 1,
                "selected_realm_id": requested,
                "realms": [{
                    "realm_id": requested,
                    "display_name": config.display_name,
                    "data_root": str(root),
                    "selection_source": mode,
                    "source_profile": source.profile,
                }],
                "source_profiles": {source.profile: source.as_dict()},
            }
            _commit_source_profile_metadata(paths, source, catalog)
        except Exception:
            if created_here and root.is_dir() and not root.is_symlink():
                shutil.rmtree(root)
            raise
    return {
        "ok": True,
        "status": f"configured_{mode}",
        "realm_id": requested,
        "realm_root": str(root),
        "next_action": "astrid-runtime up",
    }


__all__ = ["configure_workspace", "inspect_workspace"]
