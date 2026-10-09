"""Explicit one-workspace configuration for the local Runtime composition.

This module owns only launcher/catalog selection.  Canonical realm identity
and validation remain Runtime responsibilities behind ``RuntimeBoundary``.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import uuid
from typing import Any, Mapping

from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    RuntimeBoundary,
    _bootstrap_mutex,
    _commit_source_profile_metadata,
    _has_symlink_component,
    _read_catalog,
    _selected_realm,
    _validate_source_profile,
    _validate_support_paths,
)
from .paths import RuntimePaths


WORKSPACE_EFFECTS = {
    "inspect": ["observe"],
    "create": ["configure-install", "write-relocate-change-data"],
    "attach": ["configure-install", "write-relocate-change-data"],
}


def _absolute_root(value: str | Path, label: str, *, must_exist: bool, allow_populated: bool = False) -> Path:
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise BootstrapError(f"{label} must be an explicit absolute path")
    path = Path(os.path.abspath(raw))
    if _has_symlink_component(path) or path.is_symlink():
        raise BootstrapError(f"{label} must be symlink-free")
    if must_exist and (not path.is_dir() or path.is_symlink()):
        raise BootstrapError(f"{label} is unavailable: {path}")
    if not must_exist and path.exists() and (path.is_symlink() or not path.is_dir() or (not allow_populated and any(path.iterdir()))):
        raise BootstrapError(f"{label} must be absent or an empty regular directory: {path}")
    return path


def _realm_id(value: str | None, *, generate: bool) -> str:
    candidate = str(value or (uuid.uuid4() if generate else ""))
    try:
        uuid.UUID(candidate)
    except (ValueError, AttributeError) as exc:
        raise BootstrapError("workspace realm id must be a UUID") from exc
    return candidate


def _inspection_identity(report: Mapping[str, Any]) -> str:
    if report.get("state") == "uninitialized":
        raise BootstrapError("realm root contains no canonical workspace")
    identity = report.get("checks", {}).get("realm_identity", {})
    realm_id = str(identity.get("realm_id") or "") if isinstance(identity, Mapping) else ""
    if not report.get("ok") or not identity.get("ok") or not realm_id:
        raise BootstrapError("realm root is not one healthy unambiguous canonical workspace")
    return realm_id


def _inspect_boundary(boundary: RuntimeBoundary, root: Path) -> dict[str, Any]:
    inspect = getattr(boundary, "inspect", None)
    if not callable(inspect):
        raise BootstrapError("runtime boundary cannot inspect a canonical realm")
    report = inspect(realm_root=root)
    if not isinstance(report, Mapping):
        raise BootstrapError("runtime realm inspection returned invalid metadata")
    return dict(report)


def inspect_workspace(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    *,
    realm_root: str | Path | None = None,
    expected_realm_id: str | None = None,
) -> dict[str, Any]:
    """Inspect a configured or candidate realm without creating support state."""

    _validate_support_paths(paths)
    catalog = _read_catalog(paths)
    configured = _selected_realm(catalog)
    if realm_root is None:
        if configured is None:
            return {
                "ok": False,
                "state": "workspace_missing",
                "problem_code": "workspace_missing",
                "support_root": str(paths.app_support),
                "effects": WORKSPACE_EFFECTS["inspect"],
                "authorization_required": False,
            }
        root = _absolute_root(str(configured["data_root"]), "configured realm root", must_exist=True)
        expected = str(configured["realm_id"])
        selection_source = str(configured.get("selection_source") or "catalog")
    else:
        root = _absolute_root(realm_root, "realm root", must_exist=True)
        expected = _realm_id(expected_realm_id, generate=False) if expected_realm_id else None
        selection_source = "candidate"
    report = _inspect_boundary(boundary, root)
    observed = _inspection_identity(report)
    if expected is not None and observed != expected:
        raise BootstrapError(
            f"workspace identity mismatch: expected {expected}, observed {observed}"
        )
    if configured is not None and realm_root is not None:
        same = observed == str(configured["realm_id"]) and root == Path(str(configured["data_root"]))
        if not same:
            raise BootstrapError("candidate conflicts with the sole configured workspace")
        selection_source = str(configured.get("selection_source") or "catalog")
    return {
        "ok": True,
        "state": "configured" if configured is not None else "inspectable",
        "realm_id": observed,
        "realm_root": str(root),
        "support_root": str(paths.app_support),
        "selection_source": selection_source,
        "effects": WORKSPACE_EFFECTS["inspect"],
        "authorization_required": False,
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
    """Create or attach exactly one canonical realm and commit its selection."""

    if mode not in {"create", "attach"}:
        raise ValueError("workspace mode must be create or attach")
    _validate_support_paths(paths)
    source = config.resolve_source_profile(paths)
    _validate_source_profile(source, expected_profile=config.profile)
    # Permit a populated Create path only long enough to compare it with an
    # existing catalog selection; a genuinely new Create is checked again
    # below before Runtime is allowed to write it.
    root = _absolute_root(
        realm_root, "realm root", must_exist=(mode == "attach"),
        allow_populated=(mode == "create"),
    )
    requested_id = _realm_id(realm_id, generate=(mode == "create"))
    if mode == "attach":
        # Reject missing/wrong/ambiguous candidates before creating launcher
        # support directories or lock files. Repeated inspection inside the
        # mutex below closes the apply-time change window.
        observed = _inspection_identity(_inspect_boundary(boundary, root))
        if observed != requested_id:
            raise BootstrapError(
                f"workspace identity mismatch: expected {requested_id}, observed {observed}"
            )

    with _bootstrap_mutex(paths):
        paths.ensure_support_dirs()
        catalog = _read_catalog(paths)
        existing = _selected_realm(catalog)
        if existing is not None:
            existing_root = Path(str(existing["data_root"]))
            if str(existing["realm_id"]) != requested_id or existing_root != root:
                raise BootstrapError("workspace selection conflicts with the existing configured identity")
            observed = _inspection_identity(_inspect_boundary(boundary, root))
            if observed != requested_id:
                raise BootstrapError("configured workspace identity does not match its canonical realm")
            return {
                "ok": True,
                "status": "unchanged",
                "state": "workspace_configured_runtime_not_ready",
                "realm_id": requested_id,
                "realm_root": str(root),
                "support_root": str(paths.app_support),
                "selection_source": str(existing.get("selection_source") or mode),
                "effects": WORKSPACE_EFFECTS[mode],
                "authorization_required": True,
                "next_action": "astrid-runtime up",
            }

        created_here = False
        if mode == "create":
            _absolute_root(root, "realm root", must_exist=False)
            create = getattr(boundary, "create", None)
            if not callable(create):
                raise BootstrapError("runtime boundary cannot explicitly create a canonical realm")
            created = create(
                realm_id=requested_id,
                realm_root=root,
                display_name=config.display_name,
                source_profile=source,
            )
            if not isinstance(created, Mapping) or created.get("state") != "created" or str(created.get("realm_id")) != requested_id:
                raise BootstrapError("runtime realm creation returned incomplete or mismatched identity")
            created_here = True
        try:
            report = _inspect_boundary(boundary, root)
            observed = _inspection_identity(report)
            if observed != requested_id:
                raise BootstrapError(
                    f"workspace identity mismatch: expected {requested_id}, observed {observed}"
                )

            row = {
                "realm_id": requested_id,
                "display_name": config.display_name,
                "data_root": str(root),
                "selection_source": mode,
                "source_profile": source.profile,
                "readiness": "not_ready",
                "readiness_reason": "workspace_configured_runtime_not_ready",
            }
            catalog = {
                "version": 1,
                "selected_realm_id": requested_id,
                "realms": [row],
                "source_profiles": {source.profile: source.as_dict()},
            }
            _commit_source_profile_metadata(paths, source, catalog)
        except Exception:
            # This is the sole pre-selection orphan window. Remove only the
            # exact fresh root created by this invocation; Attach and any
            # previously configured realm are never cleanup targets.
            if created_here and root.is_dir() and not root.is_symlink():
                shutil.rmtree(root)
            raise
        return {
            "ok": True,
            "status": f"configured_{mode}",
            "state": "workspace_configured_runtime_not_ready",
            "realm_id": requested_id,
            "realm_root": str(root),
            "support_root": str(paths.app_support),
            "selection_source": mode,
            "effects": WORKSPACE_EFFECTS[mode],
            "authorization_required": True,
            "next_action": "astrid-runtime up",
        }


__all__ = ["WORKSPACE_EFFECTS", "configure_workspace", "inspect_workspace"]
