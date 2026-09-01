"""Explicit runtime bridge for the opt-in Astrid live migration command.

The offline migrator remains importable without the product runtime.  This
module is deliberately outside ``tools.astrid_migrate`` and is imported only
by the live operator entrypoint (or by callers that explicitly invoke that
entrypoint's live operation).
"""

from __future__ import annotations

from pathlib import Path

from runtime_protocol.service import RuntimeService


def open_runtime(
    active_root: str | Path,
    *,
    display_name: str,
    realm_id: str,
    support_root: str | Path,
) -> RuntimeService:
    """Construct the selected runtime for the explicit live bridge."""

    return RuntimeService(
        active_root,
        display_name=display_name,
        realm_id=realm_id,
        support_root=support_root,
    )


__all__ = ["open_runtime"]
