"""Read-only audit helpers for the canonical timeline cutover.

The audit deliberately reads the active parent-composition head and then uses
the same immutable closure inspector as the public ``inspectTimeline`` route.
It never treats the mutable timeline document as a read authority and never
writes the realm.  The legacy document is reported only as migration evidence
so that its bytes can remain available for recovery while its public serving
path is retired.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .errors import RuntimeErrorBase
from .timeline_inspection import inspect as inspect_timeline


AUDIT_SCHEMA = "runtime.timeline.active-head-audit/v1"
_PAGE_LIMIT = 100
_MAX_PAGES = 20


def _legacy_document(connection, project_id: str, timeline_id: str) -> dict[str, Any]:
    row = connection.execute(
        "SELECT id, version, content_json FROM project_documents "
        "WHERE id=? AND project_id=?",
        (f"timeline:{timeline_id}", project_id),
    ).fetchone()
    result: dict[str, Any] = {
        "document_id": f"timeline:{timeline_id}",
        "present": row is not None,
        "version": int(row["version"]) if row is not None else None,
        "clip_type_shot_count": 0,
        "pinned_group_count": 0,
        "legacy_shape": False,
    }
    if row is None:
        return result
    try:
        content = json.loads(row["content_json"])
    except (TypeError, json.JSONDecodeError):
        result.update({"legacy_shape": True, "invalid": True})
        return result
    config = content.get("config") if isinstance(content, dict) else None
    clips = config.get("clips", []) if isinstance(config, dict) else []
    groups = config.get("pinnedShotGroups", []) if isinstance(config, dict) else []
    clip_count = sum(
        1 for item in clips
        if isinstance(item, dict) and item.get("clipType") == "shot"
    ) if isinstance(clips, list) else 0
    group_count = len(groups) if isinstance(groups, list) else 0
    result.update({
        "clip_type_shot_count": clip_count,
        "pinned_group_count": group_count,
        "legacy_shape": bool(clip_count or group_count),
        "invalid": not isinstance(content, dict) or not isinstance(config, dict),
    })
    return result


def _pages(connection, project_id: str, timeline_id: str, head_revision_id: str) -> Iterable[dict[str, Any]]:
    """Yield every bounded inspection page for one fixed head."""
    cursor = None
    for _ in range(_MAX_PAGES):
        options: dict[str, Any] = {"revision_id": head_revision_id, "limit": _PAGE_LIMIT}
        if cursor is not None:
            options["cursor"] = cursor
        page = inspect_timeline(connection, project_id, timeline_id, options)
        yield page
        cursor = page.get("next_cursor")
        if cursor is None:
            return
    raise RuntimeErrorBase("timeline inspection pagination exceeded audit bound")


def _canonical_summary(pages: Iterable[dict[str, Any]], head_revision_id: str) -> dict[str, Any]:
    occurrences: dict[str, dict[str, Any]] = {}
    clips: dict[str, dict[str, Any]] = {}
    parent_clips: dict[str, dict[str, Any]] = {}
    first: dict[str, Any] | None = None
    for page in pages:
        if first is None:
            first = page
        if page.get("head_revision_id") != head_revision_id or not page.get("is_current_head"):
            raise ValueError("inspection page is not pinned to the active canonical head")
        for row in page.get("selected", []):
            occurrence = row.get("occurrence") if isinstance(row, dict) else None
            if isinstance(occurrence, dict) and isinstance(occurrence.get("occurrence_id"), str):
                occurrences.setdefault(occurrence["occurrence_id"], {
                    "occurrence_id": occurrence["occurrence_id"],
                    "shot_id": occurrence.get("shot_id"),
                    "name": occurrence.get("name"),
                    "start": occurrence.get("start"),
                    "duration": occurrence.get("duration"),
                    "track_id": occurrence.get("track_id"),
                    "audio_bindings": occurrence.get("audio_bindings", []),
                })
            for clip in row.get("clips", []) if isinstance(row, dict) else []:
                if isinstance(clip, dict) and isinstance(clip.get("clip_id"), str):
                    clips.setdefault(clip["clip_id"], clip)
        for clip in page.get("selected_parent_clips", []):
            if isinstance(clip, dict) and isinstance(clip.get("clip_id"), str):
                parent_clips.setdefault(clip["clip_id"], clip)
    if first is None:
        raise ValueError("canonical inspection returned no page")
    media = sorted({
        value
        for clip in list(clips.values()) + list(parent_clips.values())
        for value in (clip.get("source_object_id"), clip.get("content_digest"))
        if isinstance(value, str) and value
    })
    audio = [
        value for value in (item.get("audio_bindings", []) for item in occurrences.values())
        if value
    ]
    return {
        "revision_id": head_revision_id,
        "content_digest": first.get("parent_content_digest"),
        "snapshot_digest": first.get("snapshot_digest"),
        "occurrence_count": int(first.get("occurrence_count", len(occurrences))),
        "occurrences": list(occurrences.values()),
        "clip_count": len(clips),
        "parent_clip_count": int(first.get("parent_clip_count", len(parent_clips))),
        "parent_clips": list(parent_clips.values()),
        "media": media,
        "audio": audio,
    }


def audit_active_timeline_heads(connection, *, project_id: str | None = None) -> dict[str, Any]:
    """Return a deterministic report of active canonical timeline heads.

    Each item is either ``available`` with a complete pinned closure summary,
    ``migration_required`` when a legacy shell remains alongside a valid
    canonical head, or ``unavailable`` with a fail-closed reason.  No legacy
    document content is returned in the report.
    """
    query = "SELECT id, project_id, archived_at FROM timelines WHERE archived_at IS NULL"
    args: tuple[Any, ...] = ()
    if project_id is not None:
        query += " AND project_id=?"
        args = (project_id,)
    query += " ORDER BY project_id, created_at, id"
    rows = connection.execute(query, args).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        pid, tid = str(row["project_id"]), str(row["id"])
        legacy = _legacy_document(connection, pid, tid)
        head = connection.execute(
            "SELECT revision_id FROM parent_composition_heads WHERE project_id=? AND timeline_id=?",
            (pid, tid),
        ).fetchone()
        item: dict[str, Any] = {
            "project_id": pid,
            "timeline_id": tid,
            "status": "unavailable",
            "canonical_head": None,
            "closure": None,
            "legacy": legacy,
        }
        if head is None or not head["revision_id"]:
            item["reason"] = "missing_canonical_head"
            items.append(item)
            continue
        head_id = str(head["revision_id"])
        try:
            summary = _canonical_summary(_pages(connection, pid, tid, head_id), head_id)
            item["canonical_head"] = {
                "revision_id": head_id,
                "content_digest": summary["content_digest"],
                "snapshot_digest": summary["snapshot_digest"],
            }
            item["closure"] = summary
            item["status"] = "migration_required" if legacy["legacy_shape"] else "available"
            if legacy["invalid"]:
                item["status"] = "unavailable"
                item["reason"] = "malformed_legacy_document"
        except Exception as exc:  # noqa: BLE001 - audit must report, never fallback
            item["reason"] = f"canonical_closure_invalid:{type(exc).__name__}"
            item["error"] = str(exc)
        items.append(item)
    unavailable = sum(item["status"] == "unavailable" for item in items)
    migration_required = sum(item["status"] == "migration_required" for item in items)
    return {
        "schema": AUDIT_SCHEMA,
        "project_id": project_id,
        "timeline_count": len(items),
        "available_count": sum(item["status"] == "available" for item in items),
        "migration_required_count": migration_required,
        "unavailable_count": unavailable,
        "status": "ok" if unavailable == 0 else "unavailable",
        "items": items,
    }


__all__ = ["AUDIT_SCHEMA", "audit_active_timeline_heads"]
