"""Runtime-owned preparation for managed render snapshots.

The authoring timeline may contain ``clipType == "shot"`` composite clips.
Those are an editorial representation and must be flattened before a worker
claims a render.  This module is deliberately independent of Astrid's SDK so
the neutral workspace runtime remains the authority that freezes the exact
bytes used by a task.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from copy import deepcopy
import math
from pathlib import Path

_LOGGER = logging.getLogger(__name__)
_LoadTimelineFn = Callable[[str], tuple[Mapping[str, object], Mapping[str, object]]]


class ShotExpansionError(ValueError):
    """A managed shot reference cannot be expanded safely."""


def expand_shot_clips(
    config: Mapping[str, object],
    registry: Mapping[str, object],
    *,
    load_timeline: _LoadTimelineFn,
) -> tuple[dict[str, object], dict[str, object]]:
    """Flatten authored shot clips into a renderable timeline snapshot.

    The input documents are never mutated. Child timelines are loaded by the
    caller through an already-authorized project-scoped loader. Asset-key
    collisions fail closed when the entries differ, and nested shot clips fail
    closed rather than being expanded against a changing project during
    execution.
    """
    raw_clips = config.get("clips", [])
    if not isinstance(raw_clips, list):
        raise ShotExpansionError("timeline clips must be a list")

    raw_assets = registry.get("assets", {})
    if not isinstance(raw_assets, Mapping):
        raise ShotExpansionError("timeline registry assets must be an object")
    merged_assets: dict[str, object] = dict(raw_assets)
    expanded_clips: list[dict[str, object]] = []

    def finite_float(value: object, label: str) -> float:
        try:
            result = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ShotExpansionError(f"{label} must be a finite number") from exc
        if not math.isfinite(result):
            raise ShotExpansionError(f"{label} must be a finite number")
        return result

    def is_still_asset(asset_id: object) -> bool:
        if not isinstance(asset_id, str):
            return False
        entry = merged_assets.get(asset_id)
        if not isinstance(entry, Mapping):
            return False
        kind = str(entry.get("type", "")).lower()
        if kind in {"image", "still", "image/png", "image/jpeg", "image/webp"}:
            return True
        file_value = entry.get("file")
        return isinstance(file_value, str) and Path(file_value).suffix.lower() in {
            ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff",
        }

    def reject_unbounded_stills(clips: list[object]) -> None:
        for raw_clip in clips:
            if not isinstance(raw_clip, Mapping):
                raise ShotExpansionError("timeline clips must be objects")
            if (
                raw_clip.get("clipType") == "media"
                and "hold" in raw_clip
                and ("from" not in raw_clip or "to" not in raw_clip)
                and is_still_asset(raw_clip.get("asset"))
            ):
                raise ShotExpansionError(
                    f"Image media clip {raw_clip.get('id', '?')} uses hold without "
                    "explicit from/to source bounds"
                )

    # Root-level image holds are valid static visual overlays. The renderer
    # supports them and the authored `hold` already provides the timeline
    # duration. Keep the stricter bounded-window rule for stills inside shot
    # sub-documents, where expansion must preserve source-window semantics.
    shot_ordinal = 0
    for clip in raw_clips:
        if clip.get("clipType") != "shot":
            expanded_clips.append(dict(clip))
            continue

        params = clip.get("params")
        if not isinstance(params, Mapping):
            raise ShotExpansionError(f"Shot clip {clip.get('id', '?')} missing valid params")
        shot_id = params.get("shot_id")
        child_ref = params.get("timeline_document_id")
        if not isinstance(shot_id, str) or not shot_id or not isinstance(child_ref, str) or not child_ref:
            raise ShotExpansionError(
                f"Shot clip {clip.get('id', '?')} missing shot_id or timeline_document_id in params"
            )

        occurrence_id = f"shot-occ-{shot_ordinal:04d}-{shot_id}"
        shot_ordinal += 1
        try:
            child_config, child_registry = load_timeline(child_ref)
        except Exception as exc:  # noqa: BLE001 - normalize loader failures at the boundary
            raise ShotExpansionError(f"Failed to load sub-timeline {child_ref}: {exc}") from exc

        child_clips = child_config.get("clips", [])
        if not isinstance(child_clips, list):
            raise ShotExpansionError(f"sub-timeline {child_ref} clips must be a list")
        child_assets = child_registry.get("assets", {})
        if not isinstance(child_assets, Mapping):
            raise ShotExpansionError(f"sub-timeline {child_ref} has an invalid asset registry")
        for asset_id, entry in child_assets.items():
            if asset_id in merged_assets and merged_assets[asset_id] != entry:
                raise ShotExpansionError(
                    f"asset key collision for {asset_id!r} while expanding {child_ref}"
                )
            merged_assets.setdefault(asset_id, entry)
        reject_unbounded_stills(child_clips)

        parent_at = finite_float(clip.get("at", 0.0), f"shot clip {clip.get('id', '?')} at")
        parent_hold = finite_float(clip.get("hold", 0.0), f"shot clip {clip.get('id', '?')} hold")
        if parent_hold <= 0.0:
            raise ShotExpansionError(f"shot clip {clip.get('id', '?')} must have a positive hold")
        parent_end = parent_at + parent_hold
        for child_clip in child_clips:
            if not isinstance(child_clip, Mapping):
                raise ShotExpansionError(f"sub-clip inside sub-timeline {child_ref} must be an object")
            if child_clip.get("clipType") == "shot":
                raise ShotExpansionError(f"nested shot clip detected inside sub-timeline {child_ref}")
            child_id = child_clip.get("id")
            if not child_id:
                raise ShotExpansionError(f"Sub-clip missing id inside sub-timeline {child_ref}")
            asset_id = child_clip.get("asset")
            if isinstance(asset_id, str) and asset_id not in child_assets and asset_id not in merged_assets:
                raise ShotExpansionError(
                    f"Sub-clip {child_id} references missing asset {asset_id!r} inside sub-timeline {child_ref}"
                )

            child_at = finite_float(child_clip.get("at", 0.0), f"Sub-clip {child_id} at")
            child_hold = finite_float(child_clip.get("hold", 0.0), f"Sub-clip {child_id} hold")
            speed = finite_float(child_clip.get("speed", 1.0), f"Sub-clip {child_id} speed")
            if speed <= 0.0:
                raise ShotExpansionError(f"Sub-clip {child_id} inside sub-timeline {child_ref} has invalid speed")
            has_source_from = "from" in child_clip
            has_source_to = "to" in child_clip
            if has_source_from != has_source_to:
                raise ShotExpansionError(f"Sub-clip {child_id} must provide both from and to source bounds")
            source_from = finite_float(child_clip.get("from", 0.0), f"Sub-clip {child_id} from")
            source_to = finite_float(child_clip.get("to", 0.0), f"Sub-clip {child_id} to")
            if has_source_from and source_to <= source_from:
                raise ShotExpansionError(f"Sub-clip {child_id} must have a positive source window")
            if child_hold < 0.0:
                raise ShotExpansionError(f"Sub-clip {child_id} must not have a negative hold")
            if child_hold <= 0.0 and source_to > source_from:
                child_hold = (source_to - source_from) / speed
            if child_hold <= 0.0:
                raise ShotExpansionError(f"Sub-clip {child_id} must have a positive duration")

            raw_at = parent_at + child_at
            raw_end = raw_at + child_hold
            visible_at = max(raw_at, parent_at)
            visible_end = min(raw_end, parent_end)
            if visible_end <= visible_at:
                _LOGGER.debug("Dropping child clip %s outside parent shot window", child_id)
                continue
            left_trim = visible_at - raw_at
            visible_duration = visible_end - visible_at
            expanded = dict(child_clip)
            expanded["id"] = f"{occurrence_id}--{child_id}"
            expanded["source_clip_id"] = child_id
            expanded["at"] = visible_at
            if "hold" in expanded or not has_source_from:
                expanded["hold"] = visible_duration
            if has_source_from:
                expanded["from"] = source_from + left_trim * speed
                expanded["to"] = expanded["from"] + visible_duration * speed
            if child_clip.get("track") is None:
                expanded["track"] = clip.get("track")
            expanded["shot_id"] = shot_id
            expanded["shot_occurrence_id"] = occurrence_id
            expanded_clips.append(expanded)

    expanded_config = deepcopy(dict(config))
    expanded_config["clips"] = expanded_clips
    return expanded_config, {"assets": merged_assets}


__all__ = ["ShotExpansionError", "expand_shot_clips"]
