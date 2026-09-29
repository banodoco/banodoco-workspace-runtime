"""Bounded, metadata-only inspection of an immutable timeline closure.

This module intentionally has no Astrid, media, or executor imports.  It reads
only revision payloads already admitted by the runtime.
"""

from __future__ import annotations

import base64
import hashlib
import json
from fractions import Fraction

from .errors import ConflictError, NotFoundError, ValidationError
from .util import canonical_json

SCHEMA = "runtime.timeline.declared_inputs/v1"
MAX_OCCURRENCES = 500
# A request returns at most 100 selected clips per page. A pinned child may be
# larger; selectors and pagination must be applied before presentation limits.
MAX_SELECTED_CLIPS = 100
MAX_CLOSURE_CLIPS = 2000


def _fraction(value, label, *, milliseconds=False):
    try:
        if isinstance(value, bool) or value is None:
            raise ValueError
        if isinstance(value, (list, tuple)) and len(value) == 2 and all(isinstance(item, int) and not isinstance(item, bool) for item in value):
            result = Fraction(*value)
        else:
            raw = str(value)
            if len(raw) > 64:
                raise ValueError
            result = Fraction(raw)
        if milliseconds:
            result /= 1000
        # Existing authored payloads contain ordinary binary-float frame
        # durations (for example ``7.066666666666666``).  They are semantically
        # bounded, frame-derived values, but their decimal spelling can have a
        # huge denominator.  Canonicalize only near-equivalent values to a
        # bounded rational; do not silently round arbitrary precise input.
        if result.denominator > 1_000_000:
            bounded = result.limit_denominator(1_000_000)
            if abs(result - bounded) > Fraction(1, 1_000_000_000):
                raise ValueError
            result = bounded
        if result < 0 or result.denominator > 1_000_000:
            raise ValueError
        return result
    except (ValueError, TypeError, ZeroDivisionError, OverflowError) as exc:
        raise ValidationError(f"{label} must be a bounded non-negative rational") from exc


def _wire(value):
    return [value.numerator, value.denominator]


def normalize_options(raw):
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValidationError("timeline inspection options must be an object")
    allowed = {"revision_id", "occurrence", "shot", "clip", "asset", "track", "range", "neighbors", "detail", "limit", "formats", "cursor"}
    extra = set(raw) - allowed
    if extra:
        raise ValidationError("unsupported timeline inspection options", details={"fields": sorted(extra)})
    result = {}
    for key in ("revision_id", "occurrence", "shot", "clip", "asset", "track"):
        value = raw.get(key)
        if value is not None and (not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value)):
            raise ValidationError(f"{key} must be a bounded identifier")
        result[key] = value
    neighbors = raw.get("neighbors", 0)
    if isinstance(neighbors, bool) or not isinstance(neighbors, int) or not 0 <= neighbors <= 2:
        raise ValidationError("neighbors must be an integer from 0 to 2")
    limit = raw.get("limit", MAX_SELECTED_CLIPS)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_SELECTED_CLIPS:
        raise ValidationError("limit must be an integer from 1 to 100")
    detail = raw.get("detail", False)
    if not isinstance(detail, bool):
        raise ValidationError("detail must be a boolean")
    result.update(neighbors=neighbors, limit=limit, detail=detail)
    cursor = raw.get("cursor")
    if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 4096):
        raise ValidationError("cursor must be a bounded string")
    result["cursor"] = cursor
    interval = raw.get("range")
    if interval is not None:
        if isinstance(interval, str):
            interval = interval.split("..")
        if not isinstance(interval, (list, tuple)) or len(interval) != 2:
            raise ValidationError("range must be START..END in seconds")
        start, end = (_fraction(value, "range bound") for value in interval)
        if end <= start:
            raise ValidationError("range end must follow start")
        result["range"] = [_wire(start), _wire(end)]
    else:
        result["range"] = None
    if "formats" in raw:
        formats = raw["formats"]
        if not isinstance(formats, list) or not formats or len(formats) > 2 or any(item not in ("md", "png") for item in formats) or len(set(formats)) != len(formats):
            raise ValidationError("formats must be a unique list of md and/or png")
        result["formats"] = formats
    return result


def _row(connection, query, args, label):
    row = connection.execute(query, args).fetchone()
    if row is None:
        raise NotFoundError(f"{label} not found")
    return row


def _digest(payload):
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def _encode_cursor(scope, offset):
    payload = canonical_json({"scope": scope, "offset": offset}).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _decode_cursor(cursor):
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        payload = json.loads(raw)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ValidationError("timeline inspection cursor is invalid") from exc
    if (not isinstance(payload, dict) or set(payload) != {"scope", "offset"}
            or not isinstance(payload["scope"], str)
            or isinstance(payload["offset"], bool) or not isinstance(payload["offset"], int)
            or payload["offset"] < 0):
        raise ValidationError("timeline inspection cursor is invalid")
    return payload["scope"], payload["offset"]


def _asset(clip, registry):
    key = clip.get("asset", clip.get("asset_id"))
    assets = registry.get("assets", {}) if isinstance(registry, dict) else {}
    metadata = assets.get(key, {}) if isinstance(assets, dict) and isinstance(key, str) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    return {"asset_id": key, "source_object_id": metadata.get("media_id") or metadata.get("object_id") or clip.get("media_id") or clip.get("object_id"),
            "content_digest": metadata.get("content_sha256") or metadata.get("digest") or clip.get("content_sha256"),
            "kind": metadata.get("type")}


def _shot_name(payload, shot_id):
    """Resolve the canonical display name without consulting timeline documents."""
    provenance = payload.get("provenance") if isinstance(payload, dict) else None
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    candidates = (
        payload.get("name") if isinstance(payload, dict) else None,
        provenance.get("name") if isinstance(provenance, dict) else None,
        provenance.get("title") if isinstance(provenance, dict) else None,
        metadata.get("name") if isinstance(metadata, dict) else None,
        metadata.get("title") if isinstance(metadata, dict) else None,
        shot_id,
    )
    return next(value for value in candidates if isinstance(value, str) and value.strip())


def _clip(raw, registry, occurrence, start, end):
    if not isinstance(raw, dict):
        raise ConflictError("pinned internal timeline contains an invalid clip")
    cid = raw.get("id")
    if not isinstance(cid, str) or not cid:
        raise ConflictError("pinned internal clip has no identity")
    relative = _fraction(raw.get("at_ms", raw.get("at", 0)), "clip start", milliseconds="at_ms" in raw)
    absolute = start + relative
    speed = _fraction(raw.get("speed", 1), "clip speed")
    if speed <= 0:
        raise ConflictError("pinned internal clip speed is invalid")
    if "duration_ms" in raw:
        source_duration = _fraction(raw["duration_ms"], "clip duration", milliseconds=True)
    elif "hold" in raw:
        source_duration = _fraction(raw["hold"], "clip hold")
    elif "to_ms" in raw or "from_ms" in raw:
        source_duration = _fraction(raw.get("to_ms", 0), "clip to", milliseconds=True) - _fraction(raw.get("from_ms", 0), "clip from", milliseconds=True)
    else:
        source_duration = _fraction(raw.get("to", 0), "clip to") - _fraction(raw.get("from", 0), "clip from")
    duration = source_duration / speed
    visible_end = min(absolute + duration, end)
    if duration < 0 or visible_end <= absolute or absolute >= end:
        return None
    asset = _asset(raw, registry)
    return {"occurrence_id": occurrence["occurrence_id"], "shot_id": occurrence["shot_id"],
            "clip_id": cid, "track_id": raw.get("track"), "clip_type": raw.get("clipType", raw.get("clip_type", raw.get("type", "media"))),
            "start": _wire(absolute), "duration": _wire(visible_end - absolute), "source_from": raw.get("from_ms", raw.get("from")),
            "source_to": raw.get("to_ms", raw.get("to")), "speed": _wire(speed), "gain": raw.get("volume", 1),
            "mute": bool(raw.get("mute", False)), "text": str(raw.get("text", ""))[:2000], **asset}


def _parent_clip(raw, registry):
    """Project an ordinary parent-level effect/code clip without shot identity."""
    if not isinstance(raw, dict):
        raise ConflictError("parent composition contains an invalid clip")
    cid = raw.get("id")
    if not isinstance(cid, str) or not cid:
        raise ConflictError("parent composition clip has no identity")
    start = _fraction(raw.get("at_ms", raw.get("at", 0)), "parent clip start", milliseconds="at_ms" in raw)
    speed = _fraction(raw.get("speed", 1), "parent clip speed")
    if speed <= 0:
        raise ConflictError("parent clip speed is invalid")
    if "duration_ms" in raw:
        source_duration = _fraction(raw["duration_ms"], "parent clip duration", milliseconds=True)
    elif "hold" in raw:
        source_duration = _fraction(raw["hold"], "parent clip hold")
    elif "to_ms" in raw or "from_ms" in raw:
        source_duration = _fraction(raw.get("to_ms", 0), "parent clip to", milliseconds=True) - _fraction(raw.get("from_ms", 0), "parent clip from", milliseconds=True)
    else:
        source_duration = _fraction(raw.get("to", 0), "parent clip to") - _fraction(raw.get("from", 0), "parent clip from")
    duration = source_duration / speed
    if duration <= 0:
        return None
    parameters = raw.get("parameters", raw.get("params", raw.get("props", {})))
    if not isinstance(parameters, dict):
        parameters = {}
    element_ref = raw.get("elementRef", raw.get("element_ref"))
    if element_ref is not None and not isinstance(element_ref, (str, dict)):
        element_ref = None
    asset = _asset(raw, registry)
    return {
        "target_kind": "parent_clip", "clip_id": cid, "track_id": raw.get("track"),
        "clip_type": raw.get("clipType", raw.get("clip_type", raw.get("type", "media"))),
        "start": _wire(start), "duration": _wire(duration),
        "source_from": raw.get("from_ms", raw.get("from")), "source_to": raw.get("to_ms", raw.get("to")),
        "speed": _wire(speed), "gain": raw.get("volume", raw.get("gain", 1)),
        "mute": bool(raw.get("mute", False)), "text": str(raw.get("text", ""))[:2000],
        "parameters": parameters, "element_ref": element_ref, **asset,
    }


def inspect(connection, project_id, timeline_id, options):
    """Freeze one parent head and its pinned children under the caller's lock."""
    options = normalize_options(options)
    _row(connection, "SELECT id FROM timelines WHERE id=? AND project_id=?", (timeline_id, project_id), "timeline")
    head = connection.execute("SELECT revision_id FROM parent_composition_heads WHERE project_id=? AND timeline_id=?", (project_id, timeline_id)).fetchone()
    head_revision = head["revision_id"] if head else None
    head_row = (connection.execute(
        "SELECT content_digest FROM parent_composition_revisions WHERE id=? AND project_id=? AND timeline_id=?",
        (head_revision, project_id, timeline_id),
    ).fetchone() if head_revision else None)
    revision = options["revision_id"] or head_revision
    if revision is None:
        raise NotFoundError("timeline has no parent composition revision")
    parent = _row(connection, "SELECT * FROM parent_composition_revisions WHERE id=? AND project_id=? AND timeline_id=?", (revision, project_id, timeline_id), "parent composition revision")
    payload = json.loads(parent["payload_json"])
    occurrences = payload.get("occurrences")
    if not isinstance(occurrences, list) or len(occurrences) > MAX_OCCURRENCES:
        raise ValidationError("timeline has too many occurrences; narrow the revision")
    children = []
    parent_registry = {"assets": {}}
    source_registry = payload.get("registry")
    assets = source_registry.get("assets") if isinstance(source_registry, dict) else None
    if isinstance(assets, dict):
        parent_registry["assets"].update(assets)
    seen = set()
    closure_clips = 0
    for ordinal, raw in enumerate(occurrences):
        if not isinstance(raw, dict):
            raise ConflictError("pinned parent occurrence is invalid")
        occurrence_id, shot_id, shot_revision_id = (raw.get(key) for key in ("occurrence_id", "shot_id", "shot_revision_id"))
        if not all(isinstance(value, str) and value for value in (occurrence_id, shot_id, shot_revision_id)) or occurrence_id in seen:
            raise ConflictError("pinned parent occurrence identity is invalid")
        seen.add(occurrence_id)
        shot = _row(connection, "SELECT * FROM shot_revisions WHERE id=? AND project_id=? AND shot_id=?", (shot_revision_id, project_id, shot_id), "pinned shot revision")
        internal_id = shot["internal_timeline_revision_id"]
        internal = _row(connection, "SELECT * FROM internal_timeline_revisions WHERE id=? AND project_id=?", (internal_id, project_id), "pinned internal timeline revision")
        placement = raw.get("placement", {})
        start = _fraction(raw.get("at_ms", placement.get("start_ms", 0)), "occurrence start", milliseconds=True)
        duration = _fraction(raw.get("duration_ms", 0), "occurrence duration", milliseconds=True)
        internal_payload = json.loads(internal["payload_json"])
        shot_payload = json.loads(shot["payload_json"])
        registry = {"assets": {}}
        for source_registry in (payload.get("registry"), internal_payload.get("registry")):
            assets = source_registry.get("assets") if isinstance(source_registry, dict) else None
            if isinstance(assets, dict):
                registry["assets"].update(assets)
        for asset in shot_payload.get("assets", []):
            if isinstance(asset, dict) and isinstance(asset.get("asset_id"), str):
                registry["assets"][asset["asset_id"]] = {"media_id": asset.get("object_id"), "content_sha256": asset.get("digest")}
        clips = internal_payload.get("clips", [])
        if not isinstance(clips, list):
            raise ConflictError("pinned shot clips are invalid")
        closure_clips += len(clips)
        if closure_clips > MAX_CLOSURE_CLIPS:
            raise ValidationError("timeline closure exceeds clip limit; narrow the revision")
        identity = {"ordinal": ordinal, "occurrence_id": occurrence_id, "shot_id": shot_id,
                    "shot_revision_id": shot_revision_id, "shot_digest": shot["content_digest"],
                    "internal_timeline_revision_id": internal_id, "internal_timeline_digest": internal["content_digest"],
                    "name": _shot_name(shot_payload, shot_id),
                    "start": _wire(start), "duration": _wire(duration), "track_id": raw.get("track"),
                    "source_offset": raw.get("source_offset", 0), "speed": raw.get("speed", 1),
                    "gain": raw.get("gain", 1), "mute": bool(raw.get("muted", raw.get("mute", False))),
                    "text_bindings": shot_payload.get("text_bindings", []),
                    "audio_bindings": shot_payload.get("audio_bindings", [])}
        projected = [item for clip in clips if (item := _clip(clip, registry, identity, start, start + duration)) is not None]
        children.append((identity, projected))
    parent_clips_raw = payload.get("clips", [])
    if not isinstance(parent_clips_raw, list):
        raise ConflictError("canonical parent composition clips are invalid")
    parent_clips = [item for raw in parent_clips_raw if (item := _parent_clip(raw, parent_registry)) is not None]
    closure_clips += len(parent_clips)
    if closure_clips > MAX_CLOSURE_CLIPS:
        raise ValidationError("timeline closure exceeds clip limit; narrow the revision")
    snapshot_digest = _digest({"schema": SCHEMA, "parent": parent["content_digest"], "children": [row[0] for row in children]})
    target_indices = []
    range_bounds = tuple(Fraction(*value) for value in options["range"]) if options["range"] else None
    for index, (occurrence, clips) in enumerate(children):
        if options["occurrence"] and occurrence["occurrence_id"] != options["occurrence"]: continue
        if options["shot"] and occurrence["shot_id"] != options["shot"]: continue
        matching = [clip for clip in clips if (not options["clip"] or clip["clip_id"] == options["clip"])
                    and (not options["asset"] or clip["asset_id"] == options["asset"] or clip["source_object_id"] == options["asset"])
                    and (not options["track"] or clip["track_id"] == options["track"] or occurrence["track_id"] == options["track"])
                    and (not range_bounds or (Fraction(*clip["start"]) < range_bounds[1]
                                              and Fraction(*clip["start"]) + Fraction(*clip["duration"]) > range_bounds[0]))]
        if any(options[key] for key in ("clip", "asset", "track")) and not matching: continue
        if range_bounds and not matching: continue
        target_indices.append(index)
    selected = set(target_indices)
    for index in target_indices:
        selected.update(range(max(0, index - options["neighbors"]), min(len(children), index + options["neighbors"] + 1)))
    rows = []
    for index in sorted(selected):
        occurrence, clips = children[index]
        clips = [clip for clip in clips if (index not in target_indices or not options["clip"] or clip["clip_id"] == options["clip"])
                     and (index not in target_indices or not options["asset"] or clip["asset_id"] == options["asset"] or clip["source_object_id"] == options["asset"])
                     and (index not in target_indices or not options["track"] or clip["track_id"] == options["track"] or occurrence["track_id"] == options["track"])
                     and (not range_bounds or (Fraction(*clip["start"]) < range_bounds[1]
                                               and Fraction(*clip["start"]) + Fraction(*clip["duration"]) > range_bounds[0]))]
        rows.append({"role": "target" if index in target_indices else "neighbor", "occurrence": occurrence, "clips": clips})
    def parent_matches(clip):
        if options["occurrence"] or options["shot"]:
            return False
        return ((not options["clip"] or clip["clip_id"] == options["clip"])
                and (not options["asset"] or clip["asset_id"] == options["asset"] or clip["source_object_id"] == options["asset"])
                and (not options["track"] or clip["track_id"] == options["track"])
                and (not range_bounds or (Fraction(*clip["start"]) < range_bounds[1]
                                          and Fraction(*clip["start"]) + Fraction(*clip["duration"]) > range_bounds[0])))
    selected_parent_clips = [clip for clip in parent_clips if parent_matches(clip)]
    scope = _digest({"project_id": project_id, "timeline_id": timeline_id, "head_revision_id": head_revision,
                     "revision_id": revision, "snapshot_digest": snapshot_digest,
                     "selectors": {key: value for key, value in options.items() if key != "cursor"}})
    offset = 0
    if options["cursor"] is not None:
        cursor_scope, offset = _decode_cursor(options["cursor"])
        if cursor_scope != scope:
            raise ValidationError("timeline inspection cursor does not match current head or query")
    child_total_clips = sum(len(row["clips"]) for row in rows)
    total_clips = len(selected_parent_clips) + child_total_clips
    if offset > total_clips:
        raise ValidationError("timeline inspection cursor position is invalid")
    end_offset = min(total_clips, offset + options["limit"])
    page_rows = []
    parent_start = min(offset, len(selected_parent_clips))
    parent_end = min(end_offset, len(selected_parent_clips))
    selected_parent_page = selected_parent_clips[parent_start:parent_end]
    child_offset = max(0, offset - len(selected_parent_clips))
    child_end_offset = max(0, end_offset - len(selected_parent_clips))
    position = 0
    for row in rows:
        row_start = position
        row_end = row_start + len(row["clips"])
        position = row_end
        if row_end <= child_offset or row_start >= child_end_offset:
            continue
        clips = row["clips"][max(0, child_offset - row_start):min(len(row["clips"]), child_end_offset - row_start)]
        page_rows.append({**row, "clips": clips})
    if child_total_clips == 0:
        page_rows = rows
    next_cursor = _encode_cursor(scope, end_offset) if end_offset < total_clips else None
    return {"schema": SCHEMA, "evidence_kind": "declared_inputs", "render_requested": False,
            "representation": "canonical_head" if revision == head_revision else "canonical_revision",
            "authority": "runtime_parent_composition", "is_current_head": revision == head_revision,
            "source_pixels": "not_requested", "waveforms": "not_requested", "project_id": project_id,
            "timeline_id": timeline_id, "revision_id": revision, "parent_content_digest": parent["content_digest"],
            "head_revision_id": head_revision, "head_content_digest": (head_row["content_digest"] if head_row else None),
            "snapshot_digest": "sha256:" + snapshot_digest,
            "selectors": {key: value for key, value in options.items() if key != "cursor"},
            "selection_status": "selected" if target_indices or selected_parent_clips else "selector_miss",
            "target_count": len(target_indices), "occurrence_count": len(children),
            "parent_clip_count": len(parent_clips), "parent_clip_target_count": len(selected_parent_clips),
            "selected_clip_count": sum(len(row["clips"]) for row in page_rows) + len(selected_parent_page),
            "selected": page_rows, "selected_parent_clips": selected_parent_page, "next_cursor": next_cursor}
