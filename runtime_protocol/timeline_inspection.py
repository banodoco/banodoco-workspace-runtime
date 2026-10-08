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
from .managed_render_snapshot import ShotExpansionError, expand_shot_clips

SCHEMA = "runtime.timeline.declared_inputs/v1"
MAX_OCCURRENCES = 500
# A request returns at most 100 selected clips per page. A pinned child may be
# larger; selectors and pagination must be applied before presentation limits.
MAX_SELECTED_CLIPS = 100
MAX_CLOSURE_CLIPS = 2000
MAX_RESPONSE_BYTES = 256 * 1024
MAX_AUTHORED_VALUE_BYTES = 4096
MAX_AUTHORED_FIELDS_BYTES = 8192
MAX_TRACK_FIELDS_BYTES = 2048
MAX_BINDINGS_BYTES = 8192

_PRESENTATION_KEYS = (
    "x", "y", "width", "height", "cropTop", "cropBottom", "cropLeft",
    "cropRight", "opacity", "scale", "fit", "blendMode", "entrance",
    "exit", "continuous", "transition", "effects", "keyframes",
)
_TIMING_KEYS = ("at", "at_ms", "duration", "duration_ms", "hold", "from", "from_ms", "to", "to_ms", "speed")


def _fraction(value, label, *, milliseconds=False, nonnegative=True):
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
        if (nonnegative and result < 0) or result.denominator > 1_000_000:
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


def _value_bytes(value):
    return canonical_json(value).encode("utf-8")


def _bounded_value(value, limit, path, omissions):
    """Keep a JSON value whole, or record exactly why its bytes were omitted."""
    encoded = _value_bytes(value)
    if len(encoded) <= limit:
        return value
    omissions.append({"path": path, "reason": "byte_limit", "byte_length": len(encoded),
                      "sha256": hashlib.sha256(encoded).hexdigest(), "limit_bytes": limit})
    return None


def _authored_projection(raw):
    """Expose authored values while keeping each clip's optional data bounded."""
    omissions = []
    authored = _bounded_value(raw, MAX_AUTHORED_FIELDS_BYTES, "authored_fields", omissions)
    result = {"authored_fields": authored}
    parameters_key = next((key for key in ("parameters", "params", "props") if key in raw), None)
    parameters = raw.get(parameters_key) if parameters_key else {}
    if not isinstance(parameters, dict):
        # Preserve malformed or future-shaped authored input in authored_fields,
        # while retaining the historical mapping-shaped convenience field.
        result["parameters"] = {}
    else:
        result["parameters"] = _bounded_value(parameters, MAX_AUTHORED_VALUE_BYTES, "parameters", omissions)
    result["parameters_source"] = parameters_key
    for source, target in (("elementRef", "element_ref"), ("element_ref", "element_ref")):
        if source in raw:
            value = raw[source]
            result[target] = _bounded_value(value, MAX_AUTHORED_VALUE_BYTES, target, omissions)
            break
    if "element_ref" not in result:
        result["element_ref"] = None
    for key in ("label", "labels", "extensions", "presentation"):
        if key in raw:
            result[key] = _bounded_value(raw[key], MAX_AUTHORED_VALUE_BYTES, key, omissions)
    presentation_fields = {key: raw[key] for key in _PRESENTATION_KEYS if key in raw}
    if presentation_fields:
        result["presentation_fields"] = _bounded_value(
            presentation_fields, MAX_AUTHORED_FIELDS_BYTES, "presentation_fields", omissions
        )
    timing = {key: raw[key] for key in _TIMING_KEYS if key in raw}
    if timing:
        result["authored_timing"] = _bounded_value(timing, MAX_AUTHORED_VALUE_BYTES, "authored_timing", omissions)
    if omissions:
        result["omitted_fields"] = omissions
    return result


def _track_catalog(raw_tracks):
    """Index authored track records without merging parent and child scopes."""
    tracks = {}
    if not isinstance(raw_tracks, list):
        return tracks
    for track in raw_tracks:
        if isinstance(track, dict) and isinstance(track.get("id"), str):
            tracks.setdefault(track["id"], []).append(track)
    return tracks


def _track_projection(track_id, track_scope, tracks):
    reference = {"scope": track_scope["kind"], "scope_id": track_scope["id"], "track_id": track_id}
    if not isinstance(track_id, str) or not track_id:
        return {"track_ref": reference, "track_status": "unassigned", "track": None}
    matches = tracks.get(track_id, [])
    if not matches:
        return {"track_ref": reference, "track_status": "unresolved", "track": None}
    if len(matches) > 1:
        return {"track_ref": reference, "track_status": "ambiguous", "track": None,
                "track_match_count": len(matches)}
    omissions = []
    projected = _bounded_value(matches[0], MAX_TRACK_FIELDS_BYTES, "track", omissions)
    result = {"track_ref": reference, "track_status": "resolved", "track": projected}
    if omissions:
        result["track_omitted_fields"] = omissions
    return result


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


def _asset(clip, registries):
    """Resolve a media alias in its nearest pinned owner scope.

    Internal timeline registries are passed before the shot and parent
    registries. A repeated local key is therefore resolved from the first
    scope that owns it instead of being joined globally by its alias.
    """
    key = clip.get("asset", clip.get("asset_id", clip.get("assetId")))
    candidates = []
    omissions = []
    if isinstance(key, str):
        for scope, assets in registries:
            if isinstance(assets, dict) and key in assets and isinstance(assets[key], dict):
                metadata = assets[key]
                media_name = next((metadata.get(name) for name in (
                    "media_name", "friendly_name", "display_name", "name", "title",
                    "original_name", "filename",
                ) if isinstance(metadata.get(name), str) and metadata.get(name).strip()), None)
                if media_name is None and isinstance(metadata.get("file"), str) and metadata["file"].strip():
                    media_name = metadata["file"].replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
                candidates.append({
                    "scope": scope,
                    "source_object_id": metadata.get("source_object_id") or metadata.get("media_id") or metadata.get("object_id"),
                    "content_digest": next((metadata.get(name) for name in ("content_sha256", "digest", "sha256", "hash") if metadata.get(name) is not None), None),
                    "media_type": metadata.get("media_type") or metadata.get("type"),
                    "media_name": media_name,
                    "source_provenance": metadata.get("provenance"),
                })
    # This list is ordered from the clip's immediate pinned owner outwards.
    # Use the first matching registry entry even when another scope happens
    # to reuse its local key; the alias is not a global media identifier.
    resolved = candidates[0] if candidates else None
    direct_object = next((clip.get(name) for name in ("source_object_id", "source_media_id", "media_id", "object_id") if isinstance(clip.get(name), str)), None)
    direct_digest = next((clip.get(name) for name in ("content_sha256", "content_digest", "digest", "sha256", "hash") if isinstance(clip.get(name), str)), None)
    if resolved is not None:
        source_object_id, content_digest, media_type = resolved["source_object_id"], resolved["content_digest"], resolved["media_type"]
        media_name = resolved["media_name"]
        provenance = {"resolution": "registry", "registry_key": key,
                      "registry_scope": resolved["scope"],
                      "registry_scopes": [resolved["scope"]], "candidate_count": 1}
        source_provenance = resolved["source_provenance"]
    else:
        source_object_id = direct_object
        content_digest = direct_digest
        media_type = clip.get("media_type") or clip.get("type")
        media_name = next((clip.get(name) for name in ("media_name", "filename", "original_name")
                           if isinstance(clip.get(name), str) and clip.get(name).strip()), None)
        provenance = {"resolution": "clip_fields" if direct_object or direct_digest else "unresolved",
                      "source_fields": [name for name in ("source_object_id", "source_media_id", "media_id", "object_id") if name in clip]}
        source_provenance = clip.get("provenance")
    bounded = {}
    for name, value in (("asset_id", key), ("source_object_id", source_object_id),
                        ("content_digest", content_digest), ("media_type", media_type),
                        ("media_name", media_name),
                        ("source_provenance", source_provenance), ("source_uuid", clip.get("source_uuid"))):
        bounded[name] = _bounded_value(value, MAX_AUTHORED_VALUE_BYTES, name, omissions) if value is not None else None
    result = {"asset_id": bounded["asset_id"], "source_object_id": bounded["source_object_id"],
              "content_digest": bounded["content_digest"], "media_name": bounded["media_name"],
              "kind": bounded["media_type"],
              "media_type": bounded["media_type"], "media_provenance": provenance,
              "source_provenance": bounded["source_provenance"], "source_uuid": bounded["source_uuid"]}
    if omissions:
        result["omitted_fields"] = omissions
    return result


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


def _clip(raw, registries, occurrence, start, end, track_scope, tracks):
    if not isinstance(raw, dict):
        raise ConflictError("pinned internal timeline contains an invalid clip")
    cid = raw.get("id")
    if not isinstance(cid, str) or not cid:
        raise ConflictError("pinned internal clip has no identity")
    relative = _fraction(raw.get("at_ms", raw.get("at", 0)), "clip start", milliseconds="at_ms" in raw, nonnegative=False)
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
    visible_start = max(absolute, start)
    visible_end = min(absolute + duration, end)
    if duration < 0 or visible_end <= visible_start or absolute >= end:
        return None
    clip_end = absolute + duration
    asset = _asset(raw, registries)
    authored = _authored_projection(raw)
    result = {"occurrence_id": occurrence["occurrence_id"], "shot_id": occurrence["shot_id"],
            "clip_id": cid, "track_id": raw.get("track"), "clip_type": raw.get("clipType", raw.get("clip_type", raw.get("type", "media"))),
            "start": _wire(visible_start), "duration": _wire(visible_end - visible_start), "source_from": raw.get("from_ms", raw.get("from")),
            "source_to": raw.get("to_ms", raw.get("to")), "speed": _wire(speed), "gain": raw.get("volume", 1),
            "mute": bool(raw.get("mute", False)), "text": raw.get("text", ""),
            "time_bounds": {"timeline_start": _wire(visible_start), "timeline_end": _wire(visible_end),
                            "declared_start": _wire(absolute), "declared_end": _wire(clip_end),
                            "start_clipped_to_occurrence": visible_start > absolute,
                            "end_clipped_to_occurrence": visible_end < clip_end},
            **_track_projection(raw.get("track"), track_scope, tracks), **authored, **asset}
    if isinstance(result.get("text"), (str, dict, list)):
        omissions = result.setdefault("omitted_fields", [])
        bounded_text = _bounded_value(result["text"], 2000, "text", omissions)
        result["text"] = bounded_text if bounded_text is not None else ""
    elif "text" in result:
        result["text"] = ""
    return result


def _canonical_parent_clips(payload):
    """Resolve the canonical parent clip list without merging authorities."""
    if not isinstance(payload, dict):
        raise ConflictError("canonical parent composition payload is invalid")
    config = payload.get("config", {})
    parent_clips = payload.get("clips", [])
    config_clips = config.get("clips", []) if isinstance(config, dict) else None
    if not isinstance(parent_clips, list) or not isinstance(config_clips, list):
        raise ConflictError("canonical parent composition clips are invalid")
    if config_clips and parent_clips and config_clips != parent_clips:
        raise ConflictError("canonical parent clips and config.clips disagree")
    return parent_clips or config_clips


def _parent_clip(raw, registries, track_scope, tracks):
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
    asset = _asset(raw, registries)
    authored = _authored_projection(raw)
    result = {
        "target_kind": "parent_clip", "clip_id": cid, "track_id": raw.get("track"),
        "clip_type": raw.get("clipType", raw.get("clip_type", raw.get("type", "media"))),
        "start": _wire(start), "duration": _wire(duration),
        "source_from": raw.get("from_ms", raw.get("from")), "source_to": raw.get("to_ms", raw.get("to")),
        "speed": _wire(speed), "gain": raw.get("volume", raw.get("gain", 1)),
        "mute": bool(raw.get("mute", False)), "text": raw.get("text", ""),
        "time_bounds": {"timeline_start": _wire(start), "timeline_end": _wire(start + duration),
                        "declared_end": _wire(start + duration), "end_clipped_to_occurrence": False},
        **_track_projection(raw.get("track"), track_scope, tracks), **authored, **asset,
    }
    if isinstance(result.get("text"), (str, dict, list)):
        omissions = result.setdefault("omitted_fields", [])
        bounded_text = _bounded_value(result["text"], 2000, "text", omissions)
        result["text"] = bounded_text if bounded_text is not None else ""
    elif "text" in result:
        result["text"] = ""
    return result



def _render_timing_clip(raw):
    """Normalize existing millisecond wire aliases for managed shot expansion."""
    clip = dict(raw)
    for seconds, milliseconds in (("at", "at_ms"), ("from", "from_ms"), ("to", "to_ms")):
        if milliseconds in raw:
            clip[seconds] = float(_fraction(raw[milliseconds], milliseconds, milliseconds=True,
                                           nonnegative=seconds != "at"))
    clip.setdefault("at", 0)
    if "hold" not in clip and "duration_ms" in raw:
        clip["hold"] = float(_fraction(raw["duration_ms"], "duration_ms", milliseconds=True))
    clip.setdefault("clipType", raw.get("clip_type", raw.get("type", "media")))
    return clip


def _timing_record(raw, timing_id):
    result = {key: raw[key] for key in ("at", "hold", "from", "to", "speed", "track", "clipType", "transition", "elementRef", "volume", "opacity")
              if key in raw}
    result["id"] = timing_id
    # Scheduling needs identity/duration only, never the transition's opaque
    # component parameters or extension bytes. Keep original authored values
    # under their existing independent omission contract.
    if isinstance(result.get("transition"), dict):
        result["transition"] = {key: result["transition"][key]
                                for key in ("id", "type", "durationFrames", "duration")
                                if key in result["transition"]}
    if isinstance(result.get("elementRef"), dict):
        result["elementRef"] = {key: result["elementRef"][key]
                                for key in ("id", "kind", "revision") if key in result["elementRef"]}
    return result if len(_value_bytes(result)) <= MAX_AUTHORED_VALUE_BYTES else None


def _attach_render_timing(projected, raw_clips, occurrence, registry):
    """Use the same shot clipping producer as managed rendering, before selection."""
    reason = None
    if occurrence.get("speed", 1) != 1 or occurrence.get("source_offset", 0) != 0:
        reason = "managed shot expansion does not apply occurrence speed/source_offset"
    try:
        if reason:
            raise ShotExpansionError(reason)
        child = {"clips": [_render_timing_clip(raw) for raw in raw_clips]}
        parent = {"clips": [{"id": "inspection-shot", "clipType": "shot",
                            "at": float(Fraction(*occurrence["start"])),
                            "hold": float(Fraction(*occurrence["duration"])),
                            "track": occurrence.get("track_id"),
                            "params": {"shot_id": occurrence["shot_id"], "timeline_document_id": "pinned"}}]}
        expanded, _ = expand_shot_clips(parent, {"assets": {}},
                                       load_timeline=lambda _: (child, registry))
        by_source = {row["app"]["astrid_shot_composition"]["source_clip_id"]: row
                     for row in expanded["clips"]}
        for row in projected:
            expanded_clip = by_source.get(row["clip_id"])
            if expanded_clip is None:
                row["render_timing_unknown"] = "clip absent from managed shot expansion"
            else:
                row["render_timing"] = _timing_record(
                    expanded_clip, canonical_json([occurrence["occurrence_id"], row["clip_id"]]))
                if row["render_timing"] is None:
                    row["render_timing_unknown"] = "managed render timing fields exceed 4096-byte bound"
                    continue
                row["render_timing"]["target"] = {"occurrence_id": occurrence["occurrence_id"],
                    "clip_id": row["clip_id"], "shot_id": occurrence["shot_id"],
                    "internal_timeline_revision_id": occurrence["internal_timeline_revision_id"]}
    except (ShotExpansionError, ValidationError, TypeError, ValueError) as exc:
        for row in projected:
            row["render_timing_unknown"] = "managed shot expansion unavailable: " + str(exc)


def _render_timing_context(config, parent_tracks, parent_clips, children, *, transition_free):
    """Bounded complete scheduling input; absence never implies absent siblings."""
    output = config.get("output") if isinstance(config.get("output"), dict) else {}
    overrides = config.get("theme_overrides") if isinstance(config.get("theme_overrides"), dict) else {}
    visual = overrides.get("visual") if isinstance(overrides.get("visual"), dict) else {}
    canvas = visual.get("canvas") if isinstance(visual.get("canvas"), dict) else {}
    fps = output.get("fps", canvas.get("fps", 30))
    # These are compositor parent dispatch facts, separate from each child's
    # authored scoped track. Keep only the fields consumed by the pinned
    # AudioTrack/VisualClip/visual-track inheritance contracts.
    tracks = [{key: row[key] for key in ("id", "kind", "muted", "volume", "opacity", "blendMode") if key in row} for row in
              (parent_tracks if isinstance(parent_tracks, list) else []) if isinstance(row, dict)]
    # A transition-free page can still use ordinary per-clip duration helpers
    # when its actual compositor track is proven; no full sibling list needed.
    bounded_tracks = tracks if len(_value_bytes(tracks)) <= MAX_AUTHORED_VALUE_BYTES else []
    fallback = {"status": "unavailable", "fps": fps, "transition_free": transition_free,
                "tracks": bounded_tracks}
    all_clips = parent_clips + [clip for _, clips in children for clip in clips]
    if any(not isinstance(clip.get("render_timing"), dict) for clip in all_clips):
        return {**fallback, "reason": "one or more closure clips lack managed render timing"}
    context = {"status": "complete", "fps": fps, "transition_free": transition_free,
               "tracks": tracks, "clips": [clip["render_timing"] for clip in all_clips]}
    if len(_value_bytes(context)) > 32768:
        return {**fallback, "reason": "complete render scheduling context exceeds 32768-byte bound"}
    return context

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
    parent_clips_raw = _canonical_parent_clips(payload)
    occurrences = payload.get("occurrences")
    if not isinstance(occurrences, list) or len(occurrences) > MAX_OCCURRENCES:
        raise ValidationError("timeline has too many occurrences; narrow the revision")
    children = []
    parent_registry = {"assets": {}}
    source_registry = payload.get("registry")
    assets = source_registry.get("assets") if isinstance(source_registry, dict) else None
    if isinstance(assets, dict):
        parent_registry["assets"].update(assets)
    config = payload.get("config") if isinstance(payload.get("config"), dict) else {}
    parent_tracks_raw = config.get("tracks", payload.get("tracks", []))
    parent_tracks = _track_catalog(parent_tracks_raw)
    parent_track_scope = {"kind": "parent_composition", "id": revision}
    seen = set()
    closure_clips = 0
    has_render_transitions = any(raw.get("transition") for raw in parent_clips_raw)
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
        internal_registry = {"assets": {}}
        source_registry = internal_payload.get("registry")
        assets = source_registry.get("assets") if isinstance(source_registry, dict) else None
        if isinstance(assets, dict):
            internal_registry["assets"].update(assets)
        shot_assets = {}
        for asset in shot_payload.get("assets", []):
            if isinstance(asset, dict) and isinstance(asset.get("asset_id"), str):
                shot_assets[asset["asset_id"]] = {"media_id": asset.get("object_id"), "content_sha256": asset.get("digest"),
                                                    "media_type": asset.get("media_type"), "provenance": asset.get("provenance")}
        registries = [
            (f"internal_timeline:{internal_id}", internal_registry["assets"]),
            (f"shot_revision:{shot_revision_id}", shot_assets),
            (f"parent_composition:{revision}", parent_registry["assets"]),
        ]
        clips = internal_payload.get("clips", [])
        if not isinstance(clips, list):
            raise ConflictError("pinned shot clips are invalid")
        has_render_transitions = has_render_transitions or any(raw.get("transition") for raw in clips if isinstance(raw, dict))
        closure_clips += len(clips)
        if closure_clips > MAX_CLOSURE_CLIPS:
            raise ValidationError("timeline closure exceeds clip limit; narrow the revision")
        track_id = raw.get("track")
        if track_id is None:
            track_id = placement.get("track")
        occurrence_track = _track_projection(track_id, parent_track_scope, parent_tracks)
        text_bindings = shot_payload.get("text_bindings", [])
        if isinstance(text_bindings, list):
            # Keep old, unregistered descriptors readable for historical
            # compositions while making their weaker provenance explicit.
            text_bindings = [
                ({**item, "authority": "shot_text_binding"} if isinstance(item, dict) and item.get("binding_id")
                 else ({**item, "authority": "legacy_unregistered"} if isinstance(item, dict) else item))
                for item in text_bindings
            ]
        identity = {"ordinal": ordinal, "occurrence_id": occurrence_id, "shot_id": shot_id,
                    "shot_revision_id": shot_revision_id, "shot_digest": shot["content_digest"],
                    "internal_timeline_revision_id": internal_id, "internal_timeline_digest": internal["content_digest"],
                    "name": _shot_name(shot_payload, shot_id),
                    "start": _wire(start), "duration": _wire(duration), "track_id": track_id,
                    **occurrence_track,
                    "source_offset": raw.get("source_offset", 0), "speed": raw.get("speed", 1),
                    "gain": raw.get("gain", 1), "mute": bool(raw.get("muted", raw.get("mute", False))),
                    "text_bindings": text_bindings,
                    "audio_bindings": shot_payload.get("audio_bindings", [])}
        internal_tracks = _track_catalog(internal_payload.get("tracks", []))
        internal_track_scope = {"kind": "internal_timeline", "id": internal_id}
        for binding_key in ("text_bindings", "audio_bindings"):
            binding_value = identity.get(binding_key)
            omissions = []
            if binding_value is not None:
                identity[binding_key] = _bounded_value(binding_value, MAX_BINDINGS_BYTES, binding_key, omissions)
            if omissions:
                identity.setdefault("omitted_fields", []).extend(omissions)
        projected = [item for clip in clips if (item := _clip(clip, registries, identity, start, start + duration,
                                                              internal_track_scope, internal_tracks)) is not None]
        _attach_render_timing(projected, clips, identity, {"assets": {**parent_registry["assets"], **shot_assets, **internal_registry["assets"]}})
        children.append((identity, projected))

    parent_registries = [(f"parent_composition:{revision}", parent_registry["assets"])]
    parent_clips = [item for raw in parent_clips_raw if (item := _parent_clip(
        raw, parent_registries, parent_track_scope, parent_tracks
    )) is not None]
    raw_parent_by_id = {raw["id"]: raw for raw in parent_clips_raw}
    for row in parent_clips:
        row["render_timing"] = _timing_record(_render_timing_clip(raw_parent_by_id[row["clip_id"]]),
                                               canonical_json(["parent", row["clip_id"]]))
        if row["render_timing"] is None:
            row["render_timing_unknown"] = "managed render timing fields exceed 4096-byte bound"
            continue
        row["render_timing"]["target"] = {"target_kind": "parent_clip", "clip_id": row["clip_id"],
                                          "revision_id": revision}
    render_timing_context = _render_timing_context(config, parent_tracks_raw, parent_clips, children, transition_free=not has_render_transitions)
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
    selected_clip_count = sum(len(row["clips"]) for row in page_rows) + len(selected_parent_page)
    omitted_authored_fields = sum(
        len(clip.get("omitted_fields", []))
        for clip in [item for row in page_rows for item in row["clips"]] + selected_parent_page
    ) + sum(len(row["occurrence"].get("omitted_fields", [])) for row in page_rows)
    result = {"schema": SCHEMA, "evidence_kind": "declared_inputs", "render_requested": False,
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
            "selected_clip_count": selected_clip_count,
            "bounds": {"max_occurrences": MAX_OCCURRENCES, "max_selected_clips_per_page": MAX_SELECTED_CLIPS,
                       "max_closure_clips": MAX_CLOSURE_CLIPS,
                       "max_authored_value_bytes": MAX_AUTHORED_VALUE_BYTES,
                       "max_authored_fields_bytes_per_clip": MAX_AUTHORED_FIELDS_BYTES,
                       "max_track_fields_bytes": MAX_TRACK_FIELDS_BYTES,
                       "max_bindings_bytes": MAX_BINDINGS_BYTES,
                       "max_response_bytes": MAX_RESPONSE_BYTES},
            "page": {"offset": offset, "limit": options["limit"], "total_selected_clips": total_clips,
                     "returned_clips": selected_clip_count, "remaining_clips": total_clips - end_offset,
                     "has_continuation": next_cursor is not None, "response_bytes": 0},
            "omission_metadata": {"authored_values_omitted": omitted_authored_fields,
                                  "page_continuation_omits_clips": total_clips - end_offset},
            "selected": page_rows, "selected_parent_clips": selected_parent_page, "next_cursor": next_cursor,
            "render_timing_context": render_timing_context}

    # The transport cap is independent of per-field authored caps. If several
    # otherwise valid clips make one page too large, shrink only at clip
    # boundaries and advance the cursor to the exact returned count. This keeps
    # identity/cursor metadata truthful instead of silently truncating a field
    # or claiming that the full requested page was returned.
    def refresh_surviving_page_metadata() -> int:
        """Recompute all page-scoped counts after any clip-boundary shrink."""
        returned = len(result["selected_parent_clips"]) + sum(
            len(row["clips"]) for row in result["selected"]
        )
        cursor_end = offset + returned
        omitted = sum(
            len(clip.get("omitted_fields", []))
            for clip in [
                item
                for row in result["selected"]
                for item in row["clips"]
            ] + result["selected_parent_clips"]
        ) + sum(
            len(row["occurrence"].get("omitted_fields", []))
            for row in result["selected"]
        )
        result["selected_clip_count"] = returned
        result["page"]["returned_clips"] = returned
        result["page"]["remaining_clips"] = total_clips - cursor_end
        result["page"]["has_continuation"] = cursor_end < total_clips
        result["omission_metadata"]["authored_values_omitted"] = omitted
        result["omission_metadata"]["page_continuation_omits_clips"] = total_clips - cursor_end
        result["next_cursor"] = _encode_cursor(scope, cursor_end) if cursor_end < total_clips else None
        return returned

    def response_size() -> int:
        """Measure the final serialized result, including its byte-count field."""
        # The reported value changes its own JSON size at digit boundaries.
        # Iterate to a fixed point so the public field equals the final byte
        # count rather than the response size before metadata was appended.
        for _ in range(10):
            measured = len(canonical_json(result).encode("utf-8"))
            if result["page"]["response_bytes"] == measured:
                return measured
            result["page"]["response_bytes"] = measured
        raise ValidationError("timeline inspection response byte count did not stabilize")

    refresh_surviving_page_metadata()

    while response_size() > MAX_RESPONSE_BYTES:
        if result["selected_parent_clips"]:
            result["selected_parent_clips"].pop()
        else:
            removed = False
            for row in reversed(result["selected"]):
                if row["clips"]:
                    row["clips"].pop()
                    removed = True
                    if not row["clips"]:
                        result["selected"].remove(row)
                    break
            if not removed:
                raise ValidationError("timeline inspection response exceeds byte budget; narrow the revision or selectors")
        refresh_surviving_page_metadata()
    # One final fixed-point measurement confirms the returned field describes
    # these exact serialized bytes and remains inside the declared transport cap.
    if response_size() > MAX_RESPONSE_BYTES:
        raise ValidationError("timeline inspection response exceeds byte budget; narrow the revision or selectors")
    return result
