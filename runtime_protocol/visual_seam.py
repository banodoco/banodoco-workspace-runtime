"""Authoritative metadata admission for one-level immutable compositions.

Publication and render call this inside their existing transaction. Derived
reports never replace authored bytes. No media/decoder/plugin imports.
"""
from __future__ import annotations

import bisect
import copy
import hashlib
import json
import math
from collections import defaultdict

from .errors import ConflictError, NotFoundError, ValidationError
from .util import canonical_json
from .visual_boundary import VERSION, DISCLOSURE_VERSION, boundary_report, finite, js_round

MAX_METADATA_CLIPS = 20_000
AUXILIARY = frozenset({"end-spanning-layer", "effect-layer", "frame-overlay", "text"})
PICTURE = frozenset({"media", "hold", "video", "image", "animated-media-transform", "com.reigh.astrid.liveScene"})


def active(clip):
    return (clip.get("enabled") is not False and clip.get("active") is not False
            and clip.get("disabled") is not True and clip.get("hidden") is not True and clip.get("deleted") is not True)


def seconds(clip, key, fallback=0):
    return finite(clip.get(key + "_ms"), fallback * 1000) / 1000 if key + "_ms" in clip else finite(clip.get(key), fallback)


def speed_value(value):
    if isinstance(value, dict):
        value = finite(value.get("numerator"), 0) / finite(value.get("denominator"), 1)
    result = finite(value, None)
    if result is None or result <= 0:
        raise ValidationError("visual timing speed must be positive")
    return result


def clip_seconds(clip, fallback=0, *, speed=None):
    if "hold" in clip:
        value = finite(clip["hold"], None)
    elif "duration_ms" in clip:
        value = finite(clip["duration_ms"], None)
        value = value / 1000 if value is not None else None
    elif "duration" in clip:
        value = finite(clip["duration"], None)
    elif "to" in clip or "to_ms" in clip:
        value = seconds(clip, "to") - seconds(clip, "from")
    else:
        value = fallback
    if value is None or value < 0:
        raise ValidationError("visual timing duration must be finite and non-negative")
    return value / (speed if speed is not None else speed_value(clip.get("speed", 1)))


def parent_clips(parent):
    clips, configured = parent.get("clips", []), parent.get("config", {}).get("clips", [])
    if not isinstance(clips, list) or not isinstance(configured, list):
        raise ValidationError("canonical parent clips must be lists")
    if clips and configured and clips != configured:
        raise ConflictError("canonical parent clips and config.clips disagree")
    return clips or configured


def load_closure(conn, project_id, timeline_id, parent_row):
    """Read exact pinned bytes, including bodies omitted by render callers."""
    def verified(row, kind):
        if row is None:
            raise NotFoundError(f"canonical {kind} dependency is missing")
        if row["project_id"] != project_id:
            raise ConflictError(f"canonical {kind} dependency belongs to a different project")
        payload = json.loads(row["payload_json"])
        digest = "sha256:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        if digest != row["content_digest"]:
            raise ConflictError(f"canonical {kind} revision content integrity failed")
        return payload

    if parent_row["timeline_id"] != timeline_id:
        raise ConflictError("canonical parent has a different timeline identity")
    parent = verified(parent_row, "parent")
    shots, internal = {}, {}
    for o in parent.get("occurrences", []):
        key = (o["shot_id"], o["shot_revision_id"])
        if key in shots:
            continue
        row = conn.execute("SELECT * FROM shot_revisions WHERE id=? AND shot_id=?", (key[1], key[0])).fetchone()
        payload = verified(row, "shot")
        pin = row["internal_timeline_revision_id"]
        if payload.get("internal_timeline_revision_id") != pin:
            raise ConflictError("canonical shot internal pin disagrees with its bytes")
        shots[key] = {"payload": payload, "internal_timeline_revision_id": pin}
        if pin not in internal:
            child = conn.execute("SELECT * FROM internal_timeline_revisions WHERE id=?", (pin,)).fetchone()
            internal[pin] = {"payload": verified(child, "internal timeline")}
    return parent, shots, internal


def _strip_derived(value):
    if isinstance(value, dict):
        # Most authored clips have no app/report/intent. Keep their immutable
        # JSON object without allocating an identical recursive copy.
        if not any(k in value for k in ("app", "intents", "report", "visualSeamIntents", "visual_seam_report")):
            return value
        return {k: _strip_derived(v) for k, v in value.items() if k not in ("intents", "report", "visualSeamIntents", "visual_seam_report")}
    if isinstance(value, list):
        return [_strip_derived(v) for v in value]
    return value


def normalize_closure(parent, shots, internal, *, timeline_id, materialize=False):
    """Authored geometry plus effective spans. No mutable heads or clipping loss."""
    config = parent.get("config", {})
    fps = finite((config.get("output") or {}).get("fps", config.get("fps", 30)), None)
    if fps is None or fps <= 0:
        raise ValidationError("visual timing fps must be finite and positive")
    policy = (config.get("app") or {}).get("visualSeamContract") or {}
    tracks = {t["id"]: t for t in config.get("tracks", []) if isinstance(t, dict) and "id" in t}
    explicit = policy.get("continuityTracks")
    continuity = set(explicit) if isinstance(explicit, list) else {k for k, t in tracks.items() if t.get("kind") == "visual"}
    # Canonical occurrence tracks are explicit editorial picture lanes.
    if explicit is None:
        continuity.update(o["track"] for o in parent.get("occurrences", []))
    spans, occurrences, structural = [], [], []
    render_config = copy.deepcopy(config) if materialize else None
    render_registry = copy.deepcopy(parent.get("registry", {})) if materialize else None
    if materialize:
        render_config["clips"] = []
        render_registry.setdefault("assets", {})
    occurrence_groups = defaultdict(list)
    for o in parent.get("occurrences", []):
        occurrence_groups[o["track"]].append(o)
    next_start = {}
    for group in occurrence_groups.values():
        ordered = sorted(group, key=lambda o: seconds(o, "at", finite(o.get("placement", {}).get("start_ms"), 0) / 1000))
        for a, b in zip(ordered, ordered[1:]):
            next_start[a["occurrence_id"]] = seconds(b, "at", finite(b.get("placement", {}).get("start_ms"), 0) / 1000)

    def add(raw, registry, path, *, offset=0, bound=None, inherited_speed=1, inherited_track=None, source_offset=0, inherited_gain=1, muted=False, render=True):
        if not isinstance(raw, dict):
            raise ValidationError("canonical clips must be objects")
        if not active(raw):
            return
        clip = dict(raw)
        kind = clip.get("clipType", clip.get("clip_type", "media"))
        if kind in ("shot", "composition", "sequence"):
            raise ValidationError("nested composition is not supported by visual admission")
        clip["clipType"] = kind
        clip["speed"] = speed_value(clip.get("speed", inherited_speed))
        at = seconds(clip, "at")
        if finite(clip.get("at_ms", clip.get("at", 0)), None) is None:
            raise ValidationError("visual timing start must be finite")
        duration = clip_seconds(clip, (bound[1] - offset) * clip["speed"] if bound else 0, speed=clip["speed"])
        track = clip.get("track", inherited_track or "video")
        primary = track in continuity and kind in PICTURE and kind not in AUXILIARY
        if at < 0 or offset + at < 0:
            structural.append({"code": "boundary/negative-start", "path": path})
        raw_start = js_round((offset + at) * fps)
        raw_end = raw_start + max(1, js_round(duration * fps))
        start, end = raw_start, raw_end
        if bound:
            lower, upper = js_round(bound[0] * fps), math.ceil(bound[1] * fps - 1e-9)
            if primary and (raw_start < lower or raw_end > upper):
                structural.append({"code": "boundary/owner-overhang", "path": path, "startFrame": raw_start, "endFrame": raw_end, "ownerEndFrame": upper})
            start, end = max(start, lower), min(end, upper)
        if end <= start:
            return
        clip["at"] = (offset + at)
        clip.pop("at_ms", None)
        if "duration_ms" in clip or "duration" in clip:
            clip["hold"] = duration * clip["speed"]
            clip.pop("duration_ms", None)
            clip.pop("duration", None)
        if "from" in clip or "from_ms" in clip:
            clip["from"] = seconds(raw, "from") + source_offset
            clip.pop("from_ms", None)
        if "to" in clip or "to_ms" in clip:
            clip["to"] = seconds(raw, "to") + source_offset
            clip.pop("to_ms", None)
        asset_key = clip.get("asset", clip.get("asset_id"))
        asset = (registry.get("assets") or {}).get(asset_key, {})
        source = next((asset[k] for k in ("content_sha256", "object_id", "media_id", "digest", "file") if isinstance(asset.get(k), str)), None)
        disclosure = boundary_report({"clip": clip, "params": clip.get("params", {}), "fps": fps, "startFrame": start, "endFrame": end,
                                      "originFrame": raw_start, "path": path, "source": source, "sourceType": asset.get("type", "")})
        spans.append({"path": path, "track": track, "startFrame": start, "endFrame": end, "rawStartFrame": raw_start, "rawEndFrame": raw_end,
                      "primary": primary, "source": source, "clip": clip, "disclosure": disclosure})
        # Materialization is deliberately outside metadata evaluator timing.
        if not materialize or not render:
            rendered = None
        else:
            rendered = copy.deepcopy(clip)
        if rendered is not None:
            rendered["id"] = path[-1] if len(path) == 4 else path[3] + ":" + path[-1]
            rendered["track"] = track
            rendered["volume"] = 0 if muted else finite(clip.get("volume", clip.get("gain", inherited_gain)), 1)
        if rendered is not None and bound:
            rendered.setdefault("app", {})["canonical"] = {"parentDocumentId": timeline_id, "occurrenceId": path[3], "sourceClipId": path[-1]}
            rendered["app"]["canonicalTiming"] = {"occurrenceStartMs": bound[0] * 1000, "occurrenceDurationMs": (bound[1] - bound[0]) * 1000}
            visible_seconds = (end - start) / fps
            rendered["at"] = start / fps
            if "hold" in rendered or "to" not in rendered:
                rendered["hold"] = visible_seconds * rendered["speed"]
            else:
                rendered["to"] = rendered.get("from", 0) + visible_seconds * rendered["speed"]
            if isinstance(asset_key, str):
                qualified = path[3] + ":" + asset_key
                rendered["asset"] = qualified
                render_registry["assets"][qualified] = copy.deepcopy(asset)
        if rendered is not None:
            render_config["clips"].append(rendered)
        for i, effect in enumerate(raw.get("effects", [])):
            # Nested supported effects participate, but unsupported time semantics
            # remain opaque instead of invoking an interpreter.
            if not isinstance(effect, dict):
                raise ValidationError("clip effects must be objects")
            effect_clip = {"id": effect.get("id", str(i)), "clipType": effect.get("type", "unknown"), "at": clip["at"], "hold": duration,
                           "params": effect.get("params", effect), "track": track}
            effect_path = path + ["effect", str(effect_clip["id"])]
            d = boundary_report({"clip": effect_clip, "fps": fps, "startFrame": start, "endFrame": end, "originFrame": raw_start, "path": effect_path, "source": source})
            spans.append({"path": effect_path, "track": track, "startFrame": start, "endFrame": end, "rawStartFrame": raw_start, "rawEndFrame": raw_end,
                          "primary": False, "source": source, "clip": effect_clip, "disclosure": d})

    for raw in parent_clips(parent):
        add(raw, parent.get("registry", {}), ["parent", timeline_id, "clip", str(raw.get("id", "?"))])
    for o in parent.get("occurrences", []):
        shot = shots.get((o["shot_id"], o["shot_revision_id"]))
        if shot is None:
            raise NotFoundError("canonical shot closure is incomplete")
        pin = shot["internal_timeline_revision_id"]
        child = internal.get(pin)
        if child is None:
            raise NotFoundError("canonical internal closure is incomplete")
        body = child["payload"]
        clips = body.get("clips", body.get("local_clips", []))
        if not isinstance(clips, list):
            raise ValidationError("canonical child clips must be a list")
        offset = seconds(o, "at", finite(o.get("placement", {}).get("start_ms"), 0) / 1000)
        fallback_duration = o["duration_ms"] / 1000
        inherited_speed = speed_value(o.get("speed", 1))
        extent = max((seconds(c, "at") + clip_seconds({**c, "speed": c.get("speed", inherited_speed)}, fallback_duration * inherited_speed) for c in clips if active(c)), default=fallback_duration)
        extent = math.ceil(extent * 1000 - 1e-6) / 1000
        end = min(offset + extent, next_start.get(o["occurrence_id"], offset + extent))
        path = ["parent", timeline_id, "occurrence", o["occurrence_id"]]
        occurrences.append({"path": path, "track": o["track"], "startFrame": js_round(offset * fps), "endFrame": math.ceil(end * fps - 1e-9),
                            "rawEndFrame": js_round((offset + extent) * fps), "clip": o, "source": o["shot_revision_id"], "primary": o["track"] in continuity})
        if offset < 0 or end <= offset:
            structural.append({"code": "boundary/invalid-occurrence", "path": path})
        source_offset = o.get("source_offset", o.get("source_offset_ms", 0))
        if isinstance(source_offset, dict):
            source_offset = source_offset.get("start", 0)
        source_offset = finite(source_offset) / 1000
        for c in clips:
            track = c.get("track", o["track"])
            for t in body.get("tracks", []):
                if explicit is None and isinstance(t, dict) and t.get("id") == track and t.get("kind") == "visual" and c.get("clipType", c.get("clip_type", "media")) in PICTURE:
                    continuity.add(track)
            add(c, body.get("registry", {}), path + ["clip", str(c.get("id", "?"))], offset=offset, bound=(offset, end), inherited_speed=inherited_speed,
                inherited_track=o["track"], source_offset=source_offset, inherited_gain=o.get("gain", 1), muted=o.get("muted", o.get("mute", False)))
        for i, e in enumerate(body.get("effects", [])):
            add({**e, "id": e.get("id", str(i)), "clipType": e.get("type", "unknown"), "hold": e.get("hold", end - offset), "track": e.get("track", "fx")},
                body.get("registry", {}), path + ["effect", str(e.get("id", i))], offset=offset, bound=(offset, end), render=False)
    for i, e in enumerate(config.get("effects", [])):
        if isinstance(e, dict):
            add({**e, "id": e.get("id", str(i)), "clipType": e.get("type", "unknown"), "hold": e.get("hold", max((s["endFrame"] / fps for s in spans), default=1)), "track": e.get("track", "fx")},
                parent.get("registry", {}), ["parent", timeline_id, "effect", str(e.get("id", i))], render=False)
    if len(spans) > MAX_METADATA_CLIPS:
        raise ValidationError("visual seam metadata exceeds the bounded clip limit")
    return {"fps": fps, "policy": policy, "spans": spans, "occurrences": occurrences, "structural": structural,
            "render_config": render_config, "render_registry": render_registry}


def cue_identity(cue):
    return "/".join(cue["path"]) + ":" + cue["kind"] + ":" + cue["id"] + ":" + str(cue["frame"])


def _transition(a, b, fps):
    transition = b["clip"].get("transition")
    if not isinstance(transition, dict) or not isinstance(transition.get("type"), str):
        return False
    duration = finite(transition.get("duration"), 0)
    # Existing incoming transition owns precisely this incoming pre-roll.
    return duration > 0 and 0 < a["endFrame"] - b["startFrame"] <= js_round(duration * fps)


def analyze_normalized(metadata):
    fps, policy, spans = metadata["fps"], metadata["policy"], metadata["spans"]
    issues = list(metadata["structural"])
    candidates = defaultdict(list)
    groups = defaultdict(list)
    for s in spans:
        if s["primary"]:
            groups[(s["track"], tuple(s["path"][:4]) if "occurrence" in s["path"] else ("parent",))].append(s)
    for o in metadata["occurrences"]:
        if o["primary"]:
            groups[(o["track"], ("parent",))].append(o)
    for (track, _), rows in groups.items():
        ordered = sorted(rows, key=lambda s: (s["startFrame"], s["endFrame"]))
        furthest = None
        for b in ordered:
            if furthest is not None:
                a = furthest
                frame = b["startFrame"]
                gap = frame - a.get("rawEndFrame", a["endFrame"])
                valid_transition = _transition(a, b, fps)
                pause = any(isinstance(p, dict) and p.get("kind") == "pause" and p.get("track") == track
                            and p.get("startFrame") == a["endFrame"] and p.get("endFrame") == frame for p in policy.get("gaps", []))
                if gap < 0 and not valid_transition:
                    issues.append({"code": "boundary/overlap", "frame": frame, "paths": [a["path"], b["path"]], "frames": -gap})
                elif gap > 0 and not pause:
                    issues.append({"code": "boundary/gap", "frame": frame, "paths": [a["path"], b["path"]], "frames": gap})
                candidates[frame].extend([a, b])
            if furthest is None or b["rawEndFrame"] > furthest["rawEndFrame"]:
                furthest = b
    cues = []
    for s in spans:
        cues.extend(s["disclosure"]["cues"])
    cues.sort(key=lambda c: (c["frame"], cue_identity(c)))
    frames = [c["frame"] for c in cues]
    opaque = sorted((s for s in spans if s["disclosure"]["opaque"]), key=lambda s: s["startFrame"])
    live_opaque, cursor, boundaries = {}, 0, []
    span_by_path = {tuple(s["path"]): s for s in spans}
    fingerprints = {}
    def fingerprint(s):
        path = tuple(s["path"])
        if path not in fingerprints:
            fingerprints[path] = hashlib.sha256(canonical_json({"path": s["path"], "clip": _strip_derived(s["clip"]), "source": s["source"]}).encode()).hexdigest()
        return fingerprints[path]
    for frame, owners in sorted(candidates.items()):
        lo, hi = bisect.bisect_left(frames, frame - 2), bisect.bisect_right(frames, frame + 2)
        nearby = cues[lo:hi]
        while cursor < len(opaque) and opaque[cursor]["startFrame"] <= frame:
            s = opaque[cursor]
            live_opaque[tuple(s["path"])] = s
            cursor += 1
        live_opaque = {p: s for p, s in live_opaque.items() if s["endFrame"] > frame}
        # Bind only participants and their relevant timing/source metadata.
        # Intent/report bytes and unrelated edits never affect this context.
        relevant = {tuple(s["path"]): s for s in owners}
        relevant.update({tuple(c["path"]): span_by_path[tuple(c["path"])] for c in nearby})
        # A cue-free cut cannot acknowledge additional cues. Defer content
        # fingerprinting until there is known behavior to acknowledge.
        context = "sha256:" + hashlib.sha256((DISCLOSURE_VERSION + "|" + str(fps) + "|" + str(frame) + "|"
                  + "|".join(fingerprint(s) for _, s in sorted(relevant.items()))).encode()).hexdigest() if nearby else None
        intent = (policy.get("intents") or {}).get(str(frame))
        valid = isinstance(intent, dict) and intent.get("frame") == frame and intent.get("context") == context and intent.get("kind") in ("hard-cut", "transition", "synchronized")
        acknowledged = set(intent.get("participants", [])) if valid and intent["kind"] == "synchronized" else set()
        risky = [c for c in nearby if c["kind"] in ("activation", "motion-start", "phase-change", "source-reset", "source-change", "rate-change")]
        uncovered = [c for c in risky if cue_identity(c) not in acknowledged]
        boundaries.append({"frame": frame, "context": context, "ownerPaths": [list(p) for p in sorted({tuple(s["path"]) for s in owners})],
                           "cues": nearby, "opaquePaths": [list(p) for p in sorted(live_opaque)], "requiresIntent": bool(uncovered),
                           "unacknowledgedCues": [cue_identity(c) for c in uncovered]})
    return {"version": VERSION, "disclosureVersion": DISCLOSURE_VERSION, "fps": fps, "guardFrames": 2,
            "spans": [{k: v for k, v in s.items() if k not in ("clip", "disclosure")} for s in spans], "cues": cues,
            "boundaries": boundaries, "opaqueElements": [s["disclosure"] for s in opaque], "structuralIssues": issues,
            "warningCount": sum(bool(b["requiresIntent"] or b["opaquePaths"]) for b in boundaries),
            "blocked": bool(issues or any(b["requiresIntent"] for b in boundaries))}


def evaluate_closure(parent, shots, internal, *, timeline_id, materialize=False):
    metadata = normalize_closure(parent, shots, internal, timeline_id=timeline_id, materialize=materialize)
    return analyze_normalized(metadata), metadata


def admit_closure(parent, shots, internal, *, timeline_id, materialize=False):
    report, metadata = evaluate_closure(parent, shots, internal, timeline_id=timeline_id, materialize=materialize)
    if report["blocked"]:
        raise ValidationError("visual seam admission blocked", details={"code": "visual_seam_admission_blocked", "report": report})
    return report, metadata
