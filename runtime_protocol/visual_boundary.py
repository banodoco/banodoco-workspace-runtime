"""Trusted visual-seam/v1 disclosure. Conforms to Astrid's pure boundary.ts.

This closed implementation never evaluates submitted effect/component code.
All times are renderer-local; spans are effective, half-open visible frames.
"""
from __future__ import annotations

import math

VERSION = 1
DISCLOSURE_VERSION = "visual-seam/v1"


def finite(value, fallback=0):
    if type(value) is int:
        return value
    return value if type(value) is float and math.isfinite(value) else fallback


def js_round(value):
    return math.floor(value + 0.5)


def positive(value):
    value = finite(value, None)
    return value if value is not None and value > 0 else None


def nonnegative(value):
    value = finite(value, None)
    return value if value is not None and value >= 0 else None


DEFAULT_SEGMENTS = [
    {"id": "astrid", "start": 0, "end": 5, "label": "00", "title": "ASTRID — through the glasses"},
    {"id": "choice", "start": 5, "end": 8, "sourceStart": 74.9347, "sourceEnd": 76.4, "speed": 0.4884, "label": "01", "title": "Two options"},
    {"id": "blue", "start": 8, "end": 19, "sourceStart": 79.12, "sourceEnd": 80.87, "label": "02", "title": "Blue pill — manual tools"},
    {"id": "red", "start": 19, "end": 22, "label": "03", "title": "Red pill"},
    {"id": "creature", "start": 22, "end": 26.9167, "label": "04", "title": "Creature reveal — glasses edit"},
    {"id": "reflection", "start": 26.9167, "end": 43.4927, "label": "05", "title": "Into the minkhole — reflection close-up"},
]


def end_spanning_timing(clip, params, fps):
    seconds = positive(clip.get("hold")) or positive(finite(clip.get("to")) - finite(clip.get("at"))) or 30
    configured = params.get("phaseDurations") or {}
    values = [positive(params.get(k + "Seconds")) or positive(configured.get(k)) for k in ("prep", "iteration", "anchors", "workflow")]
    if not all(v is not None for v in values):
        values = [seconds * w for w in (0.24, 0.22, 0.2, 0.34)]
    total = 0
    frames = []
    for value in values:
        total += value
        frames.append(js_round(total * fps))
    return values, frames, max(frames[-1], js_round(seconds * fps))


def _segments(params):
    raw = params.get("timelineSegments")
    if not isinstance(raw, list):
        return DEFAULT_SEGMENTS
    result = [s for s in raw if isinstance(s, dict) and finite(s.get("start"), None) is not None
              and finite(s.get("end"), None) is not None and s["end"] > s["start"]
              and isinstance(s.get("label"), str) and s["label"] and isinstance(s.get("title"), str) and s["title"]]
    return result or DEFAULT_SEGMENTS


def _rect_at(keys, seconds):
    right = next((i for i, k in enumerate(keys) if k["at"] > seconds), -1)
    fields = ("x", "y", "width", "height", "opacity")
    if right == 0:
        return [keys[0][k] for k in fields]
    if right < 0:
        return [keys[-1][k] for k in fields]
    a, b = keys[right - 1], keys[right]
    p = (seconds - a["at"]) / (b["at"] - a["at"])
    return [a[k] + (b[k] - a[k]) * p for k in fields]


def boundary_report(context):
    clip = context["clip"]
    params = context.get("params", clip.get("params", {}))
    fps, start, end, path = (context[k] for k in ("fps", "startFrame", "endFrame", "path"))
    origin = context.get("originFrame", start)
    report = {"version": VERSION, "disclosureVersion": DISCLOSURE_VERSION, "effectVersion": 1,
              "span": {"startFrame": start, "endFrame": end, "path": list(path)}, "cues": [], "source": None, "opaque": []}

    def cue(local, kind, identity):
        frame = origin + local
        if start <= frame < end:
            report["cues"].append({"frame": frame, "kind": kind, "id": identity, "path": list(path)})

    kind = clip.get("clipType", (clip.get("elementRef") or {}).get("id"))
    try:
        if finite(fps, None) is None or fps <= 0 or not isinstance(start, int) or not isinstance(end, int) or end <= start:
            raise ValueError("invalid visible span")
        if "disclosureVersion" in params and params["disclosureVersion"] != DISCLOSURE_VERSION:
            report["opaque"].append("unsupported disclosure version")
        if kind == "end-spanning-layer":
            _, frames, _ = end_spanning_timing(clip, params, fps)
            prep, iteration, anchors = frames[:3]
            delay = max(0, finite(params.get("revealDelaySeconds")))
            fade = max(0, finite(params.get("revealDurationSeconds")))
            reveal = math.floor(delay * fps) + 1 if fade > 0 else math.ceil(delay * fps)
            cue(reveal, "activation", "reveal")
            if fade > 0:
                cue(reveal, "motion-start", "reveal-opacity")
            for i, frame in enumerate((prep, iteration, anchors)):
                if frame >= reveal:
                    cue(frame, "phase-change", ("iteration", "anchors", "workflow")[i])
                if frame + 1 >= reveal:
                    cue(max(frame + 1, reveal), "motion-start", ("move-up", "move-down", "workflow-move")[i])
            segments = _segments(params)
            if isinstance(params.get("selectedSegmentId"), str):
                index = next((i for i, s in enumerate(segments) if s.get("id") == params["selectedSegmentId"]), 0)
            else:
                requested = nonnegative(params.get("selectedSegmentIndex"))
                index = min(len(segments) - 1, 2 if requested is None else math.floor(requested))
            selected = segments[index]
            report["source"] = {"binding": context.get("source"), "selectedSegmentId": selected.get("id"), "selectedSegmentIndex": index,
                                "sourceStart": nonnegative(selected.get("sourceStart")) if nonnegative(selected.get("sourceStart")) is not None else selected["start"],
                                "sourceEnd": positive(selected.get("sourceEnd")) or selected["end"], "speed": positive(selected.get("speed")) or 1,
                                "prepSourceStart": positive(params.get("prepSourceStart")) or 74.08,
                                "prepSourceEnd": positive(params.get("prepSourceEnd")) or 84.3, "prepSourceSpeed": positive(params.get("prepSourceSpeed")) or 1}
            if context.get("source"):
                if reveal < prep:
                    cue(reveal, "source-reset", "prep-source")
                cue(max(anchors + 1, reveal), "source-reset", "workflow-source")
        elif kind == "animated-media-transform":
            keys = params.get("keyframes")
            if not isinstance(keys, list) or not keys:
                raise ValueError("animated-media-transform needs keyframes")
            previous = -1
            for k in keys:
                if (not isinstance(k, dict) or any(finite(k.get(f), None) is None for f in ("at", "x", "y", "width", "height", "opacity"))
                        or k["at"] < 0 or k["at"] <= previous or k["width"] <= 0 or k["height"] <= 0 or not 0 <= k["opacity"] <= 1):
                    raise ValueError("Transform keyframes must be finite, ordered, positive-size rectangles with opacity 0–1")
                previous = k["at"]
            moving = [any(a[k] != b[k] for k in ("x", "y", "width", "height", "opacity")) for a, b in zip(keys, keys[1:])]
            for i, moves in enumerate(moving):
                if not moves:
                    continue
                sample = math.floor(keys[i]["at"] * fps) + 1
                if _rect_at(keys, (sample - 1) / fps) != _rect_at(keys, sample / fps):
                    if i == 0 or not moving[i - 1]:
                        cue(sample, "motion-start", f"key-{i}")
                    if i > 0:
                        cue(math.ceil(keys[i]["at"] * fps), "phase-change", f"key-{i}")
            duration = max(1, js_round(finite(clip.get("hold"), 1) * fps))
            raw = params.get("sourceSegments", [{"at": 0, "sourceStart": finite(clip.get("from")), "speed": finite(clip.get("speed"), 1)}])
            segments = []
            if not str(context.get("sourceType", "")).startswith("image"):
                if not isinstance(raw, list) or not raw:
                    raise ValueError("Invalid source playback timing")
                previous = -1
                for s in raw:
                    if not isinstance(s, dict) or any(nonnegative(s.get(k)) is None for k in ("at", "sourceStart")) or positive(s.get("speed")) is None:
                        raise ValueError("Invalid source playback segment")
                    frame = js_round(s["at"] * fps)
                    if frame <= previous or frame >= duration:
                        raise ValueError("Source segment boundaries must occupy distinct increasing frames")
                    previous = frame
                    segments.append({**s, "fromFrame": frame})
                if segments[0]["fromFrame"] != 0:
                    raise ValueError("Source playback must start at clip frame zero")
            normalized = [{"fromFrame": s["fromFrame"], "durationInFrames": (segments[i + 1]["fromFrame"] if i + 1 < len(segments) else duration) - s["fromFrame"],
                           "sourceStartFrame": js_round(s["sourceStart"] * fps), "speed": s["speed"]} for i, s in enumerate(segments)]
            report["source"] = {"binding": context.get("source"), "segments": normalized}
            for i in range(1, len(normalized)):
                a, b = normalized[i - 1], normalized[i]
                continued = a["sourceStartFrame"] + (b["fromFrame"] - a["fromFrame"]) * a["speed"]
                if abs(b["sourceStartFrame"] - continued) > 1e-9:
                    cue(b["fromFrame"], "source-reset", f"source-{i}")
                if a["speed"] != b["speed"]:
                    cue(b["fromFrame"], "rate-change", f"source-{i}")
        elif kind in ("media", "hold", "video", "image"):
            for prop, rows in (clip.get("keyframes") or {}).items():
                if (prop not in ("x", "y", "width", "height", "scale", "rotation", "opacity", "translateX", "translateY") or not isinstance(rows, list)
                        or any(not isinstance(k, dict) or nonnegative(k.get("time")) is None or finite(k.get("value"), None) is None
                               or (i > 0 and k["time"] <= rows[i - 1]["time"]) or k.get("interpolation", "linear") not in ("linear", "step", "hold") for i, k in enumerate(rows))):
                    report["opaque"].append(f"unsupported keyframes: {prop}")
                    continue
                for i in range(1, len(rows)):
                    a, b = rows[i - 1], rows[i]
                    if a["value"] != b["value"]:
                        frame = math.ceil(b["time"] * fps) if a.get("interpolation") in ("step", "hold") else math.floor(a["time"] * fps) + 1
                        cue(frame, "motion-start", f"{prop}-{i}")
            report["source"] = {"binding": context.get("source")}
        else:
            report["opaque"].append("unknown effect timing")
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError) as error:
        report["cues"] = []
        report["opaque"].append(f"failed disclosure: {error}")
    report["cues"].sort(key=lambda c: (c["frame"], c["kind"], c["id"]))
    return report
