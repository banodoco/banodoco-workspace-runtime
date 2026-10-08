"""Native mirror of Astrid seam-intent.ts. Context is compared as JSON data,
avoiding Python/JS number serialization differences and self-referential hashes.
"""
import json

from .visual_boundary import DISCLOSURE_VERSION

FIELDS = ("params", "keyframes", "entrance", "exit", "continuous", "transition", "effects", "elementRef",
          "x", "y", "width", "height", "opacity", "scale", "rotation", "translateX", "translateY",
          "cropTop", "cropBottom", "cropLeft", "cropRight")


def pause_covers(gaps, track, start, end):
    """A portable pause grants precisely one track/frame interval."""
    return end > start and isinstance(gaps, list) and any(
        isinstance(p, dict) and p.get("kind") == "pause" and p.get("track") == track
        and type(p.get("startFrame")) is int and type(p.get("endFrame")) is int
        and p["startFrame"] == start and p["endFrame"] == end for p in gaps)


def relevant_intent_owners(owners, boundary_owners, cues):
    paths = {tuple(o["path"]) for o in boundary_owners} | {tuple(c["path"]) for c in cues}
    return [o for o in owners if tuple(o["path"]) in paths]


def boundary_intent_owners(owners, frame):
    """Select adjacent/furthest picture owners for one seam frame.

    This mirrors Astrid's portable boundary-owner rule. An owner on another
    lane participates only when that lane has its own cut at this frame; a
    spanning owner is not pulled in merely because it overlaps the guard
    window around an occurrence seam.
    """
    groups = {}
    for owner in owners:
        if not owner["primary"]:
            continue
        groups.setdefault(str(owner["track"]), []).append(owner)
    selected = []
    for rows in groups.values():
        rows.sort(key=lambda owner: (owner["startFrame"], owner["endFrame"]))
        furthest = None
        for row in rows:
            if furthest is not None and row["startFrame"] == frame:
                selected.extend((furthest, row))
            if furthest is None or row["endFrame"] > furthest["endFrame"]:
                furthest = row
    return selected


def opaque_activation_cues(owners, frames):
    return [{"frame": o["startFrame"], "kind": "activation", "id": "owner-activation", "path": o["path"]}
            for o in owners if not o["primary"] and o["disclosure"]["opaque"]
            and any(o["startFrame"] + delta in frames for delta in (-2, -1, 0, 1, 2))]


def intent_path(path):
    return path[2:] if path[0] in ("parent", "track") else list(path)


def cue_identity(cue):
    return json.dumps([intent_path(cue["path"]), cue["kind"], cue["id"], cue["frame"]], ensure_ascii=False, separators=(",", ":"))


def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items() if k not in ("report", "intents", "visualSeamIntents", "visual_seam_report")}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


def intent_context(fps, frame, owners):
    by_path = {}
    for owner in owners:
        clip = owner["clip"]
        path = intent_path(owner["path"])
        metadata = {"clipType": clip.get("clipType", clip.get("clip_type", "media")), "track": clip.get("track", "video"),
                    "from": clip.get("from", 0), "speed": clip.get("speed", 1)}
        # Match the shared optional-effect contract; retain every real effect
        # and preserve other empty fields whose unsupported timing is opaque.
        metadata.update({k: clean(clip[k]) for k in FIELDS if k in clip
                         and not (k == "effects" and isinstance(clip[k], (list, dict)) and not clip[k])})
        key = json.dumps(path, ensure_ascii=False, separators=(",", ":"))
        by_path[key] = {"path": path, "span": [owner["startFrame"], owner["endFrame"], owner["rawStartFrame"]],
                        "source": owner["source"], "clip": metadata}
    return {"version": DISCLOSURE_VERSION, "fps": fps, "frame": frame,
            "owners": [by_path[key] for key in sorted(by_path)]}
