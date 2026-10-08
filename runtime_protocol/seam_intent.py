"""Native mirror of Astrid seam-intent.ts. Context is compared as JSON data,
avoiding Python/JS number serialization differences and self-referential hashes.
"""
import json

from .visual_boundary import DISCLOSURE_VERSION

FIELDS = ("params", "keyframes", "entrance", "exit", "continuous", "transition", "effects", "elementRef",
          "x", "y", "width", "height", "opacity", "scale", "rotation", "translateX", "translateY",
          "cropTop", "cropBottom", "cropLeft", "cropRight")


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
        metadata.update({k: clean(clip[k]) for k in FIELDS if k in clip})
        key = json.dumps(path, ensure_ascii=False, separators=(",", ":"))
        by_path[key] = {"path": path, "span": [owner["startFrame"], owner["endFrame"], owner["rawStartFrame"]],
                        "source": owner["source"], "clip": metadata}
    return {"version": DISCLOSURE_VERSION, "fps": fps, "frame": frame,
            "owners": [by_path[key] for key in sorted(by_path)]}
