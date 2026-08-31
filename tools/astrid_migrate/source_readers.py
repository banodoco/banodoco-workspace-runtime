"""Pure readers and mappings for frozen legacy Astrid source snapshots.

This module is deliberately standalone.  It is the only place where the
small amount of Stage1 legacy-layout knowledge needed by the migrator lives;
it never imports the Astrid product, a Reigh package, or the runtime.  The
write side receives its rows through the generated-client-shaped surface in
``migrator``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


class SourceReadError(ValueError):
    """A frozen source document does not satisfy its admitted contract."""


PROMPT_TEMPLATE = (
    "{colour_name} neon piano chord, hard cut, 48fps, "
    "complementary colour {next_colour}, {timing_mode}, {segment_id}"
)
DEFAULT_FRAME_COUNT = 8085
DEFAULT_FPS = 48


def read_json_object(path: Path, *, label: str = "source document") -> dict[str, Any]:
    """Read one immutable JSON object without importing product code."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceReadError(f"{label} is unreadable: {path}") from exc
    if not isinstance(value, dict):
        raise SourceReadError(f"{label} must be a JSON object")
    return value


def build_prompt(
    *, colour_name: str, timing_mode: str, segment_id: str, next_colour_name: str
) -> str:
    """Build the deterministic prompt used by the admitted timing mapping."""

    return PROMPT_TEMPLATE.format(
        colour_name=colour_name,
        next_colour=next_colour_name,
        timing_mode=timing_mode,
        segment_id=segment_id,
    )


def load_manifest(path: Path) -> dict[str, Any]:
    return read_json_object(path, label="timing manifest")


def load_audio_reactive(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return read_json_object(path, label="audio-reactive input")


def validate_manifest_contract(
    manifest: Mapping[str, Any], audio_reactive: Mapping[str, Any] | None = None
) -> tuple[int, int]:
    """Validate timing facts before any destination/client operation."""

    transitions = manifest.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        raise SourceReadError("manifest transitions must be a non-empty array")
    declared_count = manifest.get("transition_count")
    if declared_count != len(transitions):
        raise SourceReadError(
            f"manifest transition_count {declared_count!r} does not match {len(transitions)} rows"
        )
    clock = manifest.get("clock")
    if not isinstance(clock, Mapping):
        raise SourceReadError("manifest clock must be an object")
    fps = clock.get("fps", DEFAULT_FPS)
    if isinstance(fps, bool) or not isinstance(fps, int) or not 1 <= fps <= 240:
        raise SourceReadError("manifest clock.fps must be an integer between 1 and 240")
    frames: list[int] = []
    for index, transition in enumerate(transitions):
        if not isinstance(transition, Mapping):
            raise SourceReadError(f"manifest transitions[{index}] must be an object")
        frame = transition.get("frame")
        if isinstance(frame, bool) or not isinstance(frame, int) or frame < 0:
            raise SourceReadError(
                f"manifest transitions[{index}].frame must be a non-negative integer"
            )
        frames.append(frame)
    if frames != sorted(set(frames)):
        raise SourceReadError("manifest transition frames must be unique and strictly increasing")

    frame_count = DEFAULT_FRAME_COUNT
    if audio_reactive is not None:
        try:
            timebase = audio_reactive["timebase"]
            raw_audio_fps = timebase["fps"]
            raw_frame_count = timebase["range_end_frame"]
        except (KeyError, TypeError) as exc:
            raise SourceReadError("audio-reactive timebase is malformed") from exc
        if (
            isinstance(raw_audio_fps, bool)
            or not isinstance(raw_audio_fps, int)
            or isinstance(raw_frame_count, bool)
            or not isinstance(raw_frame_count, int)
        ):
            raise SourceReadError("audio-reactive timebase values must be integers")
        if raw_audio_fps != fps:
            raise SourceReadError(
                f"audio-reactive fps {raw_audio_fps} does not match manifest fps {fps}"
            )
        frame_count = raw_frame_count
    if frame_count <= frames[-1]:
        raise SourceReadError("range_end_frame must be after the final transition")

    segments = manifest.get("segments")
    if not isinstance(segments, list) or not segments:
        raise SourceReadError("manifest segments must be a non-empty array")
    segment_ids = [s.get("id") for s in segments if isinstance(s, Mapping)]
    counts = [s.get("transition_count") for s in segments if isinstance(s, Mapping)]
    if (
        len(segment_ids) != len(segments)
        or len(counts) != len(segments)
        or any(not isinstance(item, str) or not item.strip() for item in segment_ids)
        or len(set(segment_ids)) != len(segment_ids)
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in counts)
    ):
        raise SourceReadError("manifest segments must have unique ids and non-negative counts")
    if sum(counts) != len(transitions):
        raise SourceReadError("segment transition counts do not sum to transition_count")
    return fps, frame_count


def manifest_to_transitions(
    manifest: Mapping[str, Any], audio_reactive: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Map the admitted timing manifest to generic transition rows."""

    fps, range_end = validate_manifest_contract(manifest, audio_reactive)
    raw_transitions = list(manifest.get("transitions") or [])
    prompts: list[str] = []
    for index, transition in enumerate(raw_transitions):
        colour = str(transition.get("colour_name") or transition.get("colour") or "rose")
        timing_mode = str(transition.get("timing_mode") or "literal_main_note")
        segment_id = str(transition.get("segment_id") or "S01")
        if index + 1 < len(raw_transitions):
            following = raw_transitions[index + 1]
            next_colour = str(following.get("colour_name") or following.get("colour") or "hold")
        else:
            next_colour = "hold"
        prompts.append(
            build_prompt(
                colour_name=colour,
                timing_mode=timing_mode,
                segment_id=segment_id,
                next_colour_name=next_colour,
            )
        )

    rows: list[dict[str, Any]] = []
    for index, transition in enumerate(raw_transitions):
        frame = int(transition["frame"])
        next_frame = int(raw_transitions[index + 1]["frame"]) if index + 1 < len(raw_transitions) else range_end
        duration_ms = int(round((next_frame - frame) * 1000 / fps))
        if duration_ms <= 0:
            duration_ms = int(round(1000 / fps)) or 1
        metadata = {
            "segment_id": transition.get("segment_id"),
            "segment_label": transition.get("segment_label"),
            "timing_mode": transition.get("timing_mode"),
            "colour_name": transition.get("colour_name"),
            "colour_hex": transition.get("colour_hex"),
            "colour_index": transition.get("colour_index"),
            "source_time_seconds": transition.get("source_time_seconds"),
            "grid_index": transition.get("grid_index"),
            "grid_time_seconds": transition.get("grid_time_seconds"),
            "frame": frame,
            "frame_time_seconds": transition.get("frame_time_seconds"),
            "frame_error_ms": transition.get("frame_error_ms"),
            "manifest_id": transition.get("id"),
            "command_time_seconds": transition.get("command_time_seconds"),
            "fps": fps,
            "range_end_frame": range_end,
        }
        rows.append(
            {
                "ordinal": index,
                "start_ms": int(round(frame * 1000 / fps)),
                "duration_ms": duration_ms,
                "prompt": prompts[index],
                "metadata": {key: value for key, value in metadata.items() if value is not None},
            }
        )
    return rows


__all__ = [
    "SourceReadError",
    "build_prompt",
    "load_manifest",
    "load_audio_reactive",
    "manifest_to_transitions",
    "read_json_object",
    "validate_manifest_contract",
]
