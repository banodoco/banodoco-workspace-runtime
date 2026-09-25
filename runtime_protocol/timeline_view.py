"""Small declared-input Markdown view; no media reads or render admission."""

from __future__ import annotations

from html import escape
import struct
import zlib


def _cell(value):
    return escape(str(value), quote=True).replace("|", "&#124;").replace("\n", " ").replace("\r", " ")[:2000]


def _seconds(value):
    return f"{value[0]}/{value[1]} s"


def markdown(inspection):
    lines = [
        "# Declared timeline inputs",
        "",
        f"Project: {_cell(inspection['project_id'])}  ",
        f"Timeline: {_cell(inspection['timeline_id'])}  ",
        f"Parent revision: {_cell(inspection['revision_id'])}  ",
        f"Snapshot: {_cell(inspection['snapshot_digest'])}",
        "",
        "This view records declared arrangement only. Source pixels, waveforms, and rendered output were not inspected.",
        "",
    ]
    if inspection["selection_status"] == "selector_miss":
        lines += ["No occurrence or clip matched the selectors.", ""]
    for row in inspection["selected"]:
        occurrence = row["occurrence"]
        lines += [
            f"## {_cell(row['role'].title())}: {_cell(occurrence['occurrence_id'])}",
            "",
            f"Order {occurrence['ordinal']}; shot {_cell(occurrence['shot_id'])} at {_seconds(occurrence['start'])} for {_seconds(occurrence['duration'])}.  ",
            f"Shot revision {_cell(occurrence['shot_revision_id'])}; internal timeline revision {_cell(occurrence['internal_timeline_revision_id'])}.  ",
            f"Placement speed {_cell(occurrence['speed'])}, source offset {_cell(occurrence['source_offset'])}, gain {_cell(occurrence['gain'])}, mute {_cell(occurrence['mute'])}.",
            "",
            "| Clip | Track | Type | Start | Duration | Source | Trim | Speed | Text |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for clip in row["clips"]:
            source = clip["source_object_id"] or clip["content_digest"] or clip["asset_id"] or "unresolved"
            trim = f"{clip['source_from']}..{clip['source_to']}"
            lines.append("| " + " | ".join(_cell(value) for value in (
                clip["clip_id"], clip["track_id"], clip["clip_type"], _seconds(clip["start"]),
                _seconds(clip["duration"]), source, trim, _seconds(clip["speed"]), clip["text"],
            )) + " |")
        if not row["clips"]:
            lines.append("| (no declared clips) | | | | | | | | |")
        lines.append("")
        for kind in ("text_bindings", "audio_bindings"):
            values = occurrence.get(kind)
            if isinstance(values, list) and values:
                lines += [f"{kind.replace('_', ' ').title()}: {_cell(values[:20])}", ""]
    return ("\n".join(lines) + "\n").encode("utf-8")


def png(inspection):
    """Return a tiny deterministic metadata-only lane diagram.

    This deliberately uses only the standard library: it draws the declared
    occurrence lanes and clip spans, never opens a source file, decodes media,
    or depends on Astrid/Pillow. Textual identities remain authoritative in
    the paired Markdown artifact.
    """
    width, height = 1200, 360
    pixels = bytearray([16, 22, 29] * (width * height))

    def fill(x0, y0, x1, y1, color):
        x0, y0 = max(0, int(x0)), max(0, int(y0))
        x1, y1 = min(width, int(x1)), min(height, int(y1))
        if x1 <= x0 or y1 <= y0:
            return
        red, green, blue = color
        for y in range(y0, y1):
            row = y * width * 3
            for x in range(x0, x1):
                offset = row + x * 3
                pixels[offset:offset + 3] = bytes((red, green, blue))

    selected = inspection.get("selected") or []
    occurrences = [row for row in selected if isinstance(row, dict)]
    max_end = 1.0
    for row in occurrences:
        raw = row.get("occurrence", {}).get("start", [0, 1])
        duration = row.get("occurrence", {}).get("duration", [0, 1])
        try:
            max_end = max(max_end, (float(raw[0]) / raw[1]) + (float(duration[0]) / duration[1]))
        except (TypeError, ValueError, ZeroDivisionError, IndexError):
            pass
    lane_height = max(1, (height - 40) // max(1, len(occurrences)))
    for index, row in enumerate(occurrences):
        y0 = 20 + index * lane_height
        y1 = min(height - 10, y0 + lane_height - 8)
        fill(20, y0, width - 20, y1, (38, 52, 63))
        clips = row.get("clips") or []
        for clip in clips:
            try:
                start = float(clip.get("start", [0, 1])[0]) / clip.get("start", [0, 1])[1]
                duration = float(clip.get("duration", [0, 1])[0]) / clip.get("duration", [0, 1])[1]
            except (TypeError, ValueError, ZeroDivisionError, IndexError):
                continue
            x0 = 24 + max(0.0, min(1.0, start / max_end)) * (width - 48)
            x1 = 24 + max(0.0, min(1.0, (start + duration) / max_end)) * (width - 48)
            fill(x0, y0 + 8, max(x0 + 5, x1), y1 - 4, (48, 120, 145) if row.get("role") == "target" else (85, 82, 111))

    raw = bytearray(b"\x89PNG\r\n\x1a\n")
    def chunk(kind, data):
        raw.extend(struct.pack(">I", len(data)))
        raw.extend(kind)
        raw.extend(data)
        raw.extend(struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff))
    chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    scanlines = bytearray()
    for y in range(height):
        scanlines.append(0)
        scanlines.extend(pixels[y * width * 3:(y + 1) * width * 3])
    chunk(b"IDAT", zlib.compress(bytes(scanlines), 6))
    chunk(b"IEND", b"")
    return bytes(raw)
