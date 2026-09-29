"""Declared-input Markdown and labelled PNG views; no media reads or rendering."""

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


# Compact 5x7 glyphs keep runtime visualization dependency-free. Unknown characters
# are shown as '?' (the paired Markdown retains exact Unicode identifiers).
_FONT_ROWS = {
    "A":"0E11111F111111", "B":"1E11111E11111E", "C":"0E11101010110E",
    "D":"1E11111111111E", "E":"1F10101E10101F", "F":"1F10101E101010",
    "G":"0E11101711110F", "H":"1111111F111111", "I":"0E04040404040E",
    "J":"0702020212120C", "K":"11121418141211", "L":"1010101010101F",
    "M":"111B1515111111", "N":"11191513111111", "O":"0E11111111110E",
    "P":"1E11111E101010", "Q":"0E11111115120D", "R":"1E11111E141211",
    "S":"0F10100E01011E", "T":"1F040404040404", "U":"1111111111110E",
    "V":"11111111110A04", "W":"11111115151B11", "X":"11110A040A1111",
    "Y":"11110A04040404", "Z":"1F01020408101F",
    "0":"0E11131519110E", "1":"040C040404040E", "2":"0E11010204081F",
    "3":"1E01010601011E", "4":"02060A121F0202", "5":"1F10101E01011E",
    "6":"0E10101E11110E", "7":"1F010204080808", "8":"0E11110E11110E",
    "9":"0E11110F01010E", "-":"0000001F000000", "_":"0000000000001F",
    ".":"00000000000C0C", ":":"000C0C000C0C00", "/":"01010204081010",
    "[":"0E08080808080E", "]":"0E02020202020E", "?":"0E110102040004",
    "(":"02040808080402", ")":"08040202020408", " ":"00000000000000",
}


def png(inspection):
    """Draw bounded, labelled declared clip spans, without opening any media.

    Adjacent clips get distinct colors and explicit borders. Numbered legend
    rows retain readable identifiers even for spans narrower than a text label.
    Overlapping clips occupy separate sublanes rather than hiding each other.
    """
    palette = [(48, 120, 145), (111, 87, 160), (47, 131, 100), (170, 105, 48)]
    foreground = (234, 241, 248)
    background = (16, 22, 29)
    def seconds(value):
        return float(value[0]) / value[1]
    def time(value):
        return f"{value:.3f}".rstrip("0").rstrip(".") + "s"

    all_clips = [(row, clip) for row in inspection.get("selected", []) for clip in row.get("clips", [])]
    # Keep images bounded even when a large closure is selected. Markdown and
    # the inspection JSON retain all selected rows.
    displayed = all_clips[:40]
    lanes = []
    entries = []
    for number, (row, clip) in enumerate(displayed, 1):
        start = seconds(clip["start"])
        end = start + seconds(clip["duration"])
        occurrence = str(row["occurrence"]["occurrence_id"])
        track = str(clip.get("track_id") or "unassigned")
        group = (occurrence, track)
        lane = next((i for i, value in enumerate(lanes)
                     if value["group"] == group and all(end <= a or start >= b for a, b in value["intervals"])), None)
        if lane is None:
            lane = len(lanes)
            lanes.append({"group": group, "intervals": []})
        lanes[lane]["intervals"].append((start, end))
        entries.append((number, clip, start, end, lane))
    origin = min((e[2] for e in entries), default=0)
    end_time = max((e[3] for e in entries), default=origin + 1)
    span = max(end_time - origin, .001)
    width = 1200
    legend_y = 130 + len(lanes) * 78
    height = max(260, legend_y + len(entries) * 28 + 52)
    pixels = bytearray(bytes(background) * (width * height))

    def fill(x0, y0, x1, y1, color):
        x0, y0 = max(0, int(x0)), max(0, int(y0))
        x1, y1 = min(width, int(x1)), min(height, int(y1))
        if x1 <= x0 or y1 <= y0:
            return
        segment = bytes(color) * (x1 - x0)
        for y in range(y0, y1):
            offset = (y * width + x0) * 3
            pixels[offset:offset + len(segment)] = segment

    def text(x, y, value, color=foreground, scale=2, max_chars=96):
        value = str(value).upper()
        if len(value) > max_chars:
            value = value[:max_chars - 3] + "..."
        for index, char in enumerate(value):
            glyph = bytes.fromhex(_FONT_ROWS.get(char, _FONT_ROWS["?"]))
            for gy, bits in enumerate(glyph):
                for gx in range(5):
                    if bits & (1 << (4 - gx)):
                        px = x + (index * 6 + gx) * scale
                        fill(px, y + gy * scale, px + scale, y + (gy + 1) * scale, color)

    text(24, 18, "Declared timeline inputs")
    text(24, 44, "METADATA ONLY - NO SOURCE THUMBNAILS OR RENDERED PIXELS", scale=1)
    text(24, 64, "Timeline: " + str(inspection.get("timeline_id", "")), scale=1, max_chars=180)
    text(24, 80, "Revision: " + str(inspection.get("revision_id", "")), scale=1, max_chars=180)
    left, right = 24, width - 24
    def xpos(value):
        return round(left + (value - origin) / span * (right - left))
    for i in range(5):
        moment = origin + span * i / 4
        x = xpos(moment)
        fill(x, 114, x + 1, legend_y - 12, (52, 66, 80))
        label = time(moment)
        text(min(x, width - 24 - len(label) * 6), 100, label, scale=1)
    for i, lane in enumerate(lanes):
        y = 126 + i * 78
        occurrence, track = lane["group"]
        text(left, y, f"Occurrence: {occurrence} / Track: {track}", scale=1, max_chars=185)
    for number, clip, start, end, lane in entries:
        y = 146 + lane * 78
        x0, x1 = xpos(start), xpos(end)
        color = palette[(number - 1) % len(palette)]
        fill(x0, y, max(x0 + 3, x1), y + 36, foreground)
        fill(x0 + 2, y + 2, max(x0 + 3, x1 - 2), y + 34, color)
        if x1 - x0 >= 28:
            text(x0 + 8, y + 10, str(number), scale=2)
        ly = legend_y + (number - 1) * 28
        fill(24, ly, 48, ly + 18, color)
        text(56, ly + 2, f"{number}. {time(start)} - {time(end)}  {clip['clip_id']}", max_chars=92)
    if not entries:
        text(24, 150, "No declared clips matched the selection.")
    if len(all_clips) > len(entries):
        text(24, height - 28, f"Showing {len(entries)} of {len(all_clips)} clips. Narrow selectors or read paired Markdown.", scale=1)
    else:
        text(24, height - 28, "Absolute timeline times. Full identities and source references are in paired Markdown / JSON.", scale=1)

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
