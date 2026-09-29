"""Pixel regression checks for metadata diagrams, without image dependencies."""
import copy
import struct
import zlib
from runtime_protocol.timeline_view import png


def _inspection(count=4):
    return {"timeline_id": "main", "revision_id": "head-1", "selected": [{
        "occurrence": {"occurrence_id": "opening"},
        "clips": [{"clip_id": f"image-{4-i}", "track_id": "picture",
                   "start": [i*5, 4], "duration": [5, 4]} for i in range(count)]}]}


def _decode(content):
    width, height = struct.unpack(">II", content[16:24])
    compressed = bytearray()
    offset = 8
    while offset < len(content):
        size = struct.unpack(">I", content[offset:offset+4])[0]
        if content[offset+4:offset+8] == b"IDAT":
            compressed.extend(content[offset+8:offset+8+size])
        offset += 12+size
    raw = zlib.decompress(compressed)
    stride = width*3+1
    assert all(raw[y*stride] == 0 for y in range(height))
    def pixel(x,y):
        start = y*stride+1+x*3
        return tuple(raw[start:start+3])
    return width,height,pixel


def test_adjacent_clips_remain_distinct_and_identified():
    original = _inspection()
    width,height,pixel = _decode(png(original))
    assert len({pixel(x,174) for x in (100,400,700,1000)}) == 4
    for boundary in (312,600,888):
        assert pixel(boundary,174) == (234,241,248)
    assert any(pixel(x,y) == (234,241,248) for x in range(32,42) for y in range(156,170))
    changed = copy.deepcopy(original)
    changed['selected'][0]['clips'][0]['clip_id'] = 'other-4'
    _,_,other = _decode(png(changed))
    # Identity must actually appear in the legend pixels, not only in JSON.
    assert any(pixel(x,y) != other(x,y) for x in range(235,450) for y in range(210,224))
    assert all(pixel(x,y) == other(x,y) for x in range(width) for y in range(238,height))


def test_focused_interval_has_absolute_time_labels():
    original = _inspection()
    _,_,before = _decode(png(original))
    moved = copy.deepcopy(original)
    for clip in moved['selected'][0]['clips']:
        clip['start'][0] += 40
    _,_,after = _decode(png(moved))
    assert any(before(x,y) != after(x,y) for x in range(24,150) for y in range(100,107))
    assert any(before(x,y) != after(x,y) for x in range(90,230) for y in range(210,224))


def test_overlaps_split_lanes_and_selection_is_bounded():
    inspection = _inspection(2)
    inspection['selected'][0]['clips'][1]['start'] = [0,1]
    _,_,pixel = _decode(png(inspection))
    assert pixel(100,174) != pixel(100,252)
    assert _decode(png(_inspection(100)))[1] < 5000
    assert _decode(png({'selected':[]}))[1] >= 260
