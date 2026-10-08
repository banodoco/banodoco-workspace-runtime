"""Managed compositor dispatch remains separate from authored child tracks."""
from runtime_protocol.timeline_inspection import _attach_render_timing, _render_timing_context


def test_child_audio_track_collision_keeps_parent_visual_dispatch_and_controls():
    occurrence = {'occurrence_id': 'occ', 'shot_id': 'shot', 'internal_timeline_revision_id': 'child',
                  'start': [10, 1], 'duration': [2, 1],
                  'speed': 1, 'source_offset': 0, 'track_id': 'placement', 'mute': True, 'gain': .01}
    child = {'id': 'sound', 'clipType': 'audio', 'track': 'shared', 'at': 0, 'hold': 2,
             'volume': .5, 'opacity': .6, 'params': {'fadeIn': 1}}
    child_track = {'id': 'shared', 'kind': 'audio', 'muted': True, 'volume': .1}
    projected = [{'clip_id': 'sound', 'authored_fields': child.copy(), 'track': child_track.copy(),
                  'track_ref': {'scope': 'internal_timeline', 'scope_id': 'child', 'track_id': 'shared'}}]
    parent_track = {'id': 'shared', 'kind': 'visual', 'opacity': .3, 'volume': .4, 'muted': False,
                    'blendMode': 'screen', 'app': {'ignored': 'parent extensions'}}
    _attach_render_timing(projected, [child], occurrence, {'assets': {}})
    context = _render_timing_context({'output': {'fps': 30}}, [parent_track], [],
                                     [(occurrence, projected)], transition_free=True)
    assert context['status'] == 'complete'
    assert context['tracks'] == [{key: value for key, value in parent_track.items() if key != 'app'}]
    assert projected[0]['track'] == child_track
    assert projected[0]['authored_fields']['params']['fadeIn'] == 1
    assert projected[0]['render_timing']['track'] == 'shared'
    assert projected[0]['render_timing']['volume'] == .5
    assert projected[0]['render_timing']['opacity'] == .6
    assert 'mute' not in projected[0]['render_timing'] and 'gain' not in projected[0]['render_timing']


def test_transition_free_bounded_context_keeps_parent_dispatch_controls_when_closure_is_unavailable():
    track = {'id': 'shared', 'kind': 'audio', 'muted': True, 'volume': .4}
    context = _render_timing_context({}, [track], [{'clip_id': 'missing-timing'}], [], transition_free=True)
    assert context['status'] == 'unavailable' and context['transition_free'] is True
    assert context['tracks'] == [track]
    assert context['reason'] == 'one or more closure clips lack managed render timing'
