from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from runtime_protocol.errors import ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json
from runtime_protocol.visual_boundary import boundary_report
from runtime_protocol.visual_seam import evaluate_closure, admit_closure


ROOT = Path(__file__).resolve().parents[1]


def _fixture(path):
    return json.loads(path.read_text())


def test_shared_astrid_boundary_vectors_match_runtime_byte_for_byte():
    vectors = _fixture(ROOT / "conformance/fixtures/visual-boundary-v1.json")
    astrid_vectors = _fixture(
        ROOT.parents[3] / "Astrid/.otto/worktrees/visual-seam-contract-20261008/tests/fixtures/visual-boundary-v1.json"
    )
    assert vectors == astrid_vectors
    assert len(vectors["vectors"]) >= 10
    for vector in vectors["vectors"]:
        assert boundary_report(vector["context"]) == vector["expected"], vector["name"]


def test_historical_pinned_closure_metadata_is_labeled_and_digest_verified():
    encoded = (ROOT / "conformance/fixtures/visual-seam-old-closure.json.gz.base64").read_bytes()
    fixture = json.loads(gzip.decompress(base64.b64decode(encoded)))
    assert fixture["provenance"]["source"] == "read-only Runtime immutable revision rows"
    assert fixture["provenance"]["mediaLoaded"] is False
    parent = fixture["parent"]
    digest = "sha256:" + hashlib.sha256(canonical_json(parent).encode()).hexdigest()
    assert digest == fixture["provenance"]["parent_digest"]
    assert fixture["provenance"]["parent_revision_id"].startswith("authoring-parent-revision-")
    # This verifies recovered historical metadata closure only; no media/pixel
    # evidence is inferred from the synthetic cross-runtime vectors.
    report, _ = evaluate_closure(
        parent,
        {(s["shot_id"], s["revision_id"]): s for s in fixture["shots"]},
        {x["revision_id"]: x for x in fixture["internal"]},
        timeline_id=fixture["provenance"]["timeline_id"],
    )
    assert report["version"] == 1
    assert report["spans"]


def _normalized(clips, policy=None, *, tracks=None, effects=None, assets=None):
    parent = {
        "config": {"output": {"fps": 30}, "tracks": tracks or [{"id": "v", "kind": "visual"}], "effects": effects or [],
                   "app": {"visualSeamContract": policy or {}}},
        "registry": {"assets": assets or {}}, "clips": clips, "occurrences": [],
    }
    return evaluate_closure(parent, {}, {}, timeline_id="t")[0]


def _portable_policy(report, frame, kind="synchronized"):
    boundary = next(b for b in report["boundaries"] if b["frame"] == frame)
    return {"intents": {str(frame): {"contextVersion": "visual-seam/v1", "frame": frame, "kind": kind,
                                    "context": boundary["canonicalContext"],
                                    "participants": boundary["canonicalCueIds"] if kind == "synchronized" else []}}}


def _motion_keys():
    return [{"at": 0, "x": 0, "y": 0, "width": 100, "height": 100, "opacity": 1},
            {"at": 0.5, "x": 10, "y": 0, "width": 100, "height": 100, "opacity": 1}]


@pytest.mark.parametrize("empty", [[], {}])
def test_optional_empty_effects_match_absence_without_erasing_real_effects(empty):
    clips = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "track": "v", "at": 1, "hold": 1, "entrance": "fade"}]
    absent = _normalized(clips)
    policy = _portable_policy(absent, 30)
    clips[1]["effects"] = empty
    current = _normalized(clips, policy)
    assert current["boundaries"][0]["canonicalContext"] == absent["boundaries"][0]["canonicalContext"]
    assert not current["blocked"]
    real = [{"id": "real", "type": "animated-media-transform", "params": {"keyframes": _motion_keys()}}]
    clips[1]["effects"] = real
    changed = _normalized(clips, policy)
    owner = next(o for o in changed["boundaries"][0]["canonicalContext"]["owners"] if o["path"] == ["clip", "b"])
    assert owner["clip"]["effects"] == real
    assert changed["boundaries"][0]["canonicalContext"] != absent["boundaries"][0]["canonicalContext"]
    assert changed["blocked"]


def test_historical_phase_and_motion_require_named_portable_acknowledgement():
    vector = next(v for v in _fixture(ROOT / "conformance/fixtures/visual-boundary-v1.json")["vectors"]
                  if v["name"] == "old EndSpanning phase 1259 then geometry 1260")
    effect = vector["context"]["clip"]
    clips = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1259 / 30},
             {"id": "b", "clipType": "media", "track": "v", "at": 1259 / 30, "hold": 20}, effect]
    assets = {effect["asset"]: {"file": vector["context"]["source"], "type": "video"}}
    baseline = _normalized(clips, assets=assets)
    assert baseline["blocked"]
    boundary = baseline["boundaries"][0]
    assert (1259, "phase-change", "iteration") in [(c["frame"], c["kind"], c["id"]) for c in boundary["cues"]]
    assert (1260, "motion-start", "move-up") in [(c["frame"], c["kind"], c["id"]) for c in boundary["cues"]]
    assert all(c["path"] == ["parent", "t", "clip", effect["id"]] for c in boundary["cues"])
    assert not baseline["opaqueElements"]
    policy = _portable_policy(baseline, 1259)
    assert not _normalized(clips, policy, assets=assets)["blocked"]
    policy["intents"]["1259"]["participants"].pop()
    assert _normalized(clips, policy, assets=assets)["blocked"]


def test_continuous_and_deeper_nested_effects_retain_known_motion_and_opaque_reasons():
    clips = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "track": "v", "at": 1, "hold": 1,
              "effects": [{"id": "nested", "type": "animated-media-transform", "entrance": "fade",
                           "continuous": "drift", "effects": [{"id": "deeper", "type": "submitted"}],
                           "params": {"keyframes": _motion_keys()}}]}]
    report = _normalized(clips)
    assert report["blocked"]
    path = ["parent", "t", "clip", "b", "effect", "nested"]
    opaque = next(o for o in report["opaqueElements"] if o["span"]["path"] == path)
    assert opaque["opaque"] == ["unsupported continuous timing", "unsupported nested effect timing"]
    assert any(c["path"] == path and c["id"] == "key-0" for c in report["cues"])
    assert any(c["path"] == path and c["id"] == "entrance" for c in report["cues"])


@pytest.mark.parametrize("kind", ["hard-cut", "transition", "synchronized"])
def test_incoming_crossfade_never_grants_an_unrelated_parent_effect(kind):
    clips = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "track": "v", "at": 0.8, "hold": 1,
              "transition": {"type": "crossfade", "duration": 0.2}}]
    assert not _normalized(clips)["blocked"]
    effects = [{"id": "unrelated", "type": "animated-media-transform", "at": 0.8, "hold": 1,
                "params": {"keyframes": _motion_keys()}}]
    baseline = _normalized(clips, effects=effects)
    assert not baseline["structuralIssues"]
    assert baseline["boundaries"][0]["requiresIntent"]
    assert all(c["path"] == ["parent", "t", "effect", "unrelated"] for c in baseline["boundaries"][0]["cues"])
    assert _normalized(clips, _portable_policy(baseline, 24, kind), effects=effects)["blocked"] is (kind != "synchronized")


def test_opaque_owner_activation_is_known_without_claiming_internal_phase_timing():
    clips = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "track": "v", "at": 1, "hold": 1},
             {"id": "fx", "clipType": "submitted", "track": "fx", "at": 1, "hold": 1}]
    baseline = _normalized(clips)
    assert baseline["blocked"]
    assert baseline["boundaries"][0]["cues"] == [
        {"frame": 30, "kind": "activation", "id": "owner-activation", "path": ["parent", "t", "clip", "fx"]}]
    acknowledged = _normalized(clips, _portable_policy(baseline, 30))
    assert not acknowledged["blocked"]
    assert acknowledged["boundaries"][0]["opaquePaths"] == [["parent", "t", "clip", "fx"]]


def test_opaque_primary_picture_owner_is_represented_by_the_cut_not_auxiliary_activation():
    clips = [{"id": "a", "clipType": "com.reigh.astrid.liveScene", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "com.reigh.astrid.liveScene", "track": "v", "at": 1, "hold": 1}]
    report = _normalized(clips)
    assert not report["blocked"]
    assert report["boundaries"][0]["opaquePaths"] == [["parent", "t", "clip", "b"]]
    assert not report["cues"]


def test_spanning_cue_free_secondary_picture_is_not_an_intent_owner():
    tracks = [{"id": "v", "kind": "visual"}, {"id": "secondary", "kind": "visual"}]
    clips = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "track": "v", "at": 1, "hold": 1, "entrance": "fade"},
             {"id": "spanning", "clipType": "media", "track": "secondary", "at": 0, "hold": 4}]
    baseline = _normalized(clips, tracks=tracks)
    owners = baseline["boundaries"][0]["canonicalContext"]["owners"]
    assert [o["path"] for o in owners] == [["clip", "a"], ["clip", "b"]]
    policy = _portable_policy(baseline, 30)
    assert not _normalized(clips, policy, tracks=tracks)["blocked"]
    clips[2]["opacity"] = 0.5
    assert not _normalized(clips, policy, tracks=tracks)["blocked"]
    clips[1]["entrance"] = {"type": "fade", "duration": 0.7}
    assert _normalized(clips, policy, tracks=tracks)["blocked"]


def test_two_occurrence_portable_context_ignores_spanning_secondary_child():
    tracks = [{"id": "v", "kind": "visual"}, {"id": "secondary", "kind": "visual"}]
    parent = {
        "config": {"output": {"fps": 30}, "tracks": tracks}, "registry": {}, "clips": [],
        "occurrences": [
            {"occurrence_id": "outgoing", "shot_id": "s1", "shot_revision_id": "r1",
             "placement": {"start_ms": 0}, "source_offset": 0, "duration_ms": 1000,
             "speed": 1, "track": "v", "transform": {}, "gain": 1, "mute": False},
            {"occurrence_id": "incoming", "shot_id": "s2", "shot_revision_id": "r2",
             "placement": {"start_ms": 1000}, "source_offset": 0, "duration_ms": 1000,
             "speed": 1, "track": "v", "transform": {}, "gain": 1, "mute": False},
        ],
    }
    shots = {
        ("s1", "r1"): {"internal_timeline_revision_id": "i1"},
        ("s2", "r2"): {"internal_timeline_revision_id": "i2"},
    }
    internals = {
        "i1": {"payload": {"tracks": tracks, "clips": [
            {"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
            {"id": "spanning", "clipType": "media", "track": "secondary", "at": 0, "hold": 1},
        ], "registry": {}}},
        "i2": {"payload": {"tracks": tracks, "clips": [
            {"id": "b", "clipType": "media", "track": "v", "at": 0, "hold": 1, "entrance": "fade"},
        ], "registry": {}}},
    }
    baseline, _ = evaluate_closure(parent, shots, internals, timeline_id="main")
    boundary = next(b for b in baseline["boundaries"] if b["frame"] == 30)
    assert [owner["path"] for owner in boundary["canonicalContext"]["owners"]] == [
        ["occurrence", "incoming", "clip", "b"], ["occurrence", "outgoing", "clip", "a"]]
    policy = {"intents": {"30": {"contextVersion": "visual-seam/v1", "frame": 30,
                                  "kind": "synchronized", "context": boundary["canonicalContext"],
                                  "participants": boundary["canonicalCueIds"]}}}
    parent["config"]["app"] = {"visualSeamContract": policy}
    acknowledged, _ = evaluate_closure(parent, shots, internals, timeline_id="main")
    assert not acknowledged["blocked"]

    internals["i1"]["payload"]["clips"][1]["opacity"] = 0.5
    unchanged_secondary, _ = evaluate_closure(parent, shots, internals, timeline_id="main")
    assert not unchanged_secondary["blocked"]
    internals["i2"]["payload"]["clips"][0]["entrance"] = {"type": "fade", "duration": 0.7}
    changed_picture, _ = evaluate_closure(parent, shots, internals, timeline_id="main")
    assert changed_picture["blocked"]


@pytest.mark.parametrize("mode", ["cue-free", "cue-contributor", "lane-boundary"])
def test_occurrence_context_binds_lane_boundary_children_and_independent_cues(mode):
    tracks = [{"id": "v", "kind": "visual"}, {"id": "secondary", "kind": "visual"}]
    outgoing = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
                {"id": "spanning", "clipType": "media", "track": "secondary", "at": 0, "hold": 1}]
    incoming = [{"id": "b", "clipType": "media", "track": "v", "at": 0, "hold": 1,
                 "entrance": {"type": "fade", "duration": 0.5}}]
    if mode == "cue-contributor":
        outgoing[1]["exit"] = {"type": "fade", "durationFrames": 2}
    if mode == "lane-boundary":
        incoming.append({"id": "secondary-in", "clipType": "media", "track": "secondary", "at": 0, "hold": 1})
    parent = {"config": {"output": {"fps": 30}, "tracks": tracks}, "clips": [], "registry": {},
              "occurrences": [{"occurrence_id": f"o-{i}", "shot_id": f"s-{i}", "shot_revision_id": f"sr-{i}",
                               "placement": {"start_ms": i * 1000}, "track": "v", "duration_ms": 1000}
                              for i in range(2)]}
    shots = {(f"s-{i}", f"sr-{i}"): {"internal_timeline_revision_id": f"ir-{i}"} for i in range(2)}
    internal = {f"ir-{i}": {"payload": {"clips": clips}} for i, clips in enumerate([outgoing, incoming])}
    baseline, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
    assert baseline["blocked"]
    boundary = next(b for b in baseline["boundaries"] if b["frame"] == 30)
    expected_paths = [["occurrence", "o-0", "clip", "a"]]
    if mode != "cue-free":
        expected_paths.append(["occurrence", "o-0", "clip", "spanning"])
    expected_paths.append(["occurrence", "o-1", "clip", "b"])
    if mode == "lane-boundary":
        expected_paths.append(["occurrence", "o-1", "clip", "secondary-in"])
    assert [o["path"] for o in boundary["canonicalContext"]["owners"]] == expected_paths
    # Owner selection must leave full child geometry/coverage available.
    assert len(baseline["spans"]) == len(outgoing) + len(incoming)
    assert not baseline["structuralIssues"]
    parent["config"]["app"] = {"visualSeamContract": _portable_policy(baseline, 30)}
    admitted, _ = admit_closure(parent, shots, internal, timeline_id="main")
    assert not admitted["blocked"]
    if mode == "cue-free":
        outgoing[1]["opacity"] = 0.5
        unrelated, _ = admit_closure(parent, shots, internal, timeline_id="main")
        assert unrelated["boundaries"][0]["canonicalContext"] == boundary["canonicalContext"]
    # Every selected picture or cue contributor remains bound, including the
    # secondary lane when it contributes a cue or its own adjacent pair.
    for path in expected_paths:
        clips = outgoing if path[1] == "o-0" else incoming
        clip = next(c for c in clips if c["id"] == path[-1])
        original = copy.deepcopy(clip)
        clip["opacity"] = 0.25
        changed, _ = evaluate_closure(parent, shots, internal, timeline_id="main")
        assert changed["boundaries"][0]["canonicalContext"] != boundary["canonicalContext"]
        assert changed["blocked"]
        with pytest.raises(ValidationError, match="visual seam admission blocked"):
            admit_closure(parent, shots, internal, timeline_id="main")
        clip.clear()
        clip.update(original)
    incoming[0]["entrance"] = {"type": "fade", "duration": 0.7}
    assert evaluate_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]


@pytest.mark.parametrize("mode", ["cue-free", "cue-contributor", "secondary-cut", "independent-effect"])
def test_occurrence_seam_binds_lane_boundary_owners_and_independent_cue_contributors(mode):
    tracks = [{"id": "v", "kind": "visual"}, {"id": "secondary", "kind": "visual"}]
    outgoing = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
                {"id": "spanning", "clipType": "media", "track": "secondary", "at": 0, "hold": 1}]
    incoming = [{"id": "b", "clipType": "media", "track": "v", "at": 0, "hold": 1,
                 "entrance": {"type": "fade", "duration": 0.5}}]
    if mode == "cue-contributor":
        outgoing[1]["exit"] = {"type": "fade", "durationFrames": 2}
    if mode == "secondary-cut":
        incoming.append({"id": "secondary-in", "clipType": "media", "track": "secondary", "at": 0, "hold": 1})
    if mode == "independent-effect":
        outgoing[1]["effects"] = [{"id": "nested", "type": "animated-media-transform",
                                    "params": {"keyframes": [
                                        {**_motion_keys()[0], "at": 28 / 30},
                                        {**_motion_keys()[1], "at": 29 / 30}]}}]
    parent = {"config": {"output": {"fps": 30}, "tracks": tracks}, "clips": [], "registry": {},
              "occurrences": [{"occurrence_id": f"o-{i}", "shot_id": f"s-{i}", "shot_revision_id": f"sr-{i}",
                               "placement": {"start_ms": i * 1000}, "track": "v", "duration_ms": 1000}
                              for i in range(2)]}
    shots = {(f"s-{i}", f"sr-{i}"): {"internal_timeline_revision_id": f"ir-{i}"} for i in range(2)}
    internal = {f"ir-{i}": {"payload": {"tracks": tracks, "clips": clips}}
                for i, clips in enumerate((outgoing, incoming))}
    baseline, metadata = evaluate_closure(parent, shots, internal, timeline_id="main")
    boundary = next(b for b in baseline["boundaries"] if b["frame"] == 30)
    expected_paths = [["occurrence", "o-0", "clip", "a"]]
    if mode in ("cue-contributor", "secondary-cut"):
        expected_paths.append(["occurrence", "o-0", "clip", "spanning"])
    if mode == "independent-effect":
        expected_paths.append(["occurrence", "o-0", "clip", "spanning", "effect", "nested"])
    expected_paths.append(["occurrence", "o-1", "clip", "b"])
    if mode == "secondary-cut":
        expected_paths.append(["occurrence", "o-1", "clip", "secondary-in"])
    assert [o["path"] for o in boundary["canonicalContext"]["owners"]] == expected_paths
    # Omission from the portable witness never removes child disclosure or coverage.
    assert any(s["path"][-1] == "spanning" for s in metadata["spans"])
    assert not baseline["structuralIssues"]
    assert baseline["blocked"]
    parent["config"]["app"] = {"visualSeamContract": _portable_policy(baseline, 30)}
    assert not admit_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]
    if mode == "cue-free":
        outgoing[1]["opacity"] = 0.5
        assert not admit_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]
        outgoing[1]["exit"] = {"type": "fade", "durationFrames": 2}
    elif mode == "independent-effect":
        outgoing[1]["effects"][0]["params"]["keyframes"][1]["x"] = 20
    else:
        outgoing[1]["opacity"] = 0.5
    with pytest.raises(ValidationError) as error:
        admit_closure(parent, shots, internal, timeline_id="main")
    assert error.value.details["code"] == "visual_seam_admission_blocked"
    # Reauthor, then a relevant incoming fade edit must independently invalidate.
    current = evaluate_closure(parent, shots, internal, timeline_id="main")[0]
    parent["config"]["app"] = {"visualSeamContract": _portable_policy(current, 30)}
    assert not admit_closure(parent, shots, internal, timeline_id="main")[0]["blocked"]
    incoming[0]["entrance"]["duration"] = 0.7
    with pytest.raises(ValidationError):
        admit_closure(parent, shots, internal, timeline_id="main")


@pytest.mark.parametrize("pause", [
    {"kind": "pause", "track": "v", "startFrame": 29, "endFrame": 60},
    {"kind": "pause", "track": "v", "startFrame": 30, "endFrame": 61},
    {"kind": "pause", "track": "secondary", "startFrame": 30, "endFrame": 60},
    {"kind": "pause", "track": "v", "startFrame": True, "endFrame": 60},
])
def test_pause_grants_only_its_exact_picture_interval(pause):
    clips = [{"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1},
             {"id": "b", "clipType": "media", "track": "v", "at": 2, "hold": 1,
              "app": {"visualBoundary": {"intentionalPause": True}}}]
    assert _normalized(clips)["blocked"]
    assert _normalized(clips, {"gaps": [pause]})["blocked"]
    policy = {"gaps": [{"kind": "pause", "track": "v", "startFrame": 30, "endFrame": 60}]}
    assert not _normalized(clips, policy)["blocked"]
    clips.append({"id": "c", "clipType": "media", "track": "v", "at": 4, "hold": 1})
    assert [i["frame"] for i in _normalized(clips, policy)["structuralIssues"]] == [120]


@pytest.mark.parametrize("shape", [
    {"entrance": "fade", "exit": ["fade", {"id": "slide-up", "durationFrames": 6}], "transition": "crossfade"},
    {"entrance": ["fade", {"id": "slide-up", "durationFrames": 6}], "exit": "fade", "transition": ["crossfade"]},
])
def test_materialization_retains_effect_shapes_and_child_parent_scope(shape):
    parent = _unsafe_publication("p")["parent_composition"]
    parent["occurrences"][0]["placement"]["start_ms"] = 1000
    local = {"id": "local", "type": "animated-media-transform", "params": {"keyframes": _motion_keys()}}
    child_effect = {"id": "child", "type": "animated-media-transform", "at": 1, "hold": 1, "params": {"keyframes": _motion_keys()}}
    parent_effect = {"id": "parent", "type": "animated-media-transform", "at": 2, "hold": 1, "params": {"keyframes": _motion_keys()}}
    parent["config"]["effects"] = [parent_effect]
    child = {"tracks": [{"id": "v", "kind": "visual"}], "clips": [
        {"id": "a", "clipType": "media", "track": "v", "at": 0, "hold": 1, **shape, "effects": [local]},
        {"id": "b", "clipType": "media", "track": "v", "at": 1, "hold": 1}], "effects": [child_effect]}
    original = copy.deepcopy(child)
    report, metadata = evaluate_closure(parent, {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child"}},
                                       {"unsafe-child": {"payload": child}}, timeline_id="main", materialize=True)
    rendered = metadata["render_config"]["clips"][0]
    assert all(rendered[k] == v for k, v in shape.items())
    assert rendered["effects"] == [local, child_effect]
    assert rendered["app"]["canonicalEffects"] == {"localCount": 1, "timeline": [child_effect]}
    assert metadata["render_config"]["effects"] == [parent_effect]
    assert child == original
    boundary = next(b for b in report["boundaries"] if b["frame"] == 60)
    assert any(c["path"] == ["parent", "main", "occurrence", "o", "effect", "child"] for c in boundary["cues"])
    assert any(c["path"] == ["parent", "main", "effect", "parent"] for c in boundary["cues"])
    assert report["blocked"]
    parent["config"]["app"] = {"visualSeamContract": _portable_policy(report, 60)}
    assert not evaluate_closure(parent, {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child"}},
                                {"unsafe-child": {"payload": child}}, timeline_id="main")[0]["blocked"]


def test_disclosure_is_opaque_for_unknown_effect_and_caller_report_is_ignored():
    clip = {"id": "unknown", "clipType": "submitted-plugin", "at": 0, "hold": 4, "track": "v",
            "report": {"cues": [], "opaque": []}, "visual_seam_report": {"blocked": False},
            "params": {"code": "raise RuntimeError('must not execute')"}}
    report = _normalized([clip])
    assert report["opaqueElements"]
    assert report["opaqueElements"][0]["opaque"] == ["unknown effect timing"]
    assert not report["cues"]


def test_gap_overlap_and_context_bound_intent_are_evaluated_from_authored_clips():
    clips = [
        {"id": "a", "clipType": "media", "at": 0, "hold": 1, "track": "v"},
        {"id": "b", "clipType": "media", "at": 1.2, "hold": 1, "track": "v"},
    ]
    report = _normalized(clips)
    assert any(row["code"] == "boundary/gap" and row["frames"] == 6 for row in report["structuralIssues"])
    overlapping = copy.deepcopy(clips)
    overlapping[1]["at"] = 0.8
    report = _normalized(overlapping)
    assert any(row["code"] == "boundary/overlap" and row["frames"] == 6 for row in report["structuralIssues"])
    transitioned = copy.deepcopy(overlapping)
    transitioned[1]["transition"] = {"type": "crossfade", "duration": 0.2}
    assert not any(row["code"] == "boundary/overlap" for row in _normalized(transitioned)["structuralIssues"])

    moving = [
        {"id": "a", "clipType": "media", "at": 0, "hold": 1, "track": "v"},
        {"id": "b", "clipType": "media", "at": 1, "hold": 1, "track": "v",
         "keyframes": {"x": [{"time": 0, "value": 0}, {"time": 0.5, "value": 8}]}},
    ]
    baseline = _normalized(moving)
    assert baseline["boundaries"] and baseline["boundaries"][0]["requiresIntent"]
    boundary = baseline["boundaries"][0]
    cue_ids = ["/".join(cue["path"]) + ":" + cue["kind"] + ":" + cue["id"] + ":" + str(cue["frame"])
               for cue in boundary["cues"]]
    policy = {"intents": {str(boundary["frame"]): {"frame": boundary["frame"], "kind": "synchronized",
                                                        "context": boundary["context"], "participants": cue_ids}}}
    acknowledged = _normalized(moving, policy)
    assert not acknowledged["boundaries"][0]["requiresIntent"]
    policy["intents"][str(boundary["frame"])]["context"] = "forged"
    assert _normalized(moving, policy)["boundaries"][0]["requiresIntent"]


def _unsafe_publication(project_id):
    body = {
        "project_id": project_id, "timeline_id": "main", "expected_head": None, "parent_revision_id": "unsafe-parent",
        "internal_timeline_revisions": [{"timeline_id": "main", "revision_id": "unsafe-child",
            "payload": {"tracks": [], "clips": [
                {"id": "first", "clipType": "media", "at": 0, "hold": 1, "track": "v"},
                {"id": "second", "clipType": "media", "at": 1.2, "hold": 1, "track": "v"},
            ], "effects": [], "audio": [], "layout": {}, "registry": {}, "assets": []}}],
        "shot_revisions": [{"shot_id": "s", "revision_id": "unsafe-shot", "internal_timeline_revision_id": "unsafe-child",
            "payload": {"metadata": {}, "items": [], "pools": [], "selected_variants": {}, "provenance": {},
                        "generation_inputs": {}, "audio_bindings": [], "text_bindings": []}}],
        "parent_composition": {"config": {"output": {"fps": 30}, "tracks": [{"id": "v", "kind": "visual"}]},
            "registry": {}, "clips": [], "occurrences": [{"occurrence_id": "o", "shot_id": "s", "shot_revision_id": "unsafe-shot",
                "placement": {"start_ms": 0}, "source_offset": 0, "duration_ms": 3000, "speed": 1,
                "track": "v", "transform": {}, "gain": 1, "mute": False, "provenance": {}}]},
    }
    return body


def test_publication_rejects_unsafe_resolved_child_without_partial_rows(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "seam", "name": "Seam"}, idempotency_key="project")
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        tables = ("timelines", "internal_timeline_revisions", "shot_revisions", "parent_composition_revisions",
                  "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences",
                  "composition_revision_dependencies", "timeline_events", "command_idempotency")
        before = {name: service.store.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables}
        with pytest.raises(ValidationError, match="visual seam admission"):
            service.publish_parent_composition(project["id"], "main", _unsafe_publication(project["id"]), idempotency_key="unsafe")
        after = {name: service.store.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables}
        assert after == before
    finally:
        service.close()


def test_unknown_transition_does_not_excuse_overlap():
    report = _normalized([
        {"id": "a", "clipType": "media", "at": 0, "hold": 1, "track": "v"},
        {"id": "b", "clipType": "media", "at": 0.8, "hold": 1, "track": "v",
         "transition": {"type": "not-real", "duration": 0.2}},
    ])
    assert report["blocked"]
    assert any(i["code"] == "boundary/overlap" for i in report["structuralIssues"])
    assert report["opaqueElements"]


def test_incoming_fade_is_risky_and_custom_media_reference_stays_opaque():
    report = _normalized([
        {"id": "a", "clipType": "media", "at": 0, "hold": 1, "track": "v"},
        {"id": "b", "clipType": "media", "at": 1, "hold": 1, "track": "v", "entrance": {"type": "fade", "duration": 0.5}},
        {"id": "fx", "clipType": "media", "at": 0, "hold": 2, "track": "fx", "elementRef": {"id": "custom", "kind": "effect"}},
    ])
    assert report["blocked"]
    assert any(c["id"] == "entrance" and c["frame"] == 31 for c in report["cues"])
    assert report["boundaries"][0]["opaquePaths"] == [["parent", "t", "clip", "fx"]]


@pytest.mark.parametrize("clips,code", [
    ([], "boundary/empty-child-picture"),
    ([{"id": "picture", "clipType": "media", "at": 0.2, "hold": 1, "track": "v"}], "boundary/child-picture-gap"),
    ([{"id": "picture", "clipType": "media", "at": 0, "hold": 0.5, "track": "v"},
      {"id": "tail-fx", "clipType": "end-spanning-layer", "at": 0, "hold": 1, "track": "fx"}], "boundary/child-picture-gap"),
])
def test_occurrence_requires_complete_picture_output(clips, code):
    body = _unsafe_publication("p")
    parent = body["parent_composition"]
    shots = {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child", "payload": {}}}
    internals = {"unsafe-child": {"payload": {"clips": clips}}}
    with pytest.raises(ValidationError) as error:
        admit_closure(parent, shots, internals, timeline_id="main")
    report = error.value.details["report"]
    assert error.value.details["code"] == "visual_seam_admission_blocked"
    assert any(i["code"] == code for i in report["structuralIssues"])


def test_managed_materialization_preserves_child_effects_and_offset_without_trim():
    body = _unsafe_publication("p")
    parent = body["parent_composition"]
    parent["occurrences"][0]["source_offset"] = 1500
    child_effect = {"id": "child-fade", "type": "opacity", "params": {"opacity": 0.5}}
    local_effect = {"id": "local", "type": "crop", "params": {"left": 4}}
    child = {"clips": [{"id": "picture", "clipType": "media", "at": 0, "hold": 1, "track": "v", "effects": [local_effect]}],
             "effects": [child_effect]}
    _, metadata = admit_closure(parent, {("s", "unsafe-shot"): {"internal_timeline_revision_id": "unsafe-child", "payload": {}}},
                               {"unsafe-child": {"payload": child}}, timeline_id="main", materialize=True)
    clip = metadata["render_config"]["clips"][0]
    assert clip["from"] == 1.5
    assert clip["hold"] == 1
    assert clip["effects"] == [local_effect, child_effect]
    assert "from" not in child["clips"][0]
    assert child["clips"][0]["effects"] == [local_effect]


def test_managed_render_freezes_child_effects_and_offset_from_pinned_closure(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "child-render", "name": "Child Render"}, idempotency_key="project")
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        capability = "sha256:" + hashlib.sha256(b"rendering.render").hexdigest()
        service.register_capability({"capability_id": "rendering.render", "definition_digest": capability})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.render"]})
        media = service.ingest(project["id"], b"frozen-media", media_type="video/mp4", idempotency_key="media")["data"]["object_id"]
        publication = _unsafe_publication(project["id"])
        publication["parent_composition"]["occurrences"][0]["source_offset"] = 1500
        child_effect = {"id": "child", "type": "opacity", "params": {"opacity": 0.5}}
        local_effect = {"id": "local", "type": "crop", "params": {"left": 4}}
        child = publication["internal_timeline_revisions"][0]["payload"]
        child.update({"clips": [{"id": "picture", "clipType": "media", "at": 0, "hold": 1, "track": "v", "asset": "source", "effects": [local_effect]}],
                      "effects": [child_effect], "registry": {"assets": {"source": {"object_id": media, "type": "video/mp4"}}}})
        service.publish_parent_composition(project["id"], "main", publication, idempotency_key="publish")
        task = service.create_task({"project": project["id"], "capability_id": "rendering.render", "capability_digest": capability,
                                    "input_object_ids": [], "idempotency_key": "render", "spec": {"family": "render", "params": {"timeline_ref": "main"}}})
        frozen = task["task"]["spec"]["spec"]
        clip = frozen["timeline_snapshot"]["config"]["clips"][0]
        assert clip["from"] == 1.5
        assert clip["effects"] == [local_effect, child_effect]
        assert frozen["inputs"]["timeline_authority"]["parent_revision_id"] == "unsafe-parent"
        assert not frozen["inputs"]["timeline_authority"]["visual_seam_report"]["blocked"]
    finally:
        service.close()


@pytest.mark.parametrize("clips", [[], [{"id": "picture", "clipType": "media", "at": 0.2, "hold": 1, "track": "v"}]])
def test_publication_and_historical_render_reject_uncovered_child_atomically(tmp_path, monkeypatch, clips):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "coverage", "name": "Coverage"}, idempotency_key="project")
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        capability = "sha256:" + hashlib.sha256(b"rendering.render").hexdigest()
        service.register_capability({"capability_id": "rendering.render", "definition_digest": capability})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.render"]})
        publication = _unsafe_publication(project["id"])
        publication["internal_timeline_revisions"][0]["payload"]["clips"] = clips
        tables = ("parent_composition_revisions", "internal_timeline_revisions", "shot_revisions",
                  "composition_revision_occurrences", "composition_revision_dependencies", "timeline_events",
                  "command_idempotency")
        before = {name: service.store.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables}
        with pytest.raises(ValidationError, match="visual seam admission"):
            service.publish_parent_composition(project["id"], "main", publication, idempotency_key="unsafe")
        after = {name: service.store.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in tables}
        assert after == before
        # Emulate an immutable closure accepted before the coverage policy.
        # A new managed render must still run the current independent guard.
        with monkeypatch.context() as previous_policy:
            previous_policy.setattr("runtime_protocol.service.admit_closure", lambda *args, **kwargs: ({}, None))
            service.publish_parent_composition(project["id"], "main", publication, idempotency_key="historical")
        with pytest.raises(ValidationError, match="visual seam admission"):
            service.create_task({"project": project["id"], "capability_id": "rendering.render", "capability_digest": capability,
                                 "input_object_ids": [], "idempotency_key": "render", "spec": {"family": "render", "params": {"timeline_ref": "main"}}})
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
    finally:
        service.close()
