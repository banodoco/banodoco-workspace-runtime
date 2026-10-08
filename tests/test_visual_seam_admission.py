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


def _normalized(clips, policy=None):
    parent = {
        "config": {"output": {"fps": 30}, "tracks": [{"id": "v", "kind": "visual"}],
                   "app": {"visualSeamContract": policy or {}}},
        "registry": {"assets": {}}, "clips": clips, "occurrences": [],
    }
    return evaluate_closure(parent, {}, {}, timeline_id="t")[0]


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
