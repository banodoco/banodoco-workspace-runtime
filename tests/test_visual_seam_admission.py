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
from runtime_protocol.visual_seam import evaluate_closure


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
