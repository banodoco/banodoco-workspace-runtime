from __future__ import annotations

import sys
import json
from pathlib import Path

import pytest

from runtime_protocol.errors import NotFoundError, ValidationError
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from banodoco_workspace_client import WorkspaceClient


def _service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "views", "name": "Views"}, idempotency_key="project")
    service.create_timeline(project["id"], "main", idempotency_key="timeline")
    return service, project["id"], root


def _publication(project, *, revision="parent-1", expected_head=None, offset=0):
    occurrence = lambda suffix, start: {
        "occurrence_id": suffix, "shot_id": "shot-1", "shot_revision_id": "shot-rev-1",
        "placement": {"start_ms": start}, "duration_ms": 1000, "source_offset": 0,
        "speed": 1, "track": "picture", "transform": {}, "gain": 1,
        "mute": False, "provenance": {},
    }
    return {
        "project_id": project, "timeline_id": "main", "expected_head": expected_head,
        "parent_revision_id": revision,
        "internal_timeline_revisions": [{
            "timeline_id": "main", "revision_id": "internal-1",
            "payload": {"tracks": [{"id": "picture"}], "clips": [
                {"id": "caption", "clip_type": "text", "track": "picture", "at_ms": 125,
                 "duration_ms": 500, "text": "A | <B>"}], "effects": [], "audio": [],
                "layout": {}, "registry": {}, "assets": []},
        }],
        "shot_revisions": [{
            "shot_id": "shot-1", "revision_id": "shot-rev-1", "internal_timeline_revision_id": "internal-1",
            "payload": {"metadata": {"title": "opening"}, "items": [], "pools": [],
                        "selected_variants": {}, "provenance": {}, "generation_inputs": {},
                        "audio_bindings": [], "text_bindings": []},
        }],
        "parent_composition": {"config": {}, "registry": {}, "clips": [],
                               "occurrences": [occurrence("first", offset), occurrence("second", offset + 1000),
                                               occurrence("third", offset + 2000)]},
    }


def _with_clips(publication, clips):
    publication["internal_timeline_revisions"][0]["payload"]["clips"] = clips
    return publication


def _clip(clip_id, at_ms=0, duration_ms=500):
    return {"id": clip_id, "clip_type": "text", "track": "picture", "at_ms": at_ms,
            "duration_ms": duration_ms, "text": clip_id}


def test_pinned_inspection_and_neighbor_order(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish-1")
        first = service.inspect_timeline(project, "main", {"occurrence": "second", "neighbors": 1})
        assert first["revision_id"] == "parent-1"
        assert [row["occurrence"]["occurrence_id"] for row in first["selected"]] == ["first", "second", "third"]
        assert [row["role"] for row in first["selected"]] == ["neighbor", "target", "neighbor"]
        assert first["selected"][1]["clips"][0]["start"] == [9, 8]
        assert first["selected"][1]["clips"][0]["duration"] == [1, 2]

        later = _publication(project, revision="parent-2", expected_head="parent-1", offset=5000)
        later.pop("internal_timeline_revisions")
        later.pop("shot_revisions")
        service.publish_parent_composition(project, "main", later, idempotency_key="publish-2")
        pinned = service.inspect_timeline(project, "main", {"revision_id": "parent-1", "occurrence": "second"})
        current = service.inspect_timeline(project, "main", {"occurrence": "second"})
        assert pinned["snapshot_digest"] == first["snapshot_digest"]
        assert pinned["selected"][0]["clips"][0]["start"] == [9, 8]
        assert current["selected"][0]["clips"][0]["start"] == [49, 8]
        assert current["snapshot_digest"] != pinned["snapshot_digest"]
    finally:
        service.close()


def test_selector_miss_validation_and_project_scope(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish-1")
        missing = service.inspect_timeline(project, "main", {"occurrence": "missing", "neighbors": 2})
        assert missing["selection_status"] == "selector_miss"
        assert missing["selected"] == []
        assert service.inspect_timeline(project, "main", {"clip": "caption", "range": "1..2"})["target_count"] == 1
        with pytest.raises(ValidationError):
            service.inspect_timeline(project, "main", {"neighbors": 3})
        with pytest.raises(ValidationError):
            service.inspect_timeline(project, "main", {"range": "2..1"})
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign")
        with pytest.raises(NotFoundError):
            service.inspect_timeline(foreign["id"], "main", {})
    finally:
        service.close()


def test_selection_and_range_filter_before_presentation_limit(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        publication = _publication(project)
        publication["parent_composition"]["occurrences"] = publication["parent_composition"]["occurrences"][:2]
        publication["parent_composition"]["occurrences"][0].update(shot_id="shot-unrelated", shot_revision_id="shot-rev-unrelated")
        publication["parent_composition"]["occurrences"][1].update(shot_id="shot-selected", shot_revision_id="shot-rev-selected")
        internal = publication["internal_timeline_revisions"][0]
        internal["payload"]["clips"] = [_clip(f"dense-selected-{index}") for index in range(101)]
        unrelated_internal = {**internal, "revision_id": "internal-unrelated", "payload": {
            **internal["payload"], "clips": [_clip(f"dense-unrelated-{index}") for index in range(101)]
        }}
        internal["revision_id"] = "internal-selected"
        publication["internal_timeline_revisions"].append(unrelated_internal)
        shot = publication["shot_revisions"][0]
        publication["shot_revisions"] = [
            {**shot, "shot_id": "shot-selected", "revision_id": "shot-rev-selected", "internal_timeline_revision_id": "internal-selected"},
            {**shot, "shot_id": "shot-unrelated", "revision_id": "shot-rev-unrelated", "internal_timeline_revision_id": "internal-unrelated"},
        ]
        service.publish_parent_composition(project, "main", publication, idempotency_key="publish-dense")
        selected = service.inspect_timeline(project, "main", {"occurrence": "second", "limit": 1})
        assert selected["target_count"] == 1
        assert [clip["clip_id"] for row in selected["selected"] for clip in row["clips"]] == ["dense-selected-0"]
        assert selected["next_cursor"]
        next_page = service.inspect_timeline(project, "main", {
            "occurrence": "second", "limit": 1, "cursor": selected["next_cursor"],
        })
        assert [clip["clip_id"] for row in next_page["selected"] for clip in row["clips"]] == ["dense-selected-1"]
        assert selected["next_cursor"] is not None

        range_publication = _publication(project, revision="parent-2", expected_head="parent-1")
        range_publication["internal_timeline_revisions"][0]["revision_id"] = "internal-2"
        range_publication["shot_revisions"][0]["revision_id"] = "shot-rev-2"
        range_publication["shot_revisions"][0]["internal_timeline_revision_id"] = "internal-2"
        for occurrence in range_publication["parent_composition"]["occurrences"]:
            occurrence["shot_revision_id"] = "shot-rev-2"
            occurrence["duration_ms"] = 4000
        _with_clips(range_publication, [_clip("ends-at-one", 0, 1000), _clip("overlaps", 1000, 1000), _clip("gap", 2500, 500)])
        service.publish_parent_composition(project, "main", range_publication, idempotency_key="publish-range")
        ranged = service.inspect_timeline(project, "main", {"occurrence": "first", "range": "1..2", "limit": 10})
        assert [clip["clip_id"] for row in ranged["selected"] for clip in row["clips"]] == ["overlaps"]
    finally:
        service.close()


def test_visible_time_vectors_apply_speed_once_clip_to_occurrence_and_keep_half_open_ranges(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        publication = _publication(project)
        publication["parent_composition"]["occurrences"] = publication["parent_composition"]["occurrences"][:1]
        publication["parent_composition"]["occurrences"][0]["duration_ms"] = 3000
        _with_clips(publication, [
            {"id": "hold-plain", "clip_type": "text", "track": "picture", "at": 0.125, "hold": 0.5, "speed": 1},
            {"id": "duration-ms-fast", "clip_type": "text", "track": "picture", "at_ms": 1, "duration_ms": 17, "speed": 2},
            {"id": "trim-slow", "clip_type": "media", "track": "picture", "at": 0.1, "from": 2, "to": 3, "speed": 0.5},
            {"id": "trim-fast", "clip_type": "media", "track": "picture", "at": 0.1, "from": 2, "to": 6, "speed": 2},
            {"id": "hold-fast-clipped", "clip_type": "text", "track": "picture", "at": 2.25, "hold": 4, "speed": 2},
            {"id": "hold-slow-clipped", "clip_type": "text", "track": "picture", "at": 1.75, "hold": 1, "speed": 0.5},
            {"id": "adjacent", "clip_type": "text", "track": "picture", "at": 0.625, "hold": 0.25, "speed": 1},
        ])
        service.publish_parent_composition(project, "main", publication, idempotency_key="publish-visible-time")

        result = service.inspect_timeline(project, "main", {"occurrence": "first", "limit": 20})
        clips = {clip["clip_id"]: clip for row in result["selected"] for clip in row["clips"]}
        assert {
            clip_id: (clip["start"], clip["duration"])
            for clip_id, clip in clips.items()
        } == {
            "hold-plain": ([1, 8], [1, 2]),
            "duration-ms-fast": ([1, 1000], [17, 2000]),
            "trim-slow": ([1, 10], [2, 1]),
            "trim-fast": ([1, 10], [2, 1]),
            "hold-fast-clipped": ([9, 4], [3, 4]),
            "hold-slow-clipped": ([7, 4], [5, 4]),
            "adjacent": ([5, 8], [1, 4]),
        }
        assert clips["trim-slow"]["source_from"] == 2
        assert clips["trim-slow"]["source_to"] == 3
        assert clips["trim-fast"]["source_from"] == 2
        assert clips["trim-fast"]["source_to"] == 6

        ending_at_boundary = service.inspect_timeline(
            project, "main", {"clip": "hold-plain", "range": "0.625..0.875"},
        )
        starting_at_boundary = service.inspect_timeline(
            project, "main", {"clip": "adjacent", "range": "0.625..0.875"},
        )
        assert ending_at_boundary["selection_status"] == "selector_miss"
        assert starting_at_boundary["selection_status"] == "selected"
    finally:
        service.close()


def test_inspection_continuation_is_stable_bounded_and_query_bound(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        publication = _publication(project)
        publication["parent_composition"]["occurrences"] = publication["parent_composition"]["occurrences"][:1]
        _with_clips(publication, [_clip(f"clip-{index}") for index in range(7)])
        service.publish_parent_composition(project, "main", publication, idempotency_key="publish-pages")
        options = {"occurrence": "first", "limit": 3}
        first = service.inspect_timeline(project, "main", options)
        second = service.inspect_timeline(project, "main", {**options, "cursor": first["next_cursor"]})
        third = service.inspect_timeline(project, "main", {**options, "cursor": second["next_cursor"]})
        flatten = lambda page: [clip["clip_id"] for row in page["selected"] for clip in row["clips"]]
        assert flatten(first) == ["clip-0", "clip-1", "clip-2"]
        assert flatten(second) == ["clip-3", "clip-4", "clip-5"]
        assert flatten(third) == ["clip-6"]
        assert first["next_cursor"] and second["next_cursor"] and third["next_cursor"] is None
        assert all(len(flatten(page)) <= options["limit"] for page in (first, second, third))
        for changed in ({"occurrence": "other", "limit": 3}, {"occurrence": "first", "limit": 2},
                        {"occurrence": "first", "range": "0..1", "limit": 3}):
            with pytest.raises(ValidationError, match="cursor does not match"):
                service.inspect_timeline(project, "main", {**changed, "cursor": first["next_cursor"]})

        later = _publication(project, revision="parent-2", expected_head="parent-1")
        later.pop("internal_timeline_revisions")
        later.pop("shot_revisions")
        service.publish_parent_composition(project, "main", later, idempotency_key="publish-new-head")
        with pytest.raises(ValidationError, match="cursor does not match"):
            service.inspect_timeline(project, "main", {**options, "cursor": first["next_cursor"]})
    finally:
        service.close()


def test_inspection_retains_global_closure_safety_cap(tmp_path):
    service, project, _ = _service(tmp_path)
    try:
        publication = _publication(project)
        template = publication["parent_composition"]["occurrences"][0]
        publication["parent_composition"]["occurrences"] = [
            {**template, "occurrence_id": f"occ-{index}", "placement": {"start_ms": index * 1000}}
            for index in range(21)
        ]
        _with_clips(publication, [_clip(f"clip-{index}") for index in range(100)])
        service.publish_parent_composition(project, "main", publication, idempotency_key="publish-too-many")
        with pytest.raises(ValidationError, match="closure exceeds clip limit"):
            service.inspect_timeline(project, "main", {"limit": 1})
    finally:
        service.close()


def test_markdown_png_custody_and_dedup(tmp_path):
    service, project, root = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish-1")
        options = {"occurrence": "second", "neighbors": 1, "formats": ["md", "png"]}
        result = service.create_timeline_view(project, "main", options)
        again = service.create_timeline_view(project, "main", options)
        assert result["artifacts"]["md"] == again["artifacts"]["md"]
        assert result["formats"]["png"]["status"] == "available"
        object_id = result["artifacts"]["md"]["object_id"]
        assert service.object_location(project, object_id)["verified"] is True
        _, content = service.object(object_id)
        assert b"Parent revision: parent-1" in content
        assert b"first" in content and b"second" in content and b"third" in content
        assert b"A &#124; &lt;B&gt;" in content
        png_id = result["artifacts"]["png"]["object_id"]
        assert service.object(png_id)[1].startswith(b"\x89PNG\r\n\x1a\n")
        assert "png" in service.create_timeline_view(project, "main", {"formats": ["png"]})["artifacts"]
    finally:
        service.close()
    reopened = RuntimeService(root)
    try:
        assert reopened.object_location(project, object_id)["verified"] is True
        assert reopened.object(object_id)[1] == content
        assert reopened.object_location(project, png_id)["verified"] is True
    finally:
        reopened.close()


def test_daemon_generated_client_without_executor_catalog(tmp_path):
    service, project, root = _service(tmp_path)
    try:
        service.publish_parent_composition(project, "main", _publication(project), idempotency_key="publish-1")
    finally:
        service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        inspection = client.inspect_timeline(project, "main", {"occurrence": "second", "neighbors": 1})
        assert inspection["revision_id"] == "parent-1"
        view = client.create_timeline_view(project, "main", {"occurrence": "second", "formats": ["md", "png"]})
        assert view["formats"]["png"]["status"] == "available"
        assert b"second" in client.get_object(view["artifacts"]["md"]["object_id"]).data
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    finally:
        daemon.stop()


def test_canonical_head_names_and_parent_targets_are_distinct_from_occurrences(tmp_path):
    fixture = json.loads((Path(__file__).parents[1] / "conformance/fixtures/canonical-timeline-parity.json").read_text())
    assert len(fixture["legacy_shells"]) == 6
    assert len(fixture["canonical_occurrences"]) == 9
    service, project, _ = _service(tmp_path)
    try:
        media_id = service.ingest(project, b"canonical-parity-media", idempotency_key="canonical-parity-media")["data"]["digest"]
        publication = _publication(project)
        base_occurrence = publication["parent_composition"]["occurrences"][0]
        base_shot = publication["shot_revisions"][0]
        base_internal = publication["internal_timeline_revisions"][0]
        publication["parent_composition"]["occurrences"] = []
        publication["shot_revisions"] = []
        publication["internal_timeline_revisions"] = []
        for index, item in enumerate(fixture["canonical_occurrences"]):
            shot_id = f"shot-{index + 1}"
            revision_id = f"shot-rev-{index + 1}"
            internal_id = f"internal-{index + 1}"
            publication["parent_composition"]["occurrences"].append({
                **base_occurrence,
                "occurrence_id": item["occurrence_id"],
                "shot_id": shot_id,
                "shot_revision_id": revision_id,
                "placement": {"start_ms": item["start_ms"]},
                "duration_ms": item["duration_ms"],
            })
            publication["shot_revisions"].append({
                **base_shot,
                "shot_id": shot_id,
                "revision_id": revision_id,
                "internal_timeline_revision_id": internal_id,
                "payload": {"name": item["name"], "assets": [], "audio_bindings": [], "text_bindings": []},
            })
            publication["internal_timeline_revisions"].append({
                **base_internal,
                "revision_id": internal_id,
                "payload": {"tracks": [{"id": "picture"}], "clips": [{"id": f"child-{index + 1}", "clip_type": "media", "track": "picture", "at_ms": 0, "duration_ms": item["duration_ms"]}], "registry": {}, "assets": []},
            })
        publication["parent_composition"]["registry"] = {"assets": {"media-1": {"media_id": media_id, "type": "image"}}}
        publication["parent_composition"]["clips"] = [
            {"id": effect["clip_id"], "clip_type": "effect", "track": "effects", "at_ms": 100, "duration_ms": 400, "asset": "media-1" if "source_object_id" in effect else None, "parameters": effect["parameters"], "elementRef": effect["element_ref"]}
            for effect in fixture["parent_effects"]
        ]
        service.publish_parent_composition(project, "main", publication, idempotency_key="publish-parity")
        result = service.inspect_timeline(project, "main", {})
        assert result["representation"] == "canonical_head"
        assert result["authority"] == "runtime_parent_composition"
        assert result["is_current_head"] is True
        assert result["head_revision_id"] == result["revision_id"] == "parent-1"
        assert result["head_content_digest"] == result["parent_content_digest"]
        assert result["occurrence_count"] == 9
        assert [row["occurrence"]["name"] for row in result["selected"]] == [item["name"] for item in fixture["canonical_occurrences"]]
        assert result["parent_clip_count"] == result["parent_clip_target_count"] == 2
        assert {clip["clip_id"] for clip in result["selected_parent_clips"]} == {"effect-with-source", "effect-code-only"}
        assert all("occurrence_id" not in clip and "shot_id" not in clip for clip in result["selected_parent_clips"])
        assert result["selected_clip_count"] == 11
        selected = service.inspect_timeline(project, "main", {"clip": "effect-code-only"})
        assert selected["target_count"] == 0
        assert [clip["clip_id"] for clip in selected["selected_parent_clips"]] == ["effect-code-only"]
        view = service.create_timeline_view(project, "main", {"clip": "effect-code-only", "formats": ["md"]})
        assert view["inspection"]["authority"] == "runtime_parent_composition"
        assert [clip["clip_id"] for clip in view["inspection"]["selected_parent_clips"]] == ["effect-code-only"]
    finally:
        service.close()
