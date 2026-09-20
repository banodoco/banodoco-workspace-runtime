from __future__ import annotations

import hashlib

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.managed_render_snapshot import ShotExpansionError, expand_shot_clips
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(value: bytes | str) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def test_direct_managed_render_admission_freezes_snapshot_before_claim(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability_digest = _digest("rendering.render")
        service.register_capability({
            "capability_id": "rendering.render",
            "definition_digest": capability_digest,
        })
        service.register_executor({
            "executor_id": "worker",
            "capabilities": ["rendering.render"],
        })
        project = service.create_project({"slug": "managed-render", "name": "Managed Render"}, idempotency_key="project")
        source = service.ingest(project["id"], b"source-media", media_type="video/mp4", idempotency_key="source")
        source_id = source["data"]["object_id"]
        timeline = {
            "timeline_id": "main",
            "slug": "main",
            "name": "Main",
            "config": {"clips": [{"id": "source", "type": "video"}]},
            "registry": {"assets": {"source": {"media_id": "media-source", "content_sha256": source_id}}},
        }
        service.create_timeline_document(project["id"], timeline, idempotency_key="timeline")

        admitted = service.create_task({
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "input_object_ids": [source_id],
            "idempotency_key": "render",
            "storage_estimate": {"scratch_bytes": 0, "output_bytes": 0},
            "spec": {
                "family": "render",
                "params": {
                    "timeline_ref": "main",
                    "expected_version": 1,
                    "selector": "rendering.remotion",
                },
            },
        })
        task = admitted["task"]
        admitted_spec = task["spec"]["spec"]
        assert admitted_spec["params"]["timeline_ref"] == "main"
        assert admitted_spec["timeline_snapshot"] == {
            "config": timeline["config"],
            "registry": timeline["registry"],
        }
        assert admitted_spec["inputs"]["timeline_ref"] == "main"
        assert admitted_spec["inputs"]["selector"] == "rendering.remotion"
        assert admitted_spec["inputs"]["timeline_authority"]["project_id"] == project["id"]
        assert admitted_spec["inputs"]["timeline_authority"]["project_slug"] == "managed-render"
        assert admitted_spec["inputs"]["timeline_authority"]["config_version"] == 1
        assert admitted_spec["inputs"]["timeline_authority"]["managed_media_admissions"] == {"media-source": source_id}
        assert task["spec"]["input_object_ids"] == [source_id]
        assert task["spec"]["storage_estimate"]["scratch_bytes"] >= 256 * 1024 * 1024
        assert task["spec"]["storage_estimate"]["output_bytes"] >= 1024 * 1024

        epoch = service.health()["runtime_epoch"]
        claimed = service.claim_next({
            "executor_id": "worker",
            "capability_ids": ["rendering.render"],
            "runtime_epoch": epoch,
        })
        assert claimed["spec"]["spec"]["timeline_snapshot"] == admitted_spec["timeline_snapshot"]
        assert claimed["spec"]["spec"]["inputs"]["timeline_authority"] == admitted_spec["inputs"]["timeline_authority"]
        assert claimed["input_object_ids"] == [source_id]
        assert claimed["storage_estimate"] == task["spec"]["storage_estimate"]
    finally:
        service.close()


def test_direct_managed_render_rejects_stale_scope_and_path_injection(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "managed-render", "name": "Managed Render"}, idempotency_key="project")
        service.create_timeline_document(
            project["id"],
            {"timeline_id": "main", "slug": "main", "config": {}, "registry": {}},
            idempotency_key="timeline",
        )
        capability_digest = _digest("rendering.render")
        body = {
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "spec": {"params": {"timeline_ref": "main", "expected_version": 2}},
        }
        with pytest.raises(ConflictError, match="expected_version"):
            service.create_task(body)

        understated = {
            **body,
            "spec": {"params": {"timeline_ref": "main"}},
            "storage_estimate": {"scratch_bytes": 1, "output_bytes": 1},
        }
        with pytest.raises(ConflictError, match="understates"):
            service.create_task(understated)

        for field, message in (
            ("timeline", "caller-supplied timeline path"),
            ("assets_registry", "assets registry path"),
            ("materialized_root", "materialization is host-owned"),
        ):
            injected = {
                **body,
                "spec": {
                    "params": {"timeline_ref": "main"},
                    "inputs": {field: "/caller/project/input"},
                },
            }
            with pytest.raises(ValidationError, match=message):
                service.create_task(injected)

        other_project = service.create_project({"slug": "other", "name": "Other"}, idempotency_key="other-project")
        wrong_scope = {**body, "project": other_project["id"], "spec": {"params": {"timeline_ref": "main"}}}
        with pytest.raises(NotFoundError, match="selected project"):
            service.create_task(wrong_scope)
    finally:
        service.close()


def test_direct_managed_render_expands_registered_shot_before_claim(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability_digest = _digest("rendering.render")
        service.register_capability({
            "capability_id": "rendering.render",
            "definition_digest": capability_digest,
        })
        project = service.create_project({"slug": "shot-render", "name": "Shot Render"}, idempotency_key="project")
        source = service.ingest(project["id"], b"shot-source", media_type="video/mp4", idempotency_key="source")
        source_id = source["data"]["object_id"]

        service.create_timeline_document(
            project["id"],
            {
                "timeline_id": "shot-child",
                "slug": "shot-child",
                "config": {
                    "clips": [{
                        "id": "child-clip",
                        "at": 0,
                        "hold": 2,
                        "track": "visual",
                        "clipType": "media",
                        "asset": "child-source",
                    }],
                },
                "registry": {
                    "assets": {
                        "child-source": {
                            "media_id": "media-child",
                            "content_sha256": source_id,
                        },
                    },
                },
            },
            idempotency_key="child-timeline",
        )
        service.create_project_shot(
            project["id"],
            {"shot_id": "shot-1", "name": "Opening shot"},
            idempotency_key="shot",
        )
        service.create_timeline_document(
            project["id"],
            {
                "timeline_id": "main",
                "slug": "main",
                "config": {
                    "clips": [{
                        "id": "shot-clip",
                        "at": 1,
                        "hold": 3,
                        "track": "visual",
                        "clipType": "shot",
                        "params": {
                            "shot_id": "shot-1",
                            "timeline_document_id": "shot-child",
                        },
                    }],
                },
                "registry": {"assets": {}},
            },
            idempotency_key="parent-timeline",
        )

        admitted = service.create_task({
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "input_object_ids": [],
            "idempotency_key": "shot-render",
            "spec": {
                "family": "rendering.render",
                "params": {
                    "timeline_ref": "main",
                    "selector": "rendering.remotion",
                    "output_name": "shot-render.mp4",
                    "profile": {},
                },
            },
        })

        task = admitted["task"]
        frozen = task["spec"]["spec"]
        clips = frozen["timeline_snapshot"]["config"]["clips"]
        assert len(clips) == 1
        assert clips[0]["clipType"] == "media"
        assert clips[0]["at"] == 1.0
        assert clips[0]["shot_occurrence_id"] == "shot-occ-0000-shot-1"
        assert clips[0]["shot_name"] == "Opening shot"
        assert "shot" not in {clip.get("clipType") for clip in clips}
        assert frozen["timeline_snapshot"]["registry"]["assets"]["child-source"]["content_sha256"] == source_id
        assert task["spec"]["input_object_ids"] == [source_id]
        assert frozen["inputs"]["selector"] == "rendering.remotion"
        assert frozen["inputs"]["output_name"] == "shot-render.mp4"
        assert frozen["inputs"]["profile"] == {}

        authority = frozen["inputs"]["timeline_authority"]
        assert authority["expansion"]["shots"][0]["version"] == 1
        assert authority["expansion"]["children"][0]["timeline_id"] == "shot-child"
        assert authority["materialized_registry_hash"] != authority["registry_hash"]
    finally:
        service.close()


def test_direct_managed_render_accepts_root_static_image_hold(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability_digest = _digest("rendering.render")
        service.register_capability({
            "capability_id": "rendering.render",
            "definition_digest": capability_digest,
        })
        project = service.create_project({"slug": "overlay-render", "name": "Overlay Render"}, idempotency_key="project")
        overlay = service.ingest(project["id"], b"overlay-png", media_type="image/png", idempotency_key="overlay")
        overlay_id = overlay["data"]["object_id"]
        service.create_timeline_document(
            project["id"],
            {
                "timeline_id": "main",
                "slug": "main",
                "config": {
                    "tracks": [{"id": "frame", "kind": "visual"}],
                    "clips": [{
                        "id": "frame-overlay",
                        "at": 0,
                        "hold": 5,
                        "track": "frame",
                        "clipType": "media",
                        "asset": "frame-overlay",
                    }],
                },
                "registry": {
                    "assets": {
                        "frame-overlay": {
                            "type": "image",
                            "media_id": "media-overlay",
                            "content_sha256": overlay_id,
                        },
                    },
                },
            },
            idempotency_key="timeline",
        )

        admitted = service.create_task({
            "project": project["id"],
            "capability_id": "rendering.render",
            "capability_digest": capability_digest,
            "input_object_ids": [],
            "idempotency_key": "overlay-render",
            "spec": {
                "family": "rendering.render",
                "params": {"timeline_ref": "main", "selector": "rendering.remotion"},
            },
        })

        clip = admitted["task"]["spec"]["spec"]["timeline_snapshot"]["config"]["clips"][0]
        assert clip["id"] == "frame-overlay"
        assert clip["hold"] == 5
    finally:
        service.close()


def test_direct_managed_render_rejects_nested_shot_before_queueing(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability_digest = _digest("rendering.render")
        service.register_capability({
            "capability_id": "rendering.render",
            "definition_digest": capability_digest,
        })
        project = service.create_project({"slug": "nested-shot", "name": "Nested Shot"}, idempotency_key="project")
        service.create_timeline_document(
            project["id"],
            {
                "timeline_id": "child",
                "slug": "child",
                "config": {"clips": [{
                    "id": "nested",
                    "clipType": "shot",
                    "at": 0,
                    "hold": 1,
                    "params": {"shot_id": "nested", "timeline_document_id": "missing"},
                }]},
                "registry": {"assets": {}},
            },
            idempotency_key="child",
        )
        service.create_project_shot(project["id"], {"shot_id": "outer", "name": "Outer"}, idempotency_key="outer")
        service.create_timeline_document(
            project["id"],
            {
                "timeline_id": "main",
                "slug": "main",
                "config": {"clips": [{
                    "id": "outer-clip",
                    "clipType": "shot",
                    "at": 0,
                    "hold": 1,
                    "params": {"shot_id": "outer", "timeline_document_id": "child"},
                }]},
                "registry": {"assets": {}},
            },
            idempotency_key="main",
        )

        with pytest.raises(ValidationError, match="nested shot"):
            service.create_task({
                "project": project["id"],
                "capability_id": "rendering.render",
                "capability_digest": capability_digest,
                "input_object_ids": [],
                "idempotency_key": "nested-render",
                "spec": {"params": {"timeline_ref": "main"}},
            })
        assert service.list_project_tasks(project["id"])["items"] == []
    finally:
        service.close()


def test_shot_expansion_rejects_conflicting_asset_keys():
    config = {
        "clips": [{
            "id": "shot",
            "clipType": "shot",
            "at": 0,
            "hold": 1,
            "params": {"shot_id": "shot-1", "timeline_document_id": "child"},
        }],
    }
    registry = {"assets": {"shared": {"media_id": "parent-media"}}}

    with pytest.raises(ShotExpansionError, match="asset key collision"):
        expand_shot_clips(
            config,
            registry,
            load_timeline=lambda _ref: (
                {"clips": [{"id": "child-clip", "at": 0, "hold": 1, "asset": "shared"}]},
                {"assets": {"shared": {"media_id": "child-media"}}},
            ),
        )


def test_shot_expansion_namespaces_repeated_child_clip_ids_and_trims_left_window():
    config = {
        "clips": [
            {
                "id": "shot-a",
                "clipType": "shot",
                "at": 1,
                "hold": 2,
                "params": {"shot_id": "shot-1", "timeline_document_id": "child"},
            },
            {
                "id": "shot-b",
                "clipType": "shot",
                "at": 4,
                "hold": 2,
                "params": {"shot_id": "shot-1", "timeline_document_id": "child"},
            },
        ],
    }
    child_config = {
        "clips": [{
            "id": "shared-child-id",
            "clipType": "media",
            "at": -0.5,
            "hold": 2,
            "from": 0,
            "to": 2,
            "asset": "shared",
        }],
    }
    expanded, _registry = expand_shot_clips(
        config,
        {"assets": {}},
        load_timeline=lambda _ref: (child_config, {"assets": {"shared": {"media_id": "media"}}}),
    )

    clips = expanded["clips"]
    assert [clip["id"] for clip in clips] == [
        "shot-occ-0000-shot-1--shared-child-id",
        "shot-occ-0001-shot-1--shared-child-id",
    ]
    assert [clip["shot_occurrence_id"] for clip in clips] == [
        "shot-occ-0000-shot-1",
        "shot-occ-0001-shot-1",
    ]
    assert clips[0]["at"] == 1.0
    assert clips[0]["hold"] == 1.5
    assert clips[0]["from"] == 0.5
    assert clips[0]["to"] == 2.0


def test_shot_expansion_rejects_non_finite_or_non_positive_timing():
    with pytest.raises(ShotExpansionError, match="finite"):
        expand_shot_clips(
            {"clips": [{"id": "shot", "clipType": "shot", "at": float("nan"), "hold": 1, "params": {"shot_id": "s", "timeline_document_id": "child"}}]},
            {"assets": {}},
            load_timeline=lambda _ref: ({"clips": []}, {"assets": {}}),
        )
    with pytest.raises(ShotExpansionError, match="positive hold"):
        expand_shot_clips(
            {"clips": [{"id": "shot", "clipType": "shot", "at": 0, "hold": 0, "params": {"shot_id": "s", "timeline_document_id": "child"}}]},
            {"assets": {}},
            load_timeline=lambda _ref: ({"clips": []}, {"assets": {}}),
        )
