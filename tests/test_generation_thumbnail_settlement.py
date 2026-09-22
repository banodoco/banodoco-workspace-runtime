from __future__ import annotations

import base64
import hashlib

import pytest

from runtime_protocol.errors import ConflictError, LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


CAPABILITY = "generation.thumbnail.fixture"


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _output(
    value: bytes,
    *,
    name: str,
    media_type: str,
    output_port: str | None = None,
    group_key: str | None = None,
    variant_key: str | None = None,
    ordinal: int | None = None,
    is_primary: bool | None = None,
    role: str | None = None,
    provenance: dict | None = None,
) -> dict:
    result = {
        "name": name,
        "kind": "object",
        "digest": _digest(value),
        "media_type": media_type,
        "size": len(value),
        "data_base64": base64.b64encode(value).decode("ascii"),
    }
    for key, item in {
        "output_port": output_port,
        "group_key": group_key,
        "variant_key": variant_key,
        "ordinal": ordinal,
        "is_primary": is_primary,
        "role": role,
        "provenance": provenance,
    }.items():
        if item is not None:
            result[key] = item
    if role == "thumbnail":
        result["durability"] = "durable"
    return result


def _thumbnail(value: bytes, source_object_ids: list[str], *, group_key: str = "default", media_type: str = "image/jpeg") -> dict:
    return _output(
        value,
        name="thumbnail.jpg",
        media_type=media_type,
        output_port="thumbnail",
        group_key=group_key,
        variant_key="thumbnail",
        ordinal=0,
        role="thumbnail",
        provenance={
            "thumbnail": {
                "source_object_ids": source_object_ids,
                "recipe_version": 1,
            }
        },
    )


def _service(tmp_path, slug: str) -> tuple[RuntimeService, dict]:
    root = tmp_path / slug
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    service.register_executor(
        {"executor_id": f"{slug}-worker", "capabilities": [CAPABILITY]},
        idempotency_key=f"{slug}-executor",
    )
    project = service.create_project(
        {"slug": slug, "name": slug.title()}, idempotency_key=f"{slug}-project"
    )
    return service, project


def _task(service: RuntimeService, project_id: str, effect: dict, *, key: str, inputs: list[str] | None = None) -> tuple[dict, dict]:
    task = service.create_task(
        {
            "capability_id": CAPABILITY,
            "capability_digest": _digest(CAPABILITY),
            "project": project_id,
            "input_object_ids": inputs or [],
            "settlement_effect": effect,
            "idempotency_key": key,
        }
    )
    attempt = service.claim_next(
        {
            "executor_id": task["task"].get("executor_id") or service.store.conn.execute(
                "SELECT id FROM executors ORDER BY created_at LIMIT 1"
            ).fetchone()[0],
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=f"{key}-claim",
    )
    return task, attempt


def _settle(service: RuntimeService, attempt: dict, effect: dict, outputs: list[dict], *, key: str = "settle") -> dict:
    return service.settle_attempt(
        attempt["attempt_id"],
        {
            "lease_id": attempt["lease_id"],
            "fence": attempt["fence"],
            "runtime_epoch": attempt["runtime_epoch"],
            "outputs": outputs,
            "effect": effect,
        },
        idempotency_key=key,
    )


def _create_effect(project_id: str, metadata: dict | None = None) -> dict:
    return {
        "effect_type": "generation.create_with_variant",
        "target_id": project_id,
        "payload": {
            "generation_type": "video",
            "metadata": metadata or {"shot_id": "shot-1"},
            "variant_type": "original",
            "output_name": "video",
            "output_ordinal": 0,
            "primary_policy": "preserve",
        },
    }


def _seed_generation(service: RuntimeService, project: dict, *, key: str, with_thumbnail: bool) -> dict:
    admitted = service.ingest(
        project["id"], f"admitted-{key}".encode(), media_type="image/png", idempotency_key=f"{key}-input"
    )["data"]["digest"]
    effect = _create_effect(project["id"])
    task, attempt = _task(service, project["id"], effect, key=f"{key}-task", inputs=[admitted])
    video = _output(b"primary-video-" + key.encode(), name="video", media_type="video/mp4", ordinal=0)
    outputs = [video]
    if with_thumbnail:
        outputs.append(_thumbnail(b"primary-thumbnail-" + key.encode(), [video["digest"]]))
    settled = _settle(service, attempt, effect, outputs, key=f"{key}-settle")
    variant = settled["data"]["result"]["generation_variant"]
    return {
        "task": task,
        "generation_id": variant["generation_id"],
        "variant_id": variant["variant_id"],
        "source_object_id": video["digest"],
        "thumbnail_object_id": outputs[1]["digest"] if with_thumbnail else None,
    }


def test_create_with_variant_attaches_thumbnail_without_creative_variant_pollution(tmp_path):
    service, project = _service(tmp_path, "create-thumb")
    try:
        seeded = _seed_generation(service, project, key="create", with_thumbnail=True)
        generation = service.get_generation(seeded["generation_id"])
        assert generation["metadata"]["thumbnail"] == {
            "object_id": seeded["thumbnail_object_id"],
            "source_object_id": seeded["source_object_id"],
            "recipe_version": 1,
        }
        variants = service.list_variants(seeded["generation_id"])["items"]
        assert len(variants) == 1
        associations = service.managed_outputs(seeded["task"]["task"]["id"])
        assert len(associations) == 2
        thumbnail = next(item for item in associations if item["role"] == "thumbnail")
        assert thumbnail["generation_id"] == seeded["generation_id"]
        assert thumbnail["object_id"] == seeded["thumbnail_object_id"]
        assert thumbnail["provenance"]["thumbnail"]["source_object_ids"] == [seeded["source_object_id"]]
    finally:
        service.close()


def test_publish_v1_attaches_each_group_thumbnail_by_primary_source(tmp_path):
    service, project = _service(tmp_path, "publish-thumb")
    try:
        effect = {
            "effect_type": "generation.publish_v1",
            "target_id": project["id"],
            "payload": {
                "version": 1,
                "modality": "video",
                "generation_type": "render",
                "metadata": {"shot_id": "shot-publish"},
                "partial_success_policy": "reject",
                "groups": [
                    {
                        "group_key": "left",
                        "selectors": [
                            {"selector": "left-original", "ordinal": 0, "variant_key": "original", "output_port": "video"},
                            {"selector": "left-primary", "ordinal": 1, "variant_key": "selected", "output_port": "video"},
                        ],
                    },
                    {
                        "group_key": "right",
                        "selectors": [{"selector": "right", "ordinal": 0, "variant_key": "original", "output_port": "video"}],
                    },
                ],
            },
        }
        task, attempt = _task(service, project["id"], effect, key="publish-task")
        left_original = _output(b"left-original-video", name="left-original", media_type="video/mp4", output_port="video", group_key="left", variant_key="original", ordinal=0)
        left = _output(b"left-primary-video", name="left-primary", media_type="video/mp4", output_port="video", group_key="left", variant_key="selected", ordinal=1, is_primary=True)
        right = _output(b"right-video", name="right", media_type="video/mp4", output_port="video", group_key="right", variant_key="original", ordinal=0)
        left_thumb = _thumbnail(b"left-jpeg", [left["digest"]], group_key="left")
        right_thumb = _thumbnail(b"right-jpeg", [right["digest"]], group_key="right")
        settled = _settle(service, attempt, effect, [right_thumb, left_original, left, left_thumb, right], key="publish-settle")
        publications = settled["data"]["result"]["generation_publish_v1"]["publications"]
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 3
        expected = {"left": (left, left_thumb), "right": (right, right_thumb)}
        for publication in publications:
            generation = service.get_generation(publication["generation_id"])
            source, thumbnail = expected[publication["group_key"]]
            assert generation["metadata"]["thumbnail"] == {
                "object_id": thumbnail["digest"],
                "source_object_id": source["digest"],
                "recipe_version": 1,
            }
        thumbnail_associations = [item for item in service.managed_outputs(task["task"]["id"]) if item["role"] == "thumbnail"]
        assert {item["generation_id"] for item in thumbnail_associations} == {
            publication["generation_id"] for publication in publications
        }
    finally:
        service.close()


def test_variant_append_accepts_auxiliary_thumbnail_and_preserves_primary_descriptor(tmp_path):
    service, project = _service(tmp_path, "append-thumb")
    try:
        seeded = _seed_generation(service, project, key="append-seed", with_thumbnail=True)
        effect = {
            "effect_type": "generation.variant.append",
            "target_id": seeded["generation_id"],
            "expected_version": 1,
            "payload": {
                "source_variant_id": seeded["variant_id"],
                "source_object_id": seeded["source_object_id"],
                "variant_type": "edit",
                "output_name": "video",
                "output_ordinal": 0,
                "primary_policy": "preserve",
            },
        }
        task, attempt = _task(
            service, project["id"], effect, key="append-task", inputs=[seeded["source_object_id"]]
        )
        edited = _output(b"edited-video", name="video", media_type="video/mp4", ordinal=0)
        edited_thumb = _thumbnail(b"edited-jpeg", [edited["digest"]])
        _settle(service, attempt, effect, [edited, edited_thumb], key="append-settle")
        generation = service.get_generation(seeded["generation_id"])
        assert generation["version"] == 2
        assert generation["metadata"]["thumbnail"] == {
            "object_id": seeded["thumbnail_object_id"],
            "source_object_id": seeded["source_object_id"],
            "recipe_version": 1,
        }
        variants = service.list_variants(seeded["generation_id"])["items"]
        assert len(variants) == 2
        assert len(service.managed_outputs(task["task"]["id"])) == 2
    finally:
        service.close()


def test_thumbnail_attach_backfills_atomically_and_replays_without_changing_generation_identity(tmp_path):
    service, project = _service(tmp_path, "attach-thumb")
    try:
        seeded = _seed_generation(service, project, key="attach-seed", with_thumbnail=False)
        generation_before = service.get_generation(seeded["generation_id"])
        effect = {
            "effect_type": "generation.thumbnail.attach",
            "target_id": seeded["generation_id"],
            "expected_version": 1,
            "payload": {
                "source_object_id": seeded["source_object_id"],
                "output_name": "thumbnail.jpg",
                "output_ordinal": 0,
                "recipe_version": 1,
            },
        }
        task, attempt = _task(
            service, project["id"], effect, key="attach-task", inputs=[seeded["source_object_id"]]
        )
        thumbnail = _thumbnail(b"backfill-jpeg", [seeded["source_object_id"]])
        first = _settle(service, attempt, effect, [thumbnail], key="attach-settle")
        replay = _settle(service, attempt, effect, [thumbnail], key="attach-settle")
        assert replay == first
        result = first["data"]["result"]["generation_thumbnail"]
        assert result["changed"] is True and result["version"] == 2
        generation = service.get_generation(seeded["generation_id"])
        assert generation["source_task_id"] == generation_before["source_task_id"]
        assert generation["metadata"]["shot_id"] == generation_before["metadata"]["shot_id"]
        assert generation["metadata"]["thumbnail"] == {
            "object_id": thumbnail["digest"],
            "source_object_id": seeded["source_object_id"],
            "recipe_version": 1,
        }
        variants = service.list_variants(seeded["generation_id"])["items"]
        assert len(variants) == 1
        association = service.managed_outputs(task["task"]["id"])[0]
        assert association["generation_id"] == seeded["generation_id"]
        assert association["role"] == "thumbnail"

        noop_effect = {**effect, "expected_version": 2}
        noop_task, noop_attempt = _task(
            service, project["id"], noop_effect, key="attach-noop-task", inputs=[seeded["source_object_id"]]
        )
        noop = _settle(service, noop_attempt, noop_effect, [thumbnail], key="attach-noop-settle")
        assert noop["data"]["result"]["generation_thumbnail"]["changed"] is False
        assert service.get_generation(seeded["generation_id"])["version"] == 2
        assert len(service.managed_outputs(noop_task["task"]["id"])) == 1
        assert len(service.list_variants(seeded["generation_id"])["items"]) == 1
    finally:
        service.close()


def test_thumbnail_attach_rejects_wrong_mime_stale_source_and_cross_project_without_partial_custody(tmp_path):
    service, project = _service(tmp_path, "attach-reject")
    try:
        seeded = _seed_generation(service, project, key="reject-seed", with_thumbnail=False)
        effect = {
            "effect_type": "generation.thumbnail.attach",
            "target_id": seeded["generation_id"],
            "expected_version": 1,
            "payload": {
                "source_object_id": seeded["source_object_id"],
                "output_name": "thumbnail.jpg",
                "output_ordinal": 0,
                "recipe_version": 1,
            },
        }
        task, attempt = _task(
            service, project["id"], effect, key="wrong-mime-task", inputs=[seeded["source_object_id"]]
        )
        bad = _thumbnail(b"not-a-jpeg-contract", [seeded["source_object_id"]], media_type="image/png")
        with pytest.raises(ValidationError, match="image/jpeg"):
            _settle(service, attempt, effect, [bad], key="wrong-mime-settle")
        assert service.store.conn.execute(
            "SELECT 1 FROM objects WHERE digest=?", (bad["digest"].removeprefix("sha256:"),)
        ).fetchone() is None
        assert service.managed_outputs(task["task"]["id"]) == []
        assert "thumbnail" not in service.get_generation(seeded["generation_id"])["metadata"]

        foreign = service.create_project(
            {"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign-project"
        )
        with pytest.raises(ConflictError, match="outside the task project"):
            _task(
                service, foreign["id"], effect, key="cross-project-task", inputs=[seeded["source_object_id"]]
            )

        wrong_source = service.ingest(
            project["id"], b"wrong-source", media_type="video/mp4", idempotency_key="wrong-source"
        )["data"]["digest"]
        stale_source_effect = {
            **effect,
            "payload": {**effect["payload"], "source_object_id": wrong_source},
        }
        with pytest.raises(ConflictError, match="not the generation primary"):
            _task(
                service, project["id"], stale_source_effect, key="stale-source-task", inputs=[wrong_source]
            )
    finally:
        service.close()


def test_thumbnail_attach_honors_fence_and_rolls_back_published_bytes_on_receipt_failure(tmp_path, monkeypatch):
    service, project = _service(tmp_path, "attach-fence")
    try:
        seeded = _seed_generation(service, project, key="fence-seed", with_thumbnail=False)
        effect = {
            "effect_type": "generation.thumbnail.attach",
            "target_id": seeded["generation_id"],
            "expected_version": 1,
            "payload": {
                "source_object_id": seeded["source_object_id"],
                "output_name": "thumbnail.jpg",
                "output_ordinal": 0,
                "recipe_version": 1,
            },
        }
        task, attempt = _task(
            service, project["id"], effect, key="fence-task", inputs=[seeded["source_object_id"]]
        )
        thumbnail = _thumbnail(b"fenced-thumbnail", [seeded["source_object_id"]])
        with pytest.raises(LeaseError):
            service.settle_attempt(
                attempt["attempt_id"],
                {
                    "lease_id": attempt["lease_id"],
                    "fence": attempt["fence"] - 1,
                    "runtime_epoch": attempt["runtime_epoch"],
                    "outputs": [thumbnail],
                    "effect": effect,
                },
                idempotency_key="stale-fence-settle",
            )
        assert "thumbnail" not in service.get_generation(seeded["generation_id"])["metadata"]
        assert service.managed_outputs(task["task"]["id"]) == []

        def fail_receipt(*_args, **_kwargs):
            raise RuntimeError("receipt failure")

        monkeypatch.setattr(service, "_command_record", fail_receipt)
        with pytest.raises(RuntimeError, match="receipt failure"):
            _settle(service, attempt, effect, [thumbnail], key="rollback-settle")
        digest = thumbnail["digest"].removeprefix("sha256:")
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
        assert not service.cas.path_for(digest).exists()
        assert "thumbnail" not in service.get_generation(seeded["generation_id"])["metadata"]
        assert service.managed_outputs(task["task"]["id"]) == []
    finally:
        service.close()


def test_publication_metadata_cannot_smuggle_runtime_thumbnail_descriptor(tmp_path):
    service, project = _service(tmp_path, "thumbnail-smuggle")
    try:
        forged = {
            "object_id": _digest("forged-thumbnail"),
            "source_object_id": _digest("forged-source"),
            "recipe_version": 1,
        }
        effect = _create_effect(project["id"], metadata={"thumbnail": forged})
        admitted = service.ingest(
            project["id"], b"input", media_type="image/png", idempotency_key="smuggle-input"
        )["data"]["digest"]
        task, attempt = _task(
            service, project["id"], effect, key="smuggle-task", inputs=[admitted]
        )
        video = _output(b"video", name="video", media_type="video/mp4", ordinal=0)
        with pytest.raises(ValidationError, match="Runtime-owned"):
            _settle(service, attempt, effect, [video], key="smuggle-settle")
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert service.managed_outputs(task["task"]["id"]) == []
    finally:
        service.close()
