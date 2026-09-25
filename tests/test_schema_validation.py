from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).parents[1]


def validate(schema_name: str, fixture_name: str, *, definition: str | None = None) -> None:
    schema = json.loads((ROOT / "contract/schemas" / schema_name).read_text())
    if definition:
        schema = {"$schema": schema["$schema"], "definitions": schema["definitions"], **schema["definitions"][definition]}
    instance = json.loads((ROOT / "conformance/fixtures" / fixture_name).read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(instance), key=lambda error: list(error.path))
    assert not errors, "\n".join(error.message for error in errors)


def test_core_fixtures_validate_against_closed_schemas() -> None:
    validate("handshake-response.json", "handshake.json")
    validate("project.json", "project.json")
    validate("managed-object.json", "managed-object.json")
    validate("task.json", "task.json")
    validate("event.json", "event.json")
    validate("worker.json", "settlement.json", definition="Settlement")


def test_health_schema_has_exact_closed_runtime_identity_contract() -> None:
    schema = json.loads((ROOT / "contract/schemas/health.json").read_text())
    fields = ["status", "protocol", "schema_digest", "runtime_epoch", "runtime_session_id", "runtime_instance_id"]
    assert schema["additionalProperties"] is False
    assert list(schema["required"]) == fields
    assert list(schema["properties"]) == fields

    value = {
        "status": "ok",
        "protocol": "workspace.v1",
        "schema_digest": "sha256:" + "a" * 64,
        "runtime_epoch": 1,
        "runtime_session_id": "runtime-session-1",
        "runtime_instance_id": "runtime-instance-1",
    }
    assert not list(Draft202012Validator(schema).iter_errors(value))
    assert list(Draft202012Validator(schema).iter_errors({**value, "extra": True}))
    assert list(Draft202012Validator(schema).iter_errors({key: item for key, item in value.items() if key != "runtime_instance_id"}))


def test_closed_schemas_reject_unknown_fields() -> None:
    schema = json.loads((ROOT / "contract/schemas/project.json").read_text())
    instance = json.loads((ROOT / "conformance/fixtures/project.json").read_text())
    instance["product_private_field"] = True
    assert list(Draft202012Validator(schema).iter_errors(instance))


def test_settlement_schema_allows_bounded_inline_output_bytes() -> None:
    instance = json.loads((ROOT / "conformance/fixtures/settlement.json").read_text())
    payload = b"abcd"
    output = instance["outputs"][0]
    output["digest"] = "sha256:" + hashlib.sha256(payload).hexdigest()
    output["data_base64"] = base64.b64encode(payload).decode("ascii")
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    settlement = {
        "$schema": schema["$schema"],
        "definitions": schema["definitions"],
        **schema["definitions"]["Settlement"],
    }
    errors = list(Draft202012Validator(settlement).iter_errors(instance))
    assert not errors, "\n".join(error.message for error in errors)


def test_worker_schema_declares_continuation_waits_and_output_primary_contract() -> None:
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    claim_waiting = schema["definitions"]["ClaimWaiting"]["properties"]["waiting_reason"]
    assert {"waiting_for_dependencies", "dependency_failed", "dependency_cancelled"} <= set(claim_waiting["enum"])
    output = schema["definitions"]["Output"]["properties"]
    assert output["is_primary"] == {"type": "boolean"}
    assert output["role"]["maxLength"] == 255


def test_worker_schema_declares_thumbnail_auxiliary_and_attach_effect() -> None:
    schema = json.loads((ROOT / "contract/schemas/worker.json").read_text())
    output_schema = {
        "$schema": schema["$schema"],
        "definitions": schema["definitions"],
        **schema["definitions"]["Output"],
    }
    source = "sha256:" + "a" * 64
    thumbnail = {
        "name": "thumbnail.jpg",
        "kind": "object",
        "digest": "sha256:" + "b" * 64,
        "media_type": "image/jpeg",
        "size": 4,
        "output_port": "thumbnail",
        "role": "thumbnail",
        "durability": "durable",
        "provenance": {
            "thumbnail": {"source_object_ids": [source], "recipe_version": 1}
        },
    }
    assert not list(Draft202012Validator(output_schema).iter_errors(thumbnail))
    wrong_mime = {**thumbnail, "media_type": "image/png"}
    assert list(Draft202012Validator(output_schema).iter_errors(wrong_mime))
    forged_primary = {**thumbnail, "is_primary": False}
    assert list(Draft202012Validator(output_schema).iter_errors(forged_primary))

    effect_schema = {
        "$schema": schema["$schema"],
        "definitions": schema["definitions"],
        **schema["definitions"]["Effect"],
    }
    effect = {
        "effect_type": "generation.thumbnail.attach",
        "target_id": "generation-1",
        "expected_version": 1,
        "payload": {
            "source_object_id": source,
            "output_name": "thumbnail.jpg",
            "output_ordinal": 0,
            "recipe_version": 1,
        },
    }
    assert not list(Draft202012Validator(effect_schema).iter_errors(effect))


def test_generation_schema_reserves_direct_thumbnail_descriptor() -> None:
    schema = json.loads((ROOT / "contract/schemas/generation.json").read_text())
    generation = {
        "generation_id": "generation-1",
        "project_id": "project-1",
        "source_task_id": "task-1",
        "type": "video",
        "status": "completed",
        "metadata": {
            "shot_id": "shot-1",
            "thumbnail": {
                "object_id": "sha256:" + "b" * 64,
                "source_object_id": "sha256:" + "a" * 64,
                "recipe_version": 1,
            },
        },
        "version": 1,
        "created_at": "2026-09-22T00:00:00Z",
        "updated_at": "2026-09-22T00:00:00Z",
    }
    assert not list(Draft202012Validator(schema).iter_errors(generation))
    generation["metadata"]["thumbnail"]["recipe_version"] = 2
    assert list(Draft202012Validator(schema).iter_errors(generation))
