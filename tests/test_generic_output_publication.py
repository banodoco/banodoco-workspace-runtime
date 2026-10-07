from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _new_service(root: Path) -> RuntimeService:
    RealmStore.initialize(root).close()
    return RuntimeService(root)


def _filmstrip_attempt(service: RuntimeService, project_id: str):
    definition = _digest(b"rendering.timeline_visualize-v1")
    service.register_capability(
        {"capability_id": "rendering.timeline_visualize", "definition_digest": definition}
    )
    service.register_executor(
        {"executor_id": "filmstrip-worker", "capabilities": ["rendering.timeline_visualize"]},
        idempotency_key="filmstrip-worker-register",
    )
    task = service.create_task(
        {
            "capability_id": "rendering.timeline_visualize",
            "capability_digest": definition,
            "project": project_id,
            "idempotency_key": f"filmstrip-task-{project_id}",
        }
    )
    return task, service.claim_next(
        {
            "executor_id": "filmstrip-worker",
            "capability_ids": ["rendering.timeline_visualize"],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=f"filmstrip-claim-{project_id}",
    )


def _descriptor(payload: bytes, *, name: str, filename: str, output_port: str, primary: bool, media_type: str):
    digest = _digest(payload)
    return {
        "name": name,
        "kind": "object",
        "filename": filename,
        "output_port": output_port,
        "digest": digest,
        "media_type": media_type,
        "size": len(payload),
        "role": "result" if primary else "auxiliary",
        "is_primary": primary,
        "durability": "durable" if primary else "temporary",
        "producer": {"capability_id": "rendering.timeline_visualize", "view": "filmstrip"},
        "provenance": {
            "render_run_id": "render-run-1",
            "timeline_id": "main",
            "video_digest": _digest(b"source-video"),
        },
    }


def _zip_payload() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps({"kind": "timeline_filmstrip"}))
        archive.writestr("filmstrip.html", "<html>filmstrip</html>")
    return stream.getvalue()


def _settle_body(attempt: dict, outputs: list[dict]) -> dict:
    return {
        "lease_id": attempt["lease_id"],
        "fence": attempt["fence"],
        "runtime_epoch": attempt["runtime_epoch"],
        "outputs": outputs,
    }


def _upload_binding(
    payload: bytes,
    *,
    attempt: dict,
    project_id: str,
    run_id: str,
    executor_id: str,
    output_key: str,
    output_port: str,
    filename: str,
    media_type: str,
) -> tuple[str, dict]:
    binding = {
        "project_id": project_id,
        "run_id": run_id,
        "task_id": attempt["task_id"],
        "attempt_id": attempt["attempt_id"],
        "executor_id": executor_id,
        "lease_id": attempt["lease_id"],
        "fence": attempt["fence"],
        "runtime_epoch": attempt["runtime_epoch"],
        "output_key": output_key,
        "output_port": output_port,
        "filename": filename,
        "digest": _digest(payload),
        "size": len(payload),
        "media_type": media_type,
    }
    key = "output-" + hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return key, binding


def test_generic_filmstrip_outputs_are_associated_by_fenced_settlement(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "filmstrip", "name": "Filmstrip"})
        _task, attempt = _filmstrip_attempt(service, project["id"])
        worker_identity = {"actor": "filmstrip-worker", "scopes": ["objects:write", "worker:execute"]}
        manifest = b'{"kind":"timeline_filmstrip_result"}'
        bundle = _zip_payload()
        outputs = [
            _descriptor(
                manifest,
                name="filmstrip_manifest",
                filename="filmstrip-manifest.json",
                output_port="filmstrip_manifest",
                primary=False,
                media_type="application/json",
            ),
            _descriptor(
                bundle,
                name="filmstrip_bundle",
                filename="filmstrip-bundle.zip",
                output_port="filmstrip_bundle",
                primary=True,
                media_type="application/zip",
            ),
        ]
        for payload, media_type, filename, output_key, output_port in (
            (manifest, "application/json", "filmstrip-manifest.json", "filmstrip_manifest", "filmstrip_manifest"),
            (bundle, "application/zip", "filmstrip-bundle.zip", "filmstrip_bundle", "filmstrip_bundle"),
        ):
            key, binding = _upload_binding(
                payload,
                attempt=attempt,
                project_id=project["id"],
                run_id=_task["run"]["id"],
                executor_id="filmstrip-worker",
                output_key=output_key,
                output_port=output_port,
                filename=filename,
                media_type=media_type,
            )
            service.ingest_object(
                payload,
                media_type=media_type,
                original_name=filename,
                idempotency_key=key,
                identity=worker_identity,
                upload_binding=binding,
            )

        service.settle_attempt(
            attempt["attempt_id"],
            _settle_body(attempt, outputs),
            idempotency_key="filmstrip-settle",
            identity=worker_identity,
        )

        assert service.task(_task["task"]["id"])["task"]["status"] == "completed"
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM project_objects WHERE project_id=?", (project["id"],)
        ).fetchone()[0] == 2
    finally:
        service.close()


@pytest.mark.parametrize("inline", [False, True], ids=["bound-uploads", "inline-staging"])
def test_distinct_outputs_with_identical_bytes_settle_in_one_attempt(tmp_path: Path, inline: bool) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "equal-content", "name": "Equal content"})
        task, attempt = _filmstrip_attempt(service, project["id"])
        identity = {"actor": "filmstrip-worker", "scopes": ["objects:write", "worker:execute"]}
        payload = b"identical-audio-bytes"
        outputs = [
            {
                **_descriptor(
                    payload,
                    name=f"audio/tile-{index}.wav",
                    filename=f"tile-{index}.wav",
                    output_port="audio",
                    primary=True,
                    media_type="audio/wav",
                ),
                "variant_key": f"tile-{index}",
            }
            for index in (1, 2)
        ]
        upload_keys = []
        for output in outputs:
            if inline:
                output["data_base64"] = base64.b64encode(payload).decode()
                continue
            key, binding = _upload_binding(
                payload,
                attempt=attempt,
                project_id=project["id"],
                run_id=task["run"]["id"],
                executor_id="filmstrip-worker",
                output_key=output["name"],
                output_port=output["output_port"],
                filename=output["filename"],
                media_type=output["media_type"],
            )
            service.ingest_object(
                payload,
                media_type=output["media_type"],
                original_name=output["filename"],
                idempotency_key=key,
                identity=identity,
                upload_binding=binding,
            )
            upload_keys.append(key)
        if not inline:
            assert upload_keys[0] != upload_keys[1]
        body = _settle_body(attempt, outputs)
        with pytest.raises(AuthorizationError):
            service.settle_attempt(
                attempt["attempt_id"], body, idempotency_key="equal-content-wrong-worker",
                identity={"actor": "other-worker", "scopes": identity["scopes"]},
            )
        with pytest.raises(LeaseError):
            service.settle_attempt(
                attempt["attempt_id"], body | {"fence": attempt["fence"] - 1},
                idempotency_key="equal-content-stale-fence", identity=identity,
            )
        settled = service.settle_attempt(
            attempt["attempt_id"], body, idempotency_key="equal-content-settle", identity=identity,
        )
        assert service.task(attempt["task_id"])["task"]["status"] == "completed"
        assert service.task(attempt["task_id"])["task"]["result"]["outputs"] == [
            {key: value for key, value in output.items() if key not in {"durability", "data_base64"}}
            for output in outputs
        ]
        associations = service.managed_outputs(attempt["task_id"])
        assert len(associations) == 2
        assert len({item["association_id"] for item in associations}) == 2
        for output in outputs:
            association = next(item for item in associations if item["variant_key"] == output["variant_key"])
            assert service.managed_output(association["association_id"]) == association
            for field in ("filename", "output_port", "variant_key", "digest", "size", "media_type"):
                assert association[field] == output[field]
            assert association["task_id"] == attempt["task_id"]
            assert association["attempt_id"] == attempt["attempt_id"]
            assert association["run_id"] == task["run"]["id"]
            assert association["project_id"] == project["id"]
            assert association["provenance"] == output["provenance"] | {
                "task_id": attempt["task_id"], "attempt_id": attempt["attempt_id"],
                "capability_id": "rendering.timeline_visualize", "executor_id": "filmstrip-worker",
                "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"],
            }
        digest = hashlib.sha256(payload).hexdigest()
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects WHERE digest=?", (digest,)).fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM project_objects WHERE digest=?", (digest,)).fetchone()[0] == 1
        assert service.cas.path_for(digest).read_bytes() == payload
        assert [path for path in service.cas.root.rglob("*") if path.is_file()] == [service.cas.path_for(digest)]
        assert service.settle_attempt(
            attempt["attempt_id"], body, idempotency_key="equal-content-settle", identity=identity,
        ) == settled
        assert service.managed_outputs(attempt["task_id"]) == associations
        with pytest.raises(ConflictError):
            service.settle_attempt(
                attempt["attempt_id"], body | {"outputs": outputs[:1]},
                idempotency_key="equal-content-settle", identity=identity,
            )
        assert service.managed_outputs(attempt["task_id"]) == associations
    finally:
        service.close()


@pytest.mark.parametrize("duplicate_association", [False, True], ids=["missing-second-receipt", "duplicate-association"])
def test_equal_content_does_not_bypass_output_association_protections(tmp_path: Path, duplicate_association: bool) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "protected", "name": "Protected"})
        task, attempt = _filmstrip_attempt(service, project["id"])
        identity = {"actor": "filmstrip-worker", "scopes": ["objects:write", "worker:execute"]}
        payload = b"equal-content-with-one-receipt"
        first = _descriptor(payload, name="first", filename="first.wav", output_port="audio", primary=True, media_type="audio/wav")
        second = _descriptor(payload, name="second", filename="second.wav", output_port="audio", primary=True, media_type="audio/wav")
        if not duplicate_association:
            second["variant_key"] = "second"
        key, binding = _upload_binding(
            payload, attempt=attempt, project_id=project["id"], run_id=task["run"]["id"],
            executor_id="filmstrip-worker", output_key=first["name"], output_port=first["output_port"],
            filename=first["filename"], media_type=first["media_type"],
        )
        service.ingest_object(
            payload, media_type=first["media_type"], original_name=first["filename"],
            idempotency_key=key, identity=identity, upload_binding=binding,
        )
        expected_error = ValidationError if duplicate_association else ConflictError
        expected_message = "duplicate associations" if duplicate_association else "outside the task project"
        with pytest.raises(expected_error, match=expected_message):
            service.settle_attempt(
                attempt["attempt_id"], _settle_body(attempt, [first, second]),
                idempotency_key="protected-settle", identity=identity,
            )
        assert service.task(attempt["task_id"])["task"]["status"] == "running"
        assert service.managed_outputs(attempt["task_id"]) == []
        assert service.store.conn.execute("SELECT COUNT(*) FROM project_objects WHERE project_id=?", (project["id"],)).fetchone()[0] == 0
        assert service.cas.path_for(hashlib.sha256(payload).hexdigest()).read_bytes() == payload
    finally:
        service.close()


def test_inline_equal_content_rejects_conflicting_object_metadata(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "metadata", "name": "Metadata"})
        _task, attempt = _filmstrip_attempt(service, project["id"])
        payload = b"same-inline-content"
        outputs = [
            {
                **_descriptor(payload, name=f"output-{index}", filename=f"output-{index}.bin",
                              output_port=f"output-{index}", primary=True, media_type=media_type),
                "data_base64": base64.b64encode(payload).decode(),
            }
            for index, media_type in enumerate(("audio/wav", "application/octet-stream"))
        ]
        with pytest.raises(ConflictError, match="output metadata does not match existing object"):
            service.settle_attempt(
                attempt["attempt_id"], _settle_body(attempt, outputs), idempotency_key="metadata-settle",
            )
        assert service.task(attempt["task_id"])["task"]["status"] == "running"
        assert service.managed_outputs(attempt["task_id"]) == []
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
        assert not service.cas.path_for(hashlib.sha256(payload).hexdigest()).exists()
    finally:
        service.close()


@pytest.mark.parametrize("kind", ["document", "value"])
def test_non_object_outputs_keep_existing_digest_uniqueness(tmp_path: Path, kind: str) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "non-object", "name": "Non object"})
        _task, attempt = _filmstrip_attempt(service, project["id"])
        outputs = [
            {
                **_descriptor(payload, name="output", filename="output.bin", output_port="output",
                              primary=True, media_type="application/octet-stream"),
                "kind": kind, "data_base64": base64.b64encode(payload).decode(),
            }
            for payload in (b"first-content", b"second-content")
        ]
        with pytest.raises(ValidationError, match="duplicate digests"):
            service.settle_attempt(
                attempt["attempt_id"], _settle_body(attempt, [outputs[0], outputs[0] | {"name": "second"}]),
                idempotency_key="non-object-duplicate-settle",
            )
        service.settle_attempt(
            attempt["attempt_id"], _settle_body(attempt, outputs), idempotency_key="non-object-settle",
        )
        assert service.task(attempt["task_id"])["task"]["status"] == "completed"
        assert len(service.task(attempt["task_id"])["task"]["result"]["outputs"]) == 2
        assert service.managed_outputs(attempt["task_id"]) == []
    finally:
        service.close()


def test_repeated_identical_output_bytes_bind_and_settle_for_two_live_attempts(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "repeated", "name": "Repeated"})
        definition = _digest(b"rendering.timeline_visualize-v1")
        service.register_capability(
            {"capability_id": "rendering.timeline_visualize", "definition_digest": definition}
        )
        identity = {"actor": "parallel-worker", "scopes": ["objects:write", "worker:execute"]}
        service.register_executor(
            {
                "executor_id": "parallel-worker",
                "capabilities": ["rendering.timeline_visualize"],
                "max_concurrency": 2,
            },
            idempotency_key="parallel-worker-register",
        )
        tasks = [
            service.create_task(
                {
                    "capability_id": "rendering.timeline_visualize",
                    "capability_digest": definition,
                    "project": project["id"],
                    "idempotency_key": f"repeated-task-{index}",
                }
            )
            for index in (1, 2)
        ]
        attempts = [
            service.claim_next(
                {
                    "executor_id": "parallel-worker",
                    "capability_ids": ["rendering.timeline_visualize"],
                    "runtime_epoch": service.health()["runtime_epoch"],
                },
                idempotency_key=f"repeated-claim-{index}",
                identity=identity,
            )
            for index in (1, 2)
        ]
        payload = b"the-same-successful-output"
        output = _descriptor(
            payload,
            name="filmstrip_bundle",
            filename="filmstrip-bundle.zip",
            output_port="filmstrip_bundle",
            primary=True,
            media_type="application/zip",
        )
        upload_keys = []
        for attempt in attempts:
            key, binding = _upload_binding(
                payload,
                attempt=attempt,
                project_id=project["id"],
                run_id=service.task(attempt["task_id"])["run"]["id"],
                executor_id="parallel-worker",
                output_key="filmstrip_bundle",
                output_port="filmstrip_bundle",
                filename="filmstrip-bundle.zip",
                media_type="application/zip",
            )
            service.ingest_object(
                payload,
                media_type="application/zip",
                original_name="filmstrip-bundle.zip",
                idempotency_key=key,
                identity=identity,
                upload_binding=binding,
            )
            upload_keys.append(key)
        assert upload_keys[0] != upload_keys[1]
        for index, attempt in enumerate(attempts, start=1):
            service.settle_attempt(
                attempt["attempt_id"],
                _settle_body(attempt, [output]),
                idempotency_key=f"repeated-settle-{index}",
                identity=identity,
            )

        assert all(
            service.task(attempt["task_id"])["task"]["status"] == "completed"
            for attempt in attempts
        )
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM objects WHERE digest=?",
            (hashlib.sha256(payload).hexdigest(),),
        ).fetchone()[0] == 1
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM managed_output_associations WHERE object_digest=?",
            (hashlib.sha256(payload).hexdigest(),),
        ).fetchone()[0] == 2
    finally:
        service.close()


def test_recognized_output_receipt_is_bound_to_attempt_and_worker(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "bound", "name": "Bound"})
        definition = _digest(b"rendering.timeline_visualize-v1")
        service.register_capability(
            {"capability_id": "rendering.timeline_visualize", "definition_digest": definition}
        )
        workers = {
            "worker-a": {"actor": "worker-a", "scopes": ["objects:write", "worker:execute"]},
            "worker-b": {"actor": "worker-b", "scopes": ["objects:write", "worker:execute"]},
        }
        for executor_id in workers:
            service.register_executor(
                {
                    "executor_id": executor_id,
                    "capabilities": ["rendering.timeline_visualize"],
                    "max_concurrency": 2 if executor_id == "worker-a" else 1,
                },
                idempotency_key=f"{executor_id}-register",
            )
        tasks = {
            executor_id: service.create_task(
                {
                    "capability_id": "rendering.timeline_visualize",
                    "capability_digest": definition,
                    "project": project["id"],
                    "idempotency_key": f"bound-task-{executor_id}",
                }
            )
            for executor_id in workers
        }
        tasks["worker-a-second"] = service.create_task(
            {
                "capability_id": "rendering.timeline_visualize",
                "capability_digest": definition,
                "project": project["id"],
                "idempotency_key": "bound-task-worker-a-second",
            }
        )
        attempts = {}
        for executor_id in workers:
            attempts[executor_id] = service.claim_next(
                {
                    "executor_id": executor_id,
                    "capability_ids": ["rendering.timeline_visualize"],
                    "runtime_epoch": service.health()["runtime_epoch"],
                },
                idempotency_key=f"{executor_id}-claim",
                identity=workers[executor_id],
            )

        payload = b"attempt-a-filmstrip-bundle"
        filename = "filmstrip-bundle.zip"
        key, binding = _upload_binding(
            payload,
            attempt=attempts["worker-a"],
            project_id=project["id"],
            run_id=service.task(attempts["worker-a"]["task_id"])["run"]["id"],
            executor_id="worker-a",
            output_key="filmstrip_bundle",
            output_port="filmstrip_bundle",
            filename=filename,
            media_type="application/zip",
        )
        service.ingest_object(
            payload,
            media_type="application/zip",
            original_name=filename,
            idempotency_key=key,
            identity=workers["worker-a"],
            upload_binding=binding,
        )
        attempts["worker-a-second"] = service.claim_next(
            {
                "executor_id": "worker-a",
                "capability_ids": ["rendering.timeline_visualize"],
                "runtime_epoch": service.health()["runtime_epoch"],
            },
            idempotency_key="worker-a-second-claim",
            identity=workers["worker-a"],
        )
        output = _descriptor(
            payload,
            name="filmstrip_bundle",
            filename=filename,
            output_port="filmstrip_bundle",
            primary=True,
            media_type="application/zip",
        )

        with pytest.raises(ConflictError, match="outside the task project"):
            service.settle_attempt(
                attempts["worker-b"]["attempt_id"],
                _settle_body(attempts["worker-b"], [output]),
                idempotency_key="wrong-worker-settle",
                identity=workers["worker-b"],
            )
        assert service.task(attempts["worker-b"]["task_id"])["task"]["status"] == "running"

        with pytest.raises(ConflictError, match="outside the task project"):
            service.settle_attempt(
                attempts["worker-a-second"]["attempt_id"],
                _settle_body(attempts["worker-a-second"], [output]),
                idempotency_key="wrong-attempt-settle",
                identity=workers["worker-a"],
            )
        assert service.task(attempts["worker-a-second"]["task_id"])["task"]["status"] == "running"

        service.settle_attempt(
            attempts["worker-a"]["attempt_id"],
            _settle_body(attempts["worker-a"], [output]),
            idempotency_key="right-worker-settle",
            identity=workers["worker-a"],
        )
        assert service.task(attempts["worker-a"]["task_id"])["task"]["status"] == "completed"
    finally:
        service.close()


def test_settlement_rejects_foreign_and_unrecognized_ownerless_objects(tmp_path: Path) -> None:
    service = _new_service(tmp_path / "realm")
    try:
        target = service.create_project({"slug": "target", "name": "Target"})
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"})

        foreign_payload = b"foreign-filmstrip-bundle"
        foreign_object = service.ingest(
            foreign["id"],
            foreign_payload,
            media_type="application/zip",
            idempotency_key="foreign-ingest",
        )["data"]
        # Even an output-shaped unscoped receipt cannot adopt an object that
        # is already owned by another project.
        service.ingest_object(
            foreign_payload,
            media_type="application/zip",
            idempotency_key="output-" + hashlib.sha256(foreign_payload).hexdigest(),
        )
        _task, attempt = _filmstrip_attempt(service, target["id"])
        foreign_output = _descriptor(
            foreign_payload,
            name="filmstrip_bundle",
            filename="filmstrip-bundle.zip",
            output_port="filmstrip_bundle",
            primary=True,
            media_type="application/zip",
        )
        assert foreign_output["digest"] == foreign_object["digest"]
        with pytest.raises(ConflictError, match="outside the task project"):
            service.settle_attempt(
                attempt["attempt_id"],
                _settle_body(attempt, [foreign_output]),
                idempotency_key="foreign-filmstrip-settle",
            )
        assert service.store.conn.execute(
            "SELECT 1 FROM project_objects WHERE project_id=? AND digest=?",
            (target["id"], foreign_object["digest"].removeprefix("sha256:")),
        ).fetchone() is None

        ownerless_payload = b"ownerless-cas-object"
        ownerless_object = service.ingest_object(
            ownerless_payload,
            media_type="application/zip",
            idempotency_key="not-an-output-upload",
        )["data"]
        ownerless_output = _descriptor(
            ownerless_payload,
            name="filmstrip_bundle",
            filename="filmstrip-bundle.zip",
            output_port="filmstrip_bundle",
            primary=True,
            media_type="application/zip",
        )
        assert ownerless_output["digest"] == ownerless_object["digest"]
        with pytest.raises(ConflictError, match="outside the task project"):
            service.settle_attempt(
                attempt["attempt_id"],
                _settle_body(attempt, [ownerless_output]),
                idempotency_key="unrecognized-filmstrip-settle",
            )
    finally:
        service.close()
