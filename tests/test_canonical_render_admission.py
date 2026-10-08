from __future__ import annotations

import copy
import hashlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json


def _digest(data):
    return "sha256:" + hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


@pytest.fixture
def canonical_scene(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project({"slug": "scene-render", "name": "Scene"}, idempotency_key="project")
        service.create_timeline(project["id"], "main", idempotency_key="timeline")
        service.register_capability({"capability_id": "rendering.render", "definition_digest": _digest("rendering.render")})
        service.register_executor({"executor_id": "worker", "capabilities": ["rendering.render"]})
        html = "<!doctype html><html><body>immutable scene</body></html>"
        entry = service.ingest(project["id"], html.encode(), media_type="text/html", original_name="scene.html", idempotency_key="entry")["data"]
        audio = service.ingest(project["id"], b"ordinary-audio", media_type="audio/wav", idempotency_key="audio")["data"]
        package_body = {
            "manifest": {"formatVersion": 1, "entry": "scene.html", "duration": 100, "authoredFps": 30},
            "entry": {"object_id": entry["object_id"], "digest": entry["digest"], "media_type": "text/html", "size": len(html.encode()), "filename": "scene.html"},
            "assets": [],
        }
        fixture = {"service": service, "project": project["id"], "html": html, "entry": entry, "audio": audio, "package_body": package_body}
        _set_package(fixture, package_body)
        yield fixture
    finally:
        service.close()


def _set_package(fixture, body):
    encoded = canonical_json(body)
    package = fixture["service"].ingest(fixture["project"], encoded.encode(), media_type="application/json", original_name="scene.json", idempotency_key="package-" + _digest(encoded).removeprefix("sha256:"))["data"]
    fixture["package"] = package
    fixture["envelope"] = {"revision": package["digest"], "source": {"objectId": package["object_id"], "revision": package["digest"]}, "packageBody": encoded, "html": fixture["html"]}


def _publication(fixture, *, revision="parent-1", expected_head=None):
    clips = [
        {"id": "scene-a", "clipType": "com.reigh.astrid.liveScene", "at": 0, "from": 55, "to": 65, "speed": 2, "track": "visual", "app": {"liveScene": copy.deepcopy(fixture["envelope"]), "opaque": {"keep": True}}},
        {"id": "scene-b", "clipType": "com.reigh.astrid.liveScene", "at": 5, "from": 65, "to": 75, "speed": 1, "track": "visual", "app": {"liveScene": copy.deepcopy(fixture["envelope"])}},
        {"id": "music", "clipType": "media", "at": 0, "from": 0, "to": 15, "track": "audio", "asset": "music"},
    ]
    return {
        "project_id": fixture["project"], "timeline_id": "main", "expected_head": expected_head, "parent_revision_id": revision,
        "dependency_manifest": {"media": [{"media_id": fixture["audio"]["object_id"], "content_digest": fixture["audio"]["digest"]}]},
        "parent_composition": {
            "config": {"tracks": [{"id": "visual", "kind": "visual"}, {"id": "audio", "kind": "audio"}], "effects": [], "app": {"sentinel": "canonical"}},
            "registry": {"assets": {"music": {"media_id": "music-media", "content_sha256": fixture["audio"]["object_id"], "type": "audio"}}},
            "clips": clips, "occurrences": [],
        },
    }


def _publish(fixture, **kwargs):
    publication = _publication(fixture, **kwargs)
    return fixture["service"].publish_parent_composition(fixture["project"], "main", publication, idempotency_key="publish-" + publication["parent_revision_id"])


def _request(fixture, *, head="parent-1", key="render"):
    return {
        "project": fixture["project"], "capability_id": "rendering.render", "capability_digest": _digest("rendering.render"), "input_object_ids": [], "idempotency_key": key,
        "spec": {"family": "render", "params": {"timeline_ref": "main", "expected_version": 1, "canonical_project_id": fixture["project"], "canonical_parent_document_id": "main", "canonical_head_revision_id": head, "canonical_occurrence_ids": [], "selector": "rendering.remotion"}},
    }


def _assert_rejected(fixture, body, errors=(ConflictError, ValidationError, NotFoundError), match=None):
    service = fixture["service"]
    before = {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("tasks", "runs")}
    with pytest.raises(errors, match=match):
        service.create_task(body)
    assert {table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in before} == before


def test_canonical_parent_freezes_both_placements_ordinary_audio_and_exact_objects(canonical_scene):
    f = canonical_scene
    publication = _publish(f)
    admitted = f["service"].create_task(_request(f))
    spec = admitted["task"]["spec"]
    snapshot = spec["spec"]["timeline_snapshot"]
    expected_config = copy.deepcopy(publication["data"]["payload"]["config"])
    expected_config["clips"] = publication["data"]["payload"]["clips"]
    assert snapshot == {"config": expected_config, "registry": publication["data"]["payload"]["registry"]}
    assert [clip["id"] for clip in snapshot["config"]["clips"]] == ["scene-a", "scene-b", "music"]
    assert len(spec["input_object_ids"]) == 3
    assert set(spec["input_object_ids"]) == {f["package"]["object_id"], f["entry"]["object_id"], f["audio"]["object_id"]}
    authority = spec["spec"]["inputs"]["timeline_authority"]
    assert authority["parent_revision_id"] == "parent-1"
    assert authority["parent_content_digest"] == publication["data"]["content_digest"]
    assert authority["snapshot_digest"] == _digest(canonical_json(snapshot))
    assert authority["input_object_ids"] == spec["input_object_ids"]
    assert authority["dependency_digests"] == [{"dependency_kind": "media", "dependency_id": f["audio"]["object_id"], "content_digest": f["audio"]["digest"]}]
    # An exact assertion is accepted and idempotent; it cannot create extra authority.
    request = _request(f, key="exact-inputs")
    request["input_object_ids"] = spec["input_object_ids"]
    assert f["service"].create_task(request) == f["service"].create_task(request)


def test_canonical_stale_head_rejected_when_legacy_version_is_unchanged(canonical_scene):
    f = canonical_scene
    _publish(f)
    version_before = f["service"].store.conn.execute("SELECT version FROM timelines WHERE id='main'").fetchone()[0]
    _publish(f, revision="parent-2", expected_head="parent-1")
    assert f["service"].store.conn.execute("SELECT version FROM timelines WHERE id='main'").fetchone()[0] == version_before == 1
    _assert_rejected(f, _request(f), ConflictError, "head")


@pytest.mark.parametrize("field,value", [
    ("canonical_project_id", "other-project"),
    ("canonical_parent_document_id", "other-timeline"),
    ("canonical_occurrence_ids", ["injected-occurrence"]),
])
def test_canonical_scope_assertions_are_checked(canonical_scene, field, value):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    request["spec"]["params"][field] = value
    _assert_rejected(f, request)


def test_canonical_timeline_reference_cannot_cross_projects(canonical_scene):
    f = canonical_scene
    _publish(f)
    other = f["service"].create_project({"slug": "other", "name": "Other"}, idempotency_key="other")
    request = _request(f)
    request["project"] = other["id"]
    request["spec"]["params"]["canonical_project_id"] = other["id"]
    _assert_rejected(f, request)


@pytest.mark.parametrize("where,field,value", [
    ("spec", "timeline_snapshot", {"config": {"clips": []}, "registry": {}}),
    ("inputs", "timeline_snapshot", {"config": {}, "registry": {}}),
    ("inputs", "timeline_authority", {"project_id": "injected"}),
    ("inputs", "materialized_objects", {"injected": "/caller/file"}),
    ("inputs", "materialized_root", "/caller/root"),
    ("inputs", "timeline", "/caller/timeline.json"),
    ("inputs", "assets_registry", "/caller/assets.json"),
])
def test_canonical_snapshot_authority_and_materialization_injection_rejected(canonical_scene, where, field, value):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    target = request["spec"] if where == "spec" else request["spec"].setdefault("inputs", {})
    target[field] = value
    _assert_rejected(f, request, ValidationError)


@pytest.mark.parametrize("ids", ["extra", "partial", "reversed"])
def test_canonical_nonempty_input_ids_are_only_exact_assertions(canonical_scene, ids):
    f = canonical_scene
    _publish(f)
    accepted = f["service"].create_task(_request(f, key="reference"))
    derived = accepted["task"]["spec"]["input_object_ids"]
    extra = f["service"].ingest(f["project"], b"unreachable-object", idempotency_key="extra")["data"]["object_id"]
    request = _request(f, key="injected")
    request["input_object_ids"] = {"extra": derived + [extra], "partial": derived[:-1], "reversed": list(reversed(derived))}[ids]
    _assert_rejected(f, request, ConflictError, "input_object_ids")


@pytest.mark.parametrize("object_name", ["package", "entry"])
@pytest.mark.parametrize("damage", ["unowned", "missing", "digest", "size", "media_type"])
def test_canonical_scene_objects_require_project_association_and_verified_bytes(canonical_scene, object_name, damage):
    f = canonical_scene
    _publish(f)
    digest = f[object_name]["object_id"].removeprefix("sha256:")
    conn = f["service"].store.conn
    path = f["service"].cas.path_for(digest)
    if damage == "unowned":
        other = f["service"].create_project({"slug": "other", "name": "Other"}, idempotency_key="other")
        f["service"].ingest(other["id"], path.read_bytes(), idempotency_key="other-object")
        conn.execute("DELETE FROM project_objects WHERE project_id=? AND digest=?", (f["project"], digest))
    elif damage == "missing":
        path.unlink()
    elif damage == "digest":
        data = path.read_bytes()
        path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif damage == "size":
        conn.execute("UPDATE objects SET size=size+1 WHERE digest=?", (digest,))
    elif damage == "media_type":
        conn.execute("UPDATE objects SET media_type='application/octet-stream' WHERE digest=?", (digest,))
    _assert_rejected(f, _request(f))


@pytest.mark.parametrize("mutation", ["assets_missing", "assets_nonempty", "format", "entry_path", "duration", "fps", "entry_digest", "entry_size", "entry_id", "entry_filename"])
def test_canonical_scene_package_contract_rejected(canonical_scene, mutation):
    f = canonical_scene
    body = copy.deepcopy(f["package_body"])
    if mutation == "assets_missing":
        body.pop("assets")
    elif mutation == "assets_nonempty":
        body["assets"] = [body["entry"]]
    elif mutation == "format":
        body["manifest"]["formatVersion"] = 2
    elif mutation == "entry_path":
        body["manifest"]["entry"] = "../escape.html"
    elif mutation == "duration":
        body["manifest"]["duration"] = 0
    elif mutation == "fps":
        body["manifest"]["authoredFps"] = False
    elif mutation == "entry_digest":
        body["entry"]["digest"] = _digest("other")
    elif mutation == "entry_size":
        body["entry"]["size"] += 1
    elif mutation == "entry_id":
        body["entry"]["object_id"] = f["audio"]["object_id"]
    elif mutation == "entry_filename":
        body["entry"]["filename"] = []
    _set_package(f, body)
    _publish(f)
    _assert_rejected(f, _request(f))


@pytest.mark.parametrize("field,value", [
    ("packageBody", "{}"), ("html", "<html>caller replacement</html>"),
    ("revision", _digest("different-revision")),
    ("source", {"objectId": _digest("unreachable"), "revision": _digest("unreachable")}),
])
def test_canonical_scene_envelope_must_match_immutable_objects(canonical_scene, field, value):
    f = canonical_scene
    f["envelope"][field] = value
    _publish(f)
    _assert_rejected(f, _request(f))


def test_canonical_conflicting_populated_clip_lists_fail_closed(canonical_scene):
    f = canonical_scene
    publication = _publication(f)
    publication["parent_composition"]["config"]["clips"] = [{"id": "different", "clipType": "text", "at": 0, "hold": 1}]
    with pytest.raises(ConflictError, match="clips"):
        f["service"].publish_parent_composition(f["project"], "main", publication, idempotency_key="conflicting-clips")
    assert f["service"].store.conn.execute("SELECT COUNT(*) FROM parent_composition_revisions").fetchone()[0] == 0


def test_canonical_admission_holds_sqlite_write_fence_during_snapshot_freeze(canonical_scene, monkeypatch):
    f = canonical_scene
    _publish(f)
    store = f["service"].store
    original = store._freeze_managed_render_inputs
    resolved = threading.Event()
    release = threading.Event()
    publishing = threading.Event()

    def pause_after_freeze(*args):
        result = original(*args)
        resolved.set()
        assert release.wait(5), "test did not release admission"
        return result

    monkeypatch.setattr(store, "_freeze_managed_render_inputs", pause_after_freeze)
    # Reuse the admitted service state with a separate DB connection/mutex.
    # No new Runtime session or owner is created by this competing writer.
    publisher = copy.copy(f["service"])
    publisher.store = copy.copy(store)
    publisher.store._mutex = threading.RLock()
    publisher.store.conn = sqlite3.connect(store.db_path, timeout=5, isolation_level=None, check_same_thread=False)
    publisher.store.conn.row_factory = sqlite3.Row
    publisher.store.conn.execute("PRAGMA foreign_keys=ON")
    publisher.store.conn.set_trace_callback(lambda sql: publishing.set() if sql == "BEGIN IMMEDIATE" else None)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            future = pool.submit(f["service"].create_task, _request(f))
            try:
                assert resolved.wait(5), "admission did not freeze canonical parent"
                writer = sqlite3.connect(store.db_path, timeout=0, isolation_level=None)
                try:
                    # A different DB writer cannot publish a new head during freeze.
                    # This checks SQLite fencing independently of the local mutex.
                    with pytest.raises(sqlite3.OperationalError, match="locked"):
                        writer.execute("BEGIN IMMEDIATE")
                finally:
                    writer.close()
                later = {**f, "service": publisher}
                published = pool.submit(_publish, later, revision="parent-2", expected_head="parent-1")
                assert publishing.wait(5), "concurrent publication did not reach its DB fence"
                assert not published.done(), "publication crossed the active admission fence"
            finally:
                release.set()
            admitted = future.result(timeout=5)
            assert published.result(timeout=5)["data"]["new_head"] == "parent-2"
    finally:
        publisher.store.conn.close()
    monkeypatch.setattr(store, "_freeze_managed_render_inputs", original)
    assert admitted["task"]["spec"]["spec"]["inputs"]["timeline_authority"]["parent_revision_id"] == "parent-1"
    _assert_rejected(f, _request(f, key="stale-after-publication"), ConflictError, "head")


def test_canonical_claim_and_retry_keep_snapshot_and_objects_after_later_publication(canonical_scene):
    f = canonical_scene
    service = f["service"]
    _publish(f)
    admitted = service.create_task(_request(f))
    immutable_spec = copy.deepcopy(admitted["task"]["spec"])
    # Later publication points to different real package and entry objects.
    new_html = "<html><body>later scene</body></html>"
    new_entry = service.ingest(f["project"], new_html.encode(), media_type="text/html", idempotency_key="later-entry")["data"]
    later = copy.copy(f)
    later["html"] = new_html
    later["entry"] = new_entry
    body = copy.deepcopy(f["package_body"])
    body["entry"].update(object_id=new_entry["object_id"], digest=new_entry["digest"], size=len(new_html.encode()))
    _set_package(later, body)
    _publish(later, revision="parent-2", expected_head="parent-1")
    epoch = service.health()["runtime_epoch"]
    claim_body = {"executor_id": "worker", "capability_ids": ["rendering.render"], "runtime_epoch": epoch}
    first = service.claim_next(claim_body)
    assert first["task_id"] == admitted["task"]["id"]
    assert first["spec"] == immutable_spec
    assert first["input_object_ids"] == immutable_spec["input_object_ids"]
    assert later["package"]["object_id"] not in first["input_object_ids"]
    service.fail_attempt(first["attempt_id"], {"lease_id": first["lease_id"], "fence": first["fence"], "runtime_epoch": epoch, "error": {"code": "test_retry"}}, idempotency_key="fail")
    service.retry_task(first["task_id"], idempotency_key="retry")
    retried = service.claim_next(claim_body)
    assert retried["task_id"] == first["task_id"]
    assert retried["attempt_id"] != first["attempt_id"]
    assert retried["spec"] == immutable_spec
    assert retried["input_object_ids"] == first["input_object_ids"]
