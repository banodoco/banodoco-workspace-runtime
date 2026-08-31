from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime_protocol.errors import InvalidRequestError
from runtime_protocol.service import RuntimeService
from banodoco_workspace_client.generated import ApiError, WorkspaceClient


def test_projects_and_events_are_complete_keyset_pages(tmp_path: Path) -> None:
    service = RuntimeService(tmp_path)
    for index in range(5):
        service.create_project({"name": f"Project {index}", "slug": f"project-{index}"}, idempotency_key=f"project-{index}")

    seen = []
    cursor = None
    while True:
        page = service.list_projects(cursor=cursor, limit=2)
        seen.extend(item["project_id"] for item in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert len(seen) == 5 and len(set(seen)) == 5

    task = service.create_task({"capability_id": "render.basic", "project": seen[0], "spec": {}})
    run_id = task["run"]["id"]
    with service.store._transaction():
        for index in range(4):
            service.store._append_event(run_id, task["task"]["id"], f"event.{index}", {})
    first = service.events_page(limit=2)
    second = service.events_page(cursor=first["next_cursor"], limit=2)
    assert len(first["items"]) == 2
    assert len(second["items"]) == 2 and second["next_cursor"] is not None
    assert first["items"][-1]["event_id"] != second["items"][0]["event_id"]
    third = service.events_page(cursor=second["next_cursor"], limit=2)
    assert len(third["items"]) == 1 and third["next_cursor"] is None
    service.close()


def test_cursor_scope_and_shape_are_typed_400_errors(tmp_path: Path) -> None:
    service = RuntimeService(tmp_path)
    service.create_project({"name": "Project", "slug": "project"}, idempotency_key="project")
    service.create_project({"name": "Project Two", "slug": "project-two"}, idempotency_key="project-two")
    with pytest.raises(InvalidRequestError) as malformed:
        service.list_projects(cursor="not-a-cursor", limit=1)
    assert malformed.value.status == 400
    page = service.list_projects(limit=1)
    with pytest.raises(InvalidRequestError) as wrong_scope:
        service.events_page(cursor=page["next_cursor"], limit=1)
    assert wrong_scope.value.status == 400
    service.close()


def test_generated_python_page_requires_next_cursor() -> None:
    def transport(method, path, headers, body):
        return 200, {}, json.dumps({"items": []}).encode()

    with pytest.raises(ApiError, match="next_cursor"):
        WorkspaceClient("http://runtime", transport=transport).list_projects()
