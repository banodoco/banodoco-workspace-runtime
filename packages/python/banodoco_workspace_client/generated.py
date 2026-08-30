"""Generated from contract/openapi/workspace-v1.yaml; do not edit by hand."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

PROTOCOL = "workspace.v1"


class ApiError(RuntimeError):
    def __init__(self, status: int, code: str, message: str, request_id: str = "", details: Mapping[str, Any] | None = None):
        super().__init__(f"{code}: {message}")
        self.status, self.code, self.message = status, code, message
        self.request_id, self.details = request_id, dict(details or {})


@dataclass(frozen=True)
class Handshake:
    protocol: str
    schema_digest: str
    session_id: str
    actor_id: str
    realm_id: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class Project:
    project_id: str
    realm_id: str
    name: str
    version: int
    created_at: str
    updated_at: str
    archived: bool = False

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "Project":
        return cls(project_id=value["project_id"], realm_id=value["realm_id"], name=value["name"], version=int(value["version"]), created_at=value["created_at"], updated_at=value["updated_at"], archived=bool(value.get("archived", False)))


@dataclass(frozen=True)
class ManagedObject:
    object_id: str
    digest: str
    media_type: str
    size: int
    version: int
    created_at: str
    filename: str | None = None

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "ManagedObject":
        return cls(object_id=value["object_id"], digest=value["digest"], media_type=value["media_type"], size=int(value["size"]), version=int(value["version"]), created_at=value["created_at"], filename=value.get("filename"))


@dataclass(frozen=True)
class ByteResponse:
    data: bytes
    status: int
    headers: Mapping[str, str]

    @property
    def etag(self) -> str | None:
        return self.headers.get("ETag") or self.headers.get("etag")

    @property
    def content_range(self) -> str | None:
        return self.headers.get("Content-Range") or self.headers.get("content-range")


@dataclass(frozen=True)
class Task:
    task_id: str
    run_id: str
    state: str
    version: int
    capability_id: str
    capability_digest: str
    idempotency_key: str
    created_at: str
    updated_at: str
    attempt_id: str | None = None

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "Task":
        return cls(task_id=value["task_id"], run_id=value["run_id"], state=value["state"], version=int(value["version"]), capability_id=value["capability_id"], capability_digest=value["capability_digest"], idempotency_key=value["idempotency_key"], created_at=value["created_at"], updated_at=value["updated_at"], attempt_id=value.get("attempt_id"))


@dataclass(frozen=True)
class Event:
    event_id: str
    sequence: int
    cursor: str
    event_type: str
    aggregate_type: str
    aggregate_id: str
    payload: Mapping[str, Any]
    occurred_at: str

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "Event":
        return cls(event_id=value["event_id"], sequence=int(value["sequence"]), cursor=value["cursor"], event_type=value["event_type"], aggregate_type=value["aggregate_type"], aggregate_id=value["aggregate_id"], payload=value.get("payload", {}), occurred_at=value["occurred_at"])


@dataclass(frozen=True)
class Capability:
    capability_id: str
    definition_digest: str
    status: str
    required_resource_keys: tuple[str, ...]
    estimated_scratch_bytes: int
    estimated_output_bytes: int
    unavailable_reason: str | None = None

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "Capability":
        return cls(capability_id=value["capability_id"], definition_digest=value["definition_digest"], status=value["status"], required_resource_keys=tuple(value.get("required_resource_keys", [])), estimated_scratch_bytes=int(value.get("estimated_scratch_bytes", 0)), estimated_output_bytes=int(value.get("estimated_output_bytes", 0)), unavailable_reason=value.get("unavailable_reason"))


@dataclass(frozen=True)
class Executor:
    executor_id: str
    max_concurrency: int
    resource_keys: tuple[str, ...]
    capabilities: tuple[Capability, ...]
    protocol: str

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "Executor":
        return cls(executor_id=value["executor_id"], max_concurrency=int(value["max_concurrency"]), resource_keys=tuple(value.get("resource_keys", [])), capabilities=tuple(Capability.from_json(item) for item in value.get("capabilities", [])), protocol=value["protocol"])


def _decode_error(status: int, body: bytes) -> ApiError:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        value = {}
    return ApiError(status, str(value.get("code", "http_error")), str(value.get("message", f"HTTP {status}")), str(value.get("request_id", "")), value.get("details", {}))


class WorkspaceClient:
    """Small stdlib HTTP client generated from the neutral OpenAPI contract.

    ``transport`` is injectable for conformance tests. It receives method, path,
    headers, and body and returns ``(status, headers, body)``.
    """

    def __init__(self, base_url: str, token: str | None = None, *, transport: Callable[..., tuple[int, Mapping[str, str], bytes]] | None = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._transport = transport
        self.handshake_info: Handshake | None = None

    def _request(self, method: str, path: str, *, body: bytes | None = None, headers: Mapping[str, str] | None = None, expected: tuple[int, ...] = (200,)) -> tuple[int, Mapping[str, str], bytes]:
        request_headers = {"Accept": "application/json", **dict(headers or {})}
        if self.token:
            request_headers.setdefault("Authorization", f"Bearer {self.token}")
        if self._transport:
            status, response_headers, response_body = self._transport(method, path, request_headers, body)
        else:
            request = urllib.request.Request(self.base_url + path, data=body, headers=request_headers, method=method)
            try:
                with urllib.request.urlopen(request) as response:  # noqa: S310 - endpoint is caller-configured
                    status, response_headers, response_body = response.status, dict(response.headers), response.read()
            except urllib.error.HTTPError as error:
                raise _decode_error(error.code, error.read()) from error
            except urllib.error.URLError as error:
                raise ApiError(0, "transport_error", str(error.reason)) from error
        if status not in expected:
            raise _decode_error(status, response_body)
        return status, response_headers, response_body

    @staticmethod
    def _json(body: bytes) -> Mapping[str, Any]:
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ApiError(0, "invalid_response", "expected JSON object")
        return value

    def health(self) -> Mapping[str, Any]:
        _, _, body = self._request("GET", "/v1/health")
        return self._json(body)

    def handshake(self, client_name: str, client_version: str, requested_scopes: list[str]) -> Handshake:
        payload = {"protocol": PROTOCOL, "client_name": client_name, "client_version": client_version, "requested_scopes": requested_scopes}
        _, _, body = self._request("POST", "/v1/handshake", body=json.dumps(payload, separators=(",", ":")).encode(), headers={"Content-Type": "application/json"})
        value = self._json(body)
        result = Handshake(protocol=value["protocol"], schema_digest=value["schema_digest"], session_id=value["session_id"], actor_id=value["actor_id"], realm_id=value["realm_id"], scopes=tuple(value["scopes"]))
        self.handshake_info = result
        return result

    def create_project(self, name: str, *, idempotency_key: str) -> Project:
        _, _, body = self._request("POST", "/v1/projects", body=json.dumps({"name": name}, separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key}, expected=(200, 201))
        return Project.from_json(self._json(body))

    def get_project(self, project_id: str) -> Project:
        _, _, body = self._request("GET", f"/v1/projects/{_path_part(project_id)}")
        return Project.from_json(self._json(body))

    def create_timeline(self, project_id: str, timeline_id: str, *, idempotency_key: str) -> Mapping[str, Any]:
        return self._json(self._request("POST", f"/v1/projects/{_path_part(project_id)}/timelines", body=json.dumps({"timeline_id": timeline_id}, separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key}, expected=(200, 201))[2])

    def list_timelines(self, project_id: str, *, cursor: str | None = None, limit: int = 50) -> tuple[list[Mapping[str, Any]], str | None]:
        query = f"?limit={int(limit)}" + (f"&cursor={_path_part(cursor)}" if cursor else "")
        value = self._json(self._request("GET", f"/v1/projects/{_path_part(project_id)}/timelines" + query)[2])
        return list(value.get("items", [])), value.get("next_cursor")

    def get_timeline(self, timeline_id: str) -> Mapping[str, Any]:
        return self._json(self._request("GET", f"/v1/timelines/{_path_part(timeline_id)}")[2])

    def create_shot(self, timeline_id: str, shot: Mapping[str, Any], *, idempotency_key: str) -> Mapping[str, Any]:
        return self._json(self._request("POST", f"/v1/timelines/{_path_part(timeline_id)}/shots", body=json.dumps(dict(shot), separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key}, expected=(200, 201))[2])

    def get_shot(self, shot_id: str) -> Mapping[str, Any]:
        return self._json(self._request("GET", f"/v1/shots/{_path_part(shot_id)}")[2])

    def create_reference(self, timeline_id: str, reference: Mapping[str, Any], *, idempotency_key: str) -> Mapping[str, Any]:
        return self._json(self._request("POST", f"/v1/timelines/{_path_part(timeline_id)}/references", body=json.dumps(dict(reference), separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key}, expected=(200, 201))[2])

    def get_reference(self, reference_id: str) -> Mapping[str, Any]:
        return self._json(self._request("GET", f"/v1/references/{_path_part(reference_id)}")[2])

    def list_projects(self, *, cursor: str | None = None, limit: int = 50) -> tuple[list[Project], str | None]:
        query = f"?limit={int(limit)}" + (f"&cursor={_path_part(cursor)}" if cursor else "")
        _, _, body = self._request("GET", "/v1/projects" + query)
        value = self._json(body)
        return [Project.from_json(item) for item in value.get("items", [])], value.get("next_cursor")

    def ingest_object(self, data: bytes, *, media_type: str, idempotency_key: str, filename: str | None = None) -> ManagedObject:
        headers = {"Content-Type": media_type, "Idempotency-Key": idempotency_key}
        if filename:
            headers["X-Filename"] = filename
        _, _, body = self._request("POST", "/v1/objects", body=bytes(data), headers=headers, expected=(200, 201))
        return ManagedObject.from_json(self._json(body))

    def get_object(self, object_id: str, *, byte_range: tuple[int, int | None] | None = None) -> ByteResponse:
        headers: dict[str, str] = {}
        if byte_range:
            start, end = byte_range
            if start < 0 or (end is not None and end < start):
                raise ValueError("invalid byte range")
            headers["Range"] = f"bytes={start}-{'' if end is None else end}"
        status, response_headers, body = self._request("GET", f"/v1/objects/{_path_part(object_id)}", headers=headers, expected=(200, 206))
        return ByteResponse(body, status, response_headers)

    def head_object(self, object_id: str, *, byte_range: tuple[int, int | None] | None = None) -> ByteResponse:
        headers: dict[str, str] = {}
        if byte_range:
            start, end = byte_range
            headers["Range"] = f"bytes={start}-{'' if end is None else end}"
        status, response_headers, body = self._request("HEAD", f"/v1/objects/{_path_part(object_id)}", headers=headers, expected=(200, 206))
        return ByteResponse(body, status, response_headers)

    def admit_task(self, *, capability_id: str, capability_digest: str, input_object_ids: list[str], idempotency_key: str, schema_version: str = "1", settlement_effect: Mapping[str, Any] | None = None) -> Task:
        payload: dict[str, Any] = {"capability_id": capability_id, "capability_digest": capability_digest, "schema_version": schema_version, "input_object_ids": input_object_ids}
        if settlement_effect is not None:
            payload["settlement_effect"] = settlement_effect
        _, _, body = self._request("POST", "/v1/tasks", body=json.dumps(payload, separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key}, expected=(200, 201))
        return Task.from_json(self._json(body))

    def get_task(self, task_id: str) -> Task:
        _, _, body = self._request("GET", f"/v1/tasks/{_path_part(task_id)}")
        return Task.from_json(self._json(body))

    def claim_task(self, *, executor_id: str, capability_ids: list[str], idempotency_key: str) -> Mapping[str, Any] | None:
        status, _, body = self._request("POST", "/v1/tasks/claim", body=json.dumps({"executor_id": executor_id, "capability_ids": capability_ids}, separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key}, expected=(200, 204))
        return None if status == 204 else self._json(body)

    def heartbeat_attempt(self, attempt_id: str, *, lease_id: str, fence: int, idempotency_key: str) -> Mapping[str, Any]:
        _, _, body = self._request("POST", f"/v1/attempts/{_path_part(attempt_id)}/heartbeat", body=json.dumps({"lease_id": lease_id, "fence": fence}, separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key})
        return self._json(body)

    def cancel_task(self, task_id: str, *, idempotency_key: str, expected_version: int | None = None) -> Task:
        return self._task_transition("cancel", task_id, idempotency_key=idempotency_key, expected_version=expected_version)

    def retry_task(self, task_id: str, *, idempotency_key: str, expected_version: int | None = None) -> Task:
        return self._task_transition("retry", task_id, idempotency_key=idempotency_key, expected_version=expected_version)

    def _task_transition(self, action: str, task_id: str, *, idempotency_key: str, expected_version: int | None) -> Task:
        payload = {} if expected_version is None else {"expected_version": expected_version}
        _, _, body = self._request("POST", f"/v1/tasks/{_path_part(task_id)}/{action}", body=json.dumps(payload, separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key})
        return Task.from_json(self._json(body))

    def get_run(self, run_id: str) -> Mapping[str, Any]:
        _, _, body = self._request("GET", f"/v1/runs/{_path_part(run_id)}")
        return self._json(body)

    def list_events(self, *, cursor: str | None = None, limit: int = 50, aggregate_id: str | None = None) -> tuple[list[Event], str | None]:
        query = f"?limit={int(limit)}" + (f"&cursor={_path_part(cursor)}" if cursor else "") + (f"&aggregate_id={_path_part(aggregate_id)}" if aggregate_id else "")
        _, _, body = self._request("GET", "/v1/events" + query)
        value = self._json(body)
        return [Event.from_json(item) for item in value.get("items", [])], value.get("next_cursor")

    def register_executor(self, executor: Mapping[str, Any], *, idempotency_key: str) -> Executor:
        _, _, body = self._request("POST", "/v1/executors", body=json.dumps(dict(executor), separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key}, expected=(200, 201))
        return Executor.from_json(self._json(body))

    def list_capabilities(self) -> list[Capability]:
        _, _, body = self._request("GET", "/v1/capabilities")
        return [Capability.from_json(item) for item in self._json(body).get("items", [])]

    def settle_attempt(self, attempt_id: str, settlement: Mapping[str, Any], *, idempotency_key: str) -> Task:
        _, _, body = self._request("POST", f"/v1/attempts/{_path_part(attempt_id)}/settle", body=json.dumps(dict(settlement), separators=(",", ":")).encode(), headers={"Content-Type": "application/json", "Idempotency-Key": idempotency_key})
        return Task.from_json(self._json(body))


def _path_part(value: str) -> str:
    from urllib.parse import quote
    return quote(str(value), safe="")
