from __future__ import annotations

import json
import urllib.error
import urllib.request


class Api:
    """Test-only neutral HTTP actor; production bindings are generated elsewhere."""

    def __init__(self, endpoint, credential):
        self.endpoint, self.credential = endpoint.rstrip("/"), credential

    def request(self, method, path, value=None, *, raw=None, headers=None):
        body = raw if raw is not None else (json.dumps(value).encode() if value is not None else None)
        request = urllib.request.Request(self.endpoint + path, data=body, method=method)
        if self.credential:
            request.add_header("Authorization", f"Bearer {self.credential}")
        if value is not None:
            request.add_header("Content-Type", "application/json")
        for key, val in (headers or {}).items():
            request.add_header(key, val)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                data = response.read()
                if response.headers.get("Content-Type", "").startswith("application/json"):
                    return json.loads(data)
                return data, dict(response.headers)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode())
            except Exception:
                detail = {"message": str(exc)}
            error = RuntimeError(detail)
            error.status = exc.code
            error.detail = detail
            raise error from exc

    def health(self): return self.request("GET", "/v1/health")
    def handshake(self): return self.request("GET", "/v1/handshake")
    def create_project(self, slug, name, metadata=None, idempotency_key=None): return self.request("POST", "/v1/projects", {"slug": slug, "name": name, "metadata": metadata or {}}, headers={"Idempotency-Key": idempotency_key or "test-project"})["data"]
    def get_project(self, selector): return self.request("GET", f"/v1/projects/{selector}")
    def ingest(self, project, data, *, media_type="application/octet-stream", original_name=None, expected_digest=None, idempotency_key=None):
        headers = {"Content-Type": media_type}
        if original_name: headers["X-Original-Name"] = original_name
        if expected_digest: headers["X-Expected-Digest"] = expected_digest
        headers["Idempotency-Key"] = idempotency_key or "test-ingest"
        return self.request("POST", f"/v1/projects/{project}/objects", raw=data, headers=headers)
    def read_object(self, digest, *, range_header=None): return self.request("GET", f"/v1/objects/{digest}", headers={"Range": range_header} if range_header else None)
    def create_task(self, capability, spec, *, project=None, idempotency_key=None, expected_effect=None): return self.request("POST", "/v1/tasks", {"capability_id": capability, "capability_digest": "sha256:" + __import__("hashlib").sha256(capability.encode()).hexdigest(), "input_object_ids": [], "spec": spec, "project": project, "settlement_effect": expected_effect}, headers={"Idempotency-Key": idempotency_key or "test-task"})["data"]
    def task(self, task_id): return self.request("GET", f"/v1/tasks/{task_id}")
    def events(self, run_id): return self.request("GET", f"/v1/runs/{run_id}/events")
    def register_executor(self, executor_id, capabilities, *, max_concurrency=1, resource_keys=None, idempotency_key=None):
        descriptors = []
        for value in capabilities:
            if isinstance(value, dict):
                descriptors.append(value)
                continue
            digest = "sha256:" + __import__("hashlib").sha256(str(value).encode()).hexdigest()
            descriptors.append({"capability_id": value, "definition_digest": digest, "status": "ready", "required_resource_keys": [], "estimated_scratch_bytes": 0, "estimated_output_bytes": 1})
        body = {"executor_id": executor_id, "capabilities": descriptors, "max_concurrency": max_concurrency, "resource_keys": resource_keys or [], "protocol": "workspace.v1"}
        return self.request("POST", "/v1/executors", body, headers={"Idempotency-Key": idempotency_key or f"executor-{executor_id}"})
