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
            raise RuntimeError(detail) from exc

    def health(self): return self.request("GET", "/v1/health")
    def handshake(self): return self.request("GET", "/v1/handshake")
    def create_project(self, slug, name, metadata=None, idempotency_key=None): return self.request("POST", "/v1/projects", {"slug": slug, "name": name, "metadata": metadata or {}, "idempotency_key": idempotency_key})
    def get_project(self, selector): return self.request("GET", f"/v1/projects/{selector}")
    def ingest(self, project, data, *, media_type="application/octet-stream", original_name=None, expected_digest=None):
        headers = {"Content-Type": media_type}
        if original_name: headers["X-Original-Name"] = original_name
        if expected_digest: headers["X-Expected-Digest"] = expected_digest
        return self.request("POST", f"/v1/projects/{project}/objects", raw=data, headers=headers)
    def read_object(self, digest, *, range_header=None): return self.request("GET", f"/v1/objects/{digest}", headers={"Range": range_header} if range_header else None)
    def create_task(self, capability, spec, *, project=None, idempotency_key=None, expected_effect=None): return self.request("POST", "/v1/tasks", {"capability": capability, "spec": spec, "project": project, "idempotency_key": idempotency_key, "expected_effect": expected_effect})
    def task(self, task_id): return self.request("GET", f"/v1/tasks/{task_id}")
    def claim(self, task_id, worker_id, lease_token): return self.request("POST", f"/v1/tasks/{task_id}/claim", {"worker_id": worker_id, "lease_token": lease_token})
    def settle(self, task_id, lease_token, result, *, effect=None, output_objects=None): return self.request("POST", f"/v1/tasks/{task_id}/settle", {"lease_token": lease_token, "result": result, "effect": effect, "output_objects": output_objects or []})
    def events(self, run_id): return self.request("GET", f"/v1/runs/{run_id}/events")
    def register_worker(self, worker_id, capabilities, *, max_concurrency=1, resource_keys=None): return self.request("POST", "/v1/workers", {"worker_id": worker_id, "capabilities": capabilities, "max_concurrency": max_concurrency, "resource_keys": resource_keys or []})
