from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit, parse_qs

from .errors import RuntimeErrorBase, AuthorizationError, NotFoundError, ProtocolError


class RuntimeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class RuntimeHandler(BaseHTTPRequestHandler):
    server_version = "BanodocoRuntime/0.1"

    def log_message(self, *_):
        return

    @property
    def runtime(self):
        return self.server.runtime  # type: ignore[attr-defined]

    def _identity(self, scope):
        if self.path.split("?", 1)[0] in ("/health", "/v1/health"):
            return {"actor": "health", "scopes": ["health"]}
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            raise AuthorizationError("bearer credential required")
        return self.server.credentials.require(value[7:], scope)  # type: ignore[attr-defined]

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 64 * 1024 * 1024:
            raise ProtocolError("request body exceeds 64 MiB limit")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("request body must be valid JSON") from exc

    def _send(self, status, payload=None, *, headers=None, body=None, error=None, receipt=None, idempotency_key=None):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, str(value))
        if body is None:
            encoded = json.dumps(error if error is not None else payload, sort_keys=True).encode()
            self.send_header("Content-Type", "application/json")
        else:
            encoded = body
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _error(self, exc):
        if isinstance(exc, RuntimeErrorBase):
            self._send(exc.status, error=exc.as_dict())
        else:
            self._send(500, error={"code": "internal_error", "message": "internal runtime error"})

    def _route(self):
        path = [unquote(x) for x in urlsplit(self.path).path.split("/") if x]
        method = self.command
        if path in (["health"], ["v1", "health"]):
            return self._send(200, self.runtime.health())
        if path == ["v1", "credentials"] and method == "POST":
            self._identity("credentials:provision")
            body = self._body()
            actor = str(body.get("actor_id") or "")
            token = str(body.get("credential") or "")
            scope = str(body.get("scope") or "")
            if not actor or not token or scope != "astrid":
                raise ProtocolError("actor_id, credential, and astrid scope are required")
            scopes = ["handshake", "projects:read", "projects:write", "objects:read", "objects:write", "tasks:read", "tasks:write"]
            self.server.credentials.provision_static(actor, token, scopes)  # type: ignore[attr-defined]
            return self._send(201, {"actor_id": actor, "scope": scope})
        if path == ["v1", "handshake"] and method == "POST":
            identity = self._identity("handshake")
            body = self._body()
            body["authenticated_actor"] = identity["actor"]
            value = self.runtime.handshake(body)
            return self._send(200, value)
        if path == ["v1", "handshake"] and method == "GET":
            identity = self._identity("handshake")
            return self._send(200, self.runtime.handshake({"authenticated_actor": identity["actor"], "requested_scopes": []}))
        if path == ["v1", "realm"] and method == "GET":
            self._identity("projects:read")
            return self._send(200, self.runtime.realm_resource())
        if path == ["v1", "doctor"] and method == "GET":
            self._identity("admin")
            return self._send(200, self.runtime.doctor())
        if path == ["v1", "realm", "tombstone"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.tombstone(self._body()))
        if path == ["v1", "realm", "recover"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.recover_realm(self._body()))
        if path == ["v1", "realm", "purge"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.purge(self._body()))
        if path == ["v1", "export"] and method == "GET":
            self._identity("admin")
            return self._send(200, self.runtime.export_structured())
        if path == ["v1", "backup"] and method == "POST":
            self._identity("admin")
            body = self._body()
            if not body.get("destination"):
                raise ProtocolError("destination is required")
            return self._send(201, self.runtime.backup(body["destination"]))
        if path == ["v1", "restore"] and method == "POST":
            self._identity("admin")
            body = self._body()
            if not body.get("backup") or not body.get("destination"):
                raise ProtocolError("backup and destination are required")
            return self._send(201, self.runtime.restore(body["backup"], body["destination"]))
        if len(path) == 4 and path[:2] == ["v1", "projects"] and path[3] == "timelines":
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "POST": return self._send(201, self.runtime.create_timeline(path[2], self._body().get("timeline_id", "")))
            if method == "GET": return self._send(200, self.runtime.list_timelines(path[2]))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("shots", "references") and method == "POST":
            self._identity("projects:write")
            body = self._body()
            return self._send(201, self.runtime.create_shot(path[2], body) if path[3] == "shots" else self.runtime.create_reference(path[2], body))
        if len(path) == 3 and path[:2] == ["v1", "timelines"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime._timeline_resource(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "timelines"] and method == "PATCH":
            self._identity("projects:write"); return self._send(200, self.runtime.update_timeline(path[2], self._body()))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("history", "diff") and method == "GET":
            self._identity("projects:read")
            query = parse_qs(urlsplit(self.path).query)
            if path[3] == "history":
                return self._send(200, self.runtime.list_timeline_history(path[2], limit=query.get("limit", [50])[0]))
            if "from_version" not in query or "to_version" not in query:
                raise ProtocolError("from_version and to_version are required")
            return self._send(200, self.runtime.diff_timeline(path[2], query["from_version"][0], query["to_version"][0]))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            body = self._body()
            if path[3] == "archive":
                return self._send(200, self.runtime.archive_timeline(path[2], body))
            return self._send(200, self.runtime.recover_timeline(path[2], body))
        if len(path) == 3 and path[:2] == ["v1", "shots"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_shot(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "shots"] and method == "PATCH":
            self._identity("projects:write"); return self._send(200, self.runtime.update_shot(path[2], self._body()))
        if len(path) == 4 and path[:2] == ["v1", "shots"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            return self._send(200, self.runtime.archive_shot(path[2], self._body()) if path[3] == "archive" else self.runtime.recover_shot(path[2], self._body()))
        if len(path) == 3 and path[:2] == ["v1", "references"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_reference(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "references"] and method == "PATCH":
            self._identity("projects:write"); return self._send(200, self.runtime.update_reference(path[2], self._body()))
        if len(path) == 4 and path[:2] == ["v1", "references"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            return self._send(200, self.runtime.archive_reference(path[2], self._body()) if path[3] == "archive" else self.runtime.recover_reference(path[2], self._body()))
        if path == ["v1", "projects"]:
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                return self._send(200, self.runtime.list_projects())
            if method == "POST":
                body = self._body()
                return self._send(201, self.runtime._project_resource(self.runtime.create_project(body, idempotency_key=self.headers.get("Idempotency-Key"))))
        if path == ["v1", "workers"] and method == "POST":
            self._identity("worker:register")
            return self._send(201, self.runtime.register_worker(self._body()))
        if len(path) == 4 and path[:2] == ["v1", "workers"] and path[3] == "heartbeat" and method == "POST":
            self._identity("worker:execute")
            return self._send(200, self.runtime.worker_heartbeat(path[2], self._body()))
        if len(path) >= 3 and path[:2] == ["v1", "projects"]:
            selector = path[2]
            if len(path) == 3:
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    return self._send(200, self.runtime._project_resource(self.runtime.get_project(selector)))
                if method in ("PATCH", "PUT"):
                    key = self.headers.get("Idempotency-Key")
                    if not key:
                        raise ProtocolError("Idempotency-Key header is required")
                    value = self.runtime.update_project(selector, self._body(), idempotency_key=key)
                    return self._send(200, self.runtime._project_resource(value))
            if len(path) == 4 and path[3] == "documents":
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET": return self._send(200, self.runtime.list_documents(selector))
                if method == "POST": return self._send(201, self.runtime.create_document(selector, self._body()))
            if len(path) == 5 and path[3] == "documents" and method in ("GET", "PATCH"):
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET": return self._send(200, self.runtime.get_document(selector, path[4]))
                return self._send(200, self.runtime.update_document(selector, path[4], self._body()))
            if len(path) == 4 and path[3] == "generations":
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET": return self._send(200, self.runtime.list_generations(selector))
                if method == "POST": return self._send(201, self.runtime.create_generation(selector, self._body()))
            if len(path) == 4 and path[3] == "objects":
                self._identity("objects:read" if method == "GET" else "objects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_project_objects(selector, limit=query.get("limit", [50])[0]))
                if method == "POST":
                    length = int(self.headers.get("Content-Length", "0"))
                    data = self.rfile.read(length)
                    result = self.runtime.ingest(selector, data, media_type=self.headers.get("Content-Type", "application/octet-stream"), original_name=self.headers.get("X-Original-Name"), expected_digest=self.headers.get("X-Expected-Digest"))
                    return self._send(201, self.runtime._object_resource(result))
            if len(path) == 4 and path[3] in ("tasks", "runs") and method == "GET":
                self._identity("tasks:read")
                query = parse_qs(urlsplit(self.path).query)
                value = self.runtime.list_project_tasks(selector, limit=query.get("limit", [50])[0]) if path[3] == "tasks" else self.runtime.list_project_runs(selector, limit=query.get("limit", [50])[0])
                return self._send(200, value)
            if len(path) == 4 and path[3] in ("shots", "references") and method == "GET":
                self._identity("projects:read")
                query = parse_qs(urlsplit(self.path).query)
                include_archived = query.get("include_archived", ["false"])[0].lower() == "true"
                value = self.runtime.list_project_shots(selector, include_archived=include_archived, limit=query.get("limit", [50])[0]) if path[3] == "shots" else self.runtime.list_project_references(selector, include_archived=include_archived, limit=query.get("limit", [50])[0])
                return self._send(200, value)
            if len(path) == 4 and path[3] == "media-relations":
                self._identity("objects:read" if method == "GET" else "objects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_media_relations(selector, limit=query.get("limit", [50])[0]))
                if method == "POST": return self._send(201, self.runtime.create_media_relation(selector, self._body()))
        if path == ["v1", "objects"] and method == "POST":
            self._identity("objects:write")
            length = int(self.headers.get("Content-Length", "0")); data = self.rfile.read(length)
            return self._send(201, self.runtime.ingest_object(data, media_type=self.headers.get("Content-Type", "application/octet-stream"), original_name=self.headers.get("X-Filename"), expected_digest=self.headers.get("X-Expected-Digest")))
        if len(path) == 3 and path[:2] == ["v1", "objects"] and method in ("GET", "HEAD"):
            self._identity("objects:read")
            metadata, data = self.runtime.object(path[2])
            total = len(data)
            start, end = 0, total - 1
            range_header = self.headers.get("Range")
            status = 200
            if range_header:
                try:
                    unit, spec = range_header.split("=", 1)
                    if unit != "bytes" or "," in spec:
                        raise ValueError
                    left, right = spec.split("-", 1)
                    start = int(left) if left else max(0, total - int(right))
                    end = int(right) if right else total - 1
                    if start < 0 or end < start or end >= total:
                        raise ValueError
                    status = 206
                except ValueError as exc:
                    return self._send(416, {"code": "invalid_range", "message": "invalid byte range"}, headers={"Content-Range": f"bytes */{total}"})
            digest = path[2].removeprefix("sha256:")
            etag_value = "sha256:" + digest
            headers = {"Content-Type": metadata["media_type"], "ETag": f'"{etag_value}"', "Accept-Ranges": "bytes", "X-Content-Digest": etag_value}
            if status == 206:
                headers["Content-Range"] = f"bytes {start}-{end}/{total}"
            return self._send(status, headers=headers, body=data[start:end+1])
        if path == ["v1", "tasks"] and method == "POST":
            self._identity("tasks:write")
            body = self._body()
            body["idempotency_key"] = self.headers.get("Idempotency-Key") or body.get("idempotency_key")
            return self._send(201, self.runtime._task_resource(self.runtime.create_task(body)))
        if path == ["v1", "tasks", "claim"] and method == "POST":
            self._identity("worker:execute")
            result = self.runtime.claim_next(self._body())
            if result is None:
                return self._send(204, body=b"")
            return self._send(200, result)
        if len(path) == 3 and path[:2] == ["v1", "tasks"]:
            task_id = path[2]
            if method == "GET":
                self._identity("tasks:read")
                value = self.runtime.task(task_id)
                return self._send(200, self.runtime._task_resource(value))
        if len(path) == 4 and path[:2] == ["v1", "tasks"]:
            task_id, action = path[2:]
            self._identity("worker:execute" if action in ("claim", "settle", "heartbeat") else "tasks:write")
            if method == "POST" and action == "claim":
                return self._send(200, self.runtime._task_resource(self.runtime.claim(task_id, self._body())))
            if method == "POST" and action == "settle":
                return self._send(200, self.runtime._task_resource(self.runtime.settle(task_id, self._body())))
            if method == "POST" and action == "heartbeat":
                return self._send(200, self.runtime.heartbeat(task_id, self._body()))
            if method == "POST" and action == "cancel":
                return self._send(200, self.runtime.cancel_task_canonical(task_id, self._body()))
            if method == "POST" and action == "retry":
                return self._send(200, self.runtime.retry_task(task_id, self._body()))
            if method == "GET" and action == "events":
                task = self.runtime.store.get_task(task_id)
                return self._send(200, self.runtime.events_page(task["run"]["id"]))
        if len(path) == 4 and path[:2] == ["v1", "attempts"] and method == "POST":
            self._identity("worker:execute")
            action = path[3]
            if action == "prepare-reboot":
                body = self._body()
                # The canonical attempt identity is the path parameter.  The
                # generated clients intentionally do not duplicate it in the
                # JSON body, so bind it at the HTTP boundary before invoking
                # the service.
                body["attempt_id"] = path[2]
                return self._send(200, self.runtime.prepare_reboot(body))
            if action == "checkpoint": return self._send(201, self.runtime.checkpoint_attempt(path[2], self._body()))
            if action == "settle": return self._send(200, self.runtime.settle_attempt(path[2], self._body()))
            if action == "heartbeat": return self._send(200, self.runtime.heartbeat_attempt(path[2], self._body()))
            if action == "fail": return self._send(200, self.runtime.fail_attempt(path[2], self._body()))
        if path in (["v1", "recovery", "reboot"], ["v1", "runtime", "reboot"]) and method == "POST":
            self._identity("worker:execute")
            return self._send(200, self.runtime.request_reboot(self._body()))
        if path in (["v1", "recovery", "resume"], ["v1", "runtime", "resume"]) and method == "POST":
            self._identity("worker:execute")
            return self._send(200, self.runtime.resume_attempt(self._body()))
        if len(path) == 3 and path[:2] == ["v1", "generations"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_generation(path[2]))
        if len(path) == 4 and path[:2] == ["v1", "generations"] and path[3] == "variants":
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET": return self._send(200, self.runtime.list_variants(path[2]))
            if method == "POST": return self._send(201, self.runtime.create_variant(path[2], self._body()))
        if len(path) == 3 and path[:2] == ["v1", "variants"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_variant(path[2]))
        if len(path) == 4 and path[:2] == ["v1", "runs"] and path[3] == "events" and method == "GET":
            self._identity("tasks:read")
            return self._send(200, self.runtime.events_page(path[2]))
        if len(path) == 4 and path[:2] == ["v1", "runs"] and path[3] in ("cancel", "retry-failed", "retry") and method == "POST":
            self._identity("tasks:write")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            body = self._body()
            if path[3] == "cancel":
                return self._send(200, self.runtime.cancel_run(path[2], body, idempotency_key=key))
            return self._send(200, self.runtime.retry_run(path[2], body, idempotency_key=key))
        if path == ["v1", "events"] and method == "GET":
            self._identity("tasks:read")
            query = parse_qs(urlsplit(self.path).query)
            return self._send(200, self.runtime.events_page(query.get("aggregate_id", [None])[0], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if path == ["v1", "capabilities"] and method == "GET":
            # Capability discovery is part of task admission, not worker
            # control. Astrid's scoped product actor must be able to resolve
            # a capability digest before creating a task, while registration
            # and execution remain restricted to worker scopes.
            self._identity("tasks:read")
            return self._send(200, self.runtime.list_capabilities())
        if path == ["v1", "capabilities"] and method == "POST":
            self._identity("worker:register")
            return self._send(201, self.runtime.register_capability(self._body()))
        if path == ["v1", "executors"] and method == "POST":
            self._identity("worker:register")
            return self._send(201, self.runtime.register_executor(self._body()))
        if len(path) == 3 and path[:2] == ["v1", "runs"] and method == "GET":
            self._identity("tasks:read")
            return self._send(200, self.runtime.run(path[2]))
        raise NotFoundError("route not found")

    def do_GET(self):
        try:
            self._route()
        except Exception as exc:
            self._error(exc)

    def do_HEAD(self):
        try:
            self._route()
        except Exception as exc:
            self._error(exc)

    def do_POST(self):
        try:
            self._route()
        except Exception as exc:
            self._error(exc)

    def do_PATCH(self):
        try:
            self._route()
        except Exception as exc:
            self._error(exc)

    def do_PUT(self):
        self.do_PATCH()
