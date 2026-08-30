from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

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
            encoded = json.dumps({"ok": status < 400, "data": payload if error is None else None, "error": error, "receipt": receipt, "idempotency_key": idempotency_key}, sort_keys=True).encode()
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
        if path == ["v1", "handshake"] and method == "GET":
            self._identity("health")
            return self._send(200, {"protocol_version": "core-v1", "schema_version": 1, "realm": self.runtime.realm, "actor": self._identity("health")["actor"]})
        if path == ["v1", "projects"]:
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                return self._send(200, self.runtime.list_projects())
            if method == "POST":
                return self._send(201, self.runtime.create_project(self._body()))
        if path == ["v1", "workers"] and method == "POST":
            self._identity("worker:register")
            return self._send(201, self.runtime.register_worker(self._body()))
        if len(path) >= 3 and path[:2] == ["v1", "projects"]:
            selector = path[2]
            if len(path) == 3:
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    return self._send(200, self.runtime.get_project(selector))
                if method in ("PATCH", "PUT"):
                    return self._send(200, self.runtime.update_project(selector, self._body()))
            if len(path) == 4 and path[3] == "objects":
                self._identity("objects:read" if method == "GET" else "objects:write")
                if method == "GET":
                    return self._send(200, self.runtime.objects(selector))
                if method == "POST":
                    length = int(self.headers.get("Content-Length", "0"))
                    data = self.rfile.read(length)
                    result = self.runtime.ingest(selector, data, media_type=self.headers.get("Content-Type", "application/octet-stream"), original_name=self.headers.get("X-Original-Name"), expected_digest=self.headers.get("X-Expected-Digest"))
                    return self._send(201, result)
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
            headers = {"Content-Type": metadata["media_type"], "ETag": f'"{path[2]}"', "Accept-Ranges": "bytes", "X-Content-Digest": path[2]}
            if status == 206:
                headers["Content-Range"] = f"bytes {start}-{end}/{total}"
            return self._send(status, headers=headers, body=data[start:end+1])
        if path == ["v1", "tasks"] and method == "POST":
            self._identity("tasks:write")
            return self._send(201, self.runtime.create_task(self._body()))
        if len(path) == 3 and path[:2] == ["v1", "tasks"]:
            task_id = path[2]
            if method == "GET":
                self._identity("tasks:read")
                return self._send(200, self.runtime.task(task_id))
        if len(path) == 4 and path[:2] == ["v1", "tasks"]:
            task_id, action = path[2:]
            self._identity("worker:execute" if action in ("claim", "settle") else "tasks:write")
            if method == "POST" and action == "claim":
                return self._send(200, self.runtime.claim(task_id, self._body()))
            if method == "POST" and action == "settle":
                return self._send(200, self.runtime.settle(task_id, self._body()))
            if method == "POST" and action == "cancel":
                return self._send(200, self.runtime.cancel(task_id))
            if method == "GET" and action == "events":
                task = self.runtime.task(task_id)
                return self._send(200, self.runtime.events(task["run"]["id"]))
        if len(path) == 4 and path[:2] == ["v1", "runs"] and path[3] == "events" and method == "GET":
            self._identity("tasks:read")
            return self._send(200, self.runtime.events(path[2]))
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
