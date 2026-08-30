import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, WorkspaceClient } from "../dist/generated.js";

const json = (value) => new TextEncoder().encode(JSON.stringify(value));

test("generated TypeScript client performs scoped handshake and idempotent project admission", async () => {
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, headers, body });
    if (path === "/v1/handshake") return { status: 200, headers: {}, body: json({ protocol: "workspace.v1", schema_digest: `sha256:${"a".repeat(64)}`, session_id: "s", actor_id: "a", realm_id: "r", scopes: ["project:write"] }) };
    if (path === "/v1/projects") return { status: 201, headers: {}, body: json({ project_id: "p", realm_id: "r", name: "Neutral", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }) };
    throw new Error(`unexpected ${method} ${path}`);
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  const session = await client.handshake("neutral-gallery", "0.1.0", ["project:write"]);
  const project = await client.createProject("Neutral", "idempotency-1");
  assert.equal(session.realm_id, "r");
  assert.equal(project.project_id, "p");
  assert.equal(calls[1].headers.Authorization, "Bearer token");
  assert.equal(calls[1].headers["Idempotency-Key"], "idempotency-1");
});

test("generated TypeScript client preserves inclusive range and strong ETag", async () => {
  const transport = async (method, path, headers) => {
    assert.equal(method, "GET"); assert.equal(path, "/v1/objects/o"); assert.equal(headers.Range, "bytes=2-5");
    return { status: 206, headers: { ETag: `"sha256:${"b".repeat(64)}"`, "Content-Range": "bytes 2-5/10" }, body: new TextEncoder().encode("2345") };
  };
  const response = await new WorkspaceClient("http://runtime", undefined, transport).getObject("o", [2, 5]);
  assert.equal(response.status, 206); assert.equal(new TextDecoder().decode(response.data), "2345"); assert.equal(response.content_range, "bytes 2-5/10");
});

test("generated TypeScript client exposes structured conflict errors", async () => {
  const transport = async () => ({ status: 409, headers: {}, body: json({ code: "version_conflict", message: "stale", request_id: "q", details: { actual: 2 } }) });
  await assert.rejects(() => new WorkspaceClient("http://runtime", undefined, transport).getProject("p"), (error) => error instanceof ApiError && error.code === "version_conflict" && error.details.actual === 2);
});
