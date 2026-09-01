import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, WorkspaceClient } from "../dist/generated.js";

const json = (value) => new TextEncoder().encode(JSON.stringify(value));

test("generated TypeScript client performs scoped handshake and idempotent project admission", async () => {
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, headers, body });
    if (path === "/v1/handshake") return { status: 200, headers: {}, body: json({ protocol: "workspace.v1", schema_digest: `sha256:${"a".repeat(64)}`, session_id: "s", actor_id: "a", realm_id: "r", scopes: ["project:write"] }) };
    if (path === "/v1/projects") return { status: 201, headers: {}, body: json({ data: { project_id: "p", realm_id: "r", name: "Neutral", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }, receipt: { receipt_id: "runtime-command-1", command_kind: "project.create", idempotency_key: "idempotency-1", request_hash: `sha256:${"a".repeat(64)}`, project_id: "p", project_seq: [1, 1], event_ids: [], result: {}, created_at: "2026-01-01T00:00:00Z" } }) };
    throw new Error(`unexpected ${method} ${path}`);
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  const session = await client.handshake("neutral-gallery", "0.1.0", ["project:write"]);
  const project = await client.createProject("Neutral", "idempotency-1");
  assert.equal(session.realm_id, "r");
  assert.equal(project.project_id, "p");
  assert.equal(project.receipt.command_kind, "project.create");
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

test("generated TypeScript client preserves the EventPage boundary", async () => {
  const event = { event_id: "1", sequence: 1, cursor: "1", event_type: "task.admitted", aggregate_type: "run", aggregate_id: "run-1", payload: {}, occurred_at: "2026-01-01T00:00:00Z" };
  const transport = async (method, path) => {
    assert.equal(method, "GET");
    assert.equal(path, "/v1/runs/run-1/events");
    return { status: 200, headers: {}, body: json({ items: [event], next_cursor: null }) };
  };
  const page = await new WorkspaceClient("http://runtime", undefined, transport).listRunEvents("run-1");
  assert.deepEqual(page, { items: [event], next_cursor: null });
});

test("generated TypeScript client exposes structured conflict errors", async () => {
  const transport = async () => ({ status: 409, headers: {}, body: json({ code: "version_conflict", message: "stale", request_id: "q", details: { actual: 2 } }) });
  await assert.rejects(() => new WorkspaceClient("http://runtime", undefined, transport).getProject("p"), (error) => error instanceof ApiError && error.code === "version_conflict" && error.details.actual === 2);
});

test("generated TypeScript client registers capabilities and fences failure", async () => {
  const task = { task_id: "t", run_id: "r", state: "failed", version: 2, capability_id: "render.basic", capability_digest: `sha256:${"b".repeat(64)}`, idempotency_key: "i", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" };
  const transport = async (method, path, headers, body) => {
    if (path === "/v1/capabilities") {
      assert.equal(method, "POST");
      const value = JSON.parse(new TextDecoder().decode(body));
      assert.equal(value.capability_id, "render.new");
      return { status: 201, headers: {}, body: json({ capability_id: "render.new", definition_digest: value.definition_digest, status: "ready", required_resource_keys: [], estimated_scratch_bytes: 0, estimated_output_bytes: 0 }) };
    }
    if (path === "/v1/attempts/a/fail") {
      assert.equal(JSON.parse(new TextDecoder().decode(body)).fence, 4);
      return { status: 200, headers: {}, body: json({ data: task, receipt: { receipt_id: "fail-receipt" } }) };
    }
    throw new Error(`unexpected ${method} ${path}`);
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  const capability = await client.registerCapability({ capability_id: "render.new", definition_digest: `sha256:${"c".repeat(64)}` }, "cap-1");
  const failed = await client.failAttempt("a", "lease", 4, { code: "worker_error" }, "fail-1");
  assert.equal(capability.capability_id, "render.new");
  assert.equal(failed.state, "failed");
});

test("generated TypeScript recovery routes preserve path identity and 201 checkpoint responses", async () => {
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, body: JSON.parse(new TextDecoder().decode(body)) });
    if (path.endsWith("/prepare-reboot")) return { status: 200, headers: {}, body: json({ attempt_id: "a/1", nonce: "n" }) };
    if (path.endsWith("/checkpoint")) return { status: 201, headers: {}, body: json({ checkpoint_id: "c", attempt_id: "a/1" }) };
    throw new Error(`unexpected ${method} ${path}`);
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  const prepared = await client.prepareReboot("a/1", "lease", 3, 7);
  const checkpoint = await client.checkpointAttempt("a/1", "lease", 3, "n", "n", { step: 2 }, 7);
  assert.equal(prepared.attempt_id, "a/1");
  assert.equal(checkpoint.checkpoint_id, "c");
  assert.equal(calls[0].path, "/v1/attempts/a%2F1/prepare-reboot");
  assert.equal(calls[0].body.attempt_id, undefined);
  assert.equal(calls[1].path, "/v1/attempts/a%2F1/checkpoint");
});
