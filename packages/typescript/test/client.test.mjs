import test from "node:test";
import { readFileSync } from "node:fs";
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

const preference = JSON.parse(readFileSync(new URL("../../../conformance/fixtures/preferences-user.json", import.meta.url), "utf8"));

test("preference clients preserve user null receipts and committed project receipts", async () => {
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, headers, body: body ? JSON.parse(new TextDecoder().decode(body)) : undefined });
    const data = path.includes("project") ? { ...preference, scope: "project", actor_id: null, project_id: "p /?", document_id: "preferences:project:p /?" } : preference;
    return { status: 200, headers: {}, body: json(method === "GET" ? data : { data, receipt: data.scope === "user" ? null : { receipt_id: "project-commit" } }) };
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  assert.deepEqual(await client.getPreferences("user"), preference);
  const user = await client.updatePreferences("user", preference.content, 0, "write-1");
  assert.equal(user.receipt, null);
  assert.equal(user.content, preference.content);
  assert.deepEqual(calls.at(-1).body, { content: preference.content, expected_version: 0 });
  assert.equal(calls.at(-1).headers["Idempotency-Key"], "write-1");
  assert.equal(calls.at(-1).headers.Authorization, "Bearer token");
  const project = await client.updatePreferences("project", "text", 0, "write-2", "p /?");
  assert.equal(project.receipt.receipt_id, "project-commit");
  assert.equal(calls.at(-1).path, "/v1/preferences/project?project_id=p%20%2F%3F");
  await client.getPreferences("project");
  assert.equal(calls.at(-1).path, "/v1/preferences/project");
});

test("preference clients reject caller ownership and malformed null receipt results", async () => {
  const noTransport = new WorkspaceClient("http://runtime", undefined, async () => { throw new Error("transport called"); });
  await assert.rejects(() => noTransport.getPreferences("user", "p"), /cannot select a project/);
  await assert.rejects(() => noTransport.updatePreferences("user", "text", 0, "key", "p"), /cannot select a project/);
  await assert.rejects(() => noTransport.getPreferences("invalid"), /scope must be/);
  for (const response of [
    { data: preference, receipt: {} },
    { data: preference },
    { data: { ...preference, content: {} }, receipt: null },
    { data: { ...preference, version: true }, receipt: null },
    { data: { ...preference, actor_id: null }, receipt: null },
    { data: { ...preference, project_id: "forged" }, receipt: null },
    { data: { ...preference, document_id: "other" }, receipt: null },
    { data: { ...preference, extra: "value" }, receipt: null },
    { data: preference, receipt: null, extra: "value" },
  ]) {
    const client = new WorkspaceClient("http://runtime", undefined, async () => ({ status: 200, headers: {}, body: json(response) }));
    await assert.rejects(() => client.updatePreferences("user", "text", 0, "key"), /invalid/);
  }
});

test("null preference receipts do not weaken ordinary or project mutation decoding", async () => {
  const data = { ...preference, scope: "project", actor_id: null, project_id: "p", document_id: "preferences:project:p" };
  const client = new WorkspaceClient("http://runtime", undefined, async () => ({ status: 200, headers: {}, body: json({ data, receipt: null }) }));
  await assert.rejects(() => client.updatePreferences("project", "text", 0, "key"), /committed receipt/);
  await assert.rejects(() => client.updateDocument("p", "d", 1, "key", "text"), /committed receipt/);
});

test("document kind filter preserves existing pagination arguments and escapes query values", async () => {
  const client = new WorkspaceClient("http://runtime", undefined, async (method, path) => {
    assert.equal(method, "GET");
    assert.equal(path, "/v1/projects/p%20%2F/documents?limit=5&cursor=next%2Fpage&kind=astrid.note%20%2F%3F");
    return { status: 200, headers: {}, body: json({ items: [], next_cursor: null }) };
  });
  assert.deepEqual(await client.listDocuments("p /", "next/page", 5, "astrid.note /?"), { items: [], next_cursor: null });
});
test("binary client imports forward Blob without materializing its bytes", async () => {
  const blob = new Blob(["media"], { type: "video/mp4" });
  blob.arrayBuffer = async () => { throw new Error("whole file was buffered"); };
  const calls = [];
  const transport = async (method, path, headers, body) => {
    assert.equal(body, blob);
    calls.push(path);
    return { status: 201, headers: {}, body: json({ data: { object_id: "sha256:media" }, receipt: { receipt_id: "receipt" } }) };
  };
  const client = new WorkspaceClient("http://runtime", undefined, transport);
  await client.ingestObject(blob, "video/mp4", "object");
  await client.ingestProjectObject("project", blob, "video/mp4", "project-object");
  await client.importProjectMedia("project", blob, "video/mp4", "media");
  assert.deepEqual(calls, ["/v1/objects", "/v1/projects/project/objects", "/v1/projects/project/media-imports"]);
});

test("default fetch receives Blob directly", async () => {
  const previousFetch = globalThis.fetch;
  const blob = new Blob(["media"], { type: "image/png" });
  blob.arrayBuffer = async () => { throw new Error("whole file was buffered"); };
  globalThis.fetch = async (url, options) => {
    assert.equal(options.body, blob);
    return new Response(json({ data: { object_id: "sha256:media" }, receipt: { receipt_id: "receipt" } }), { status: 201 });
  };
  try {
    await new WorkspaceClient("http://runtime").importProjectMedia("project", blob, "image/png", "media");
  } finally {
    globalThis.fetch = previousFetch;
  }
});
