/** Generated from contract/openapi/workspace-v1.yaml; do not edit by hand. */
export const PROTOCOL = "workspace.v1" as const;
export type HeadersLike = Record<string, string>;
export type Transport = (method: string, path: string, headers: HeadersLike, body?: Uint8Array) => Promise<{ status: number; headers: HeadersLike; body: Uint8Array }>;
export interface Health { status: "ok" | "degraded"; protocol: typeof PROTOCOL; schema_digest: string; runtime_epoch: number }
export interface Handshake { protocol: typeof PROTOCOL; schema_digest: string; session_id: string; actor_id: string; realm_id: string; scopes: string[] }
export interface Realm { realm_id: string; display_name: string; version: number; created_at: string }
export interface Project { project_id: string; realm_id: string; name: string; version: number; created_at: string; updated_at: string; archived?: boolean }
export interface ManagedObject { object_id: string; digest: string; media_type: string; size: number; version: number; created_at: string; filename?: string }
export interface ByteResponse { data: Uint8Array; status: number; headers: HeadersLike; etag?: string; content_range?: string }
export type TaskState = "queued" | "ready" | "running" | "succeeded" | "failed" | "cancel_requested" | "cancelled" | "retrying";
export interface Task { task_id: string; run_id: string; state: TaskState; version: number; capability_id: string; capability_digest: string; idempotency_key: string; created_at: string; updated_at: string; attempt_id?: string | null }
export interface Event { event_id: string; sequence: number; cursor: string; event_type: string; aggregate_type: string; aggregate_id: string; payload: Record<string, unknown>; occurred_at: string }
export type CapabilityStatus = "ready" | "unavailable" | "unsupported" | "retired";
export interface Capability { capability_id: string; definition_digest: string; status: CapabilityStatus; required_resource_keys: string[]; estimated_scratch_bytes: number; estimated_output_bytes: number; unavailable_reason?: string | null }
export interface Executor { executor_id: string; max_concurrency: number; resource_keys: string[]; capabilities: Capability[]; protocol: typeof PROTOCOL }
export class ApiError extends Error { constructor(public status: number, public code: string, message: string, public request_id = "", public details: Record<string, unknown> = {}) { super(`${code}: ${message}`); this.name = "ApiError" } }

export class WorkspaceClient {
  public handshakeInfo?: Handshake;
  constructor(private readonly baseUrl: string, private readonly token?: string, private readonly transport?: Transport) {}
  private async request(method: string, path: string, body?: Uint8Array, headers: HeadersLike = {}, expected = [200]): Promise<{ status: number; headers: HeadersLike; body: Uint8Array }> {
    const requestHeaders: HeadersLike = { Accept: "application/json", ...headers };
    if (this.token) requestHeaders.Authorization ??= `Bearer ${this.token}`;
    let response: { status: number; headers: HeadersLike; body: Uint8Array };
    if (this.transport) response = await this.transport(method, path, requestHeaders, body);
    else {
      const responseObj = await fetch(`${this.baseUrl.replace(/\/$/, "")}${path}`, { method, headers: requestHeaders, body: body as BodyInit | undefined });
      const bytes = new Uint8Array(await responseObj.arrayBuffer());
      const responseHeaders: HeadersLike = {}; responseObj.headers.forEach((value, key) => { responseHeaders[key] = value });
      response = { status: responseObj.status, headers: responseHeaders, body: bytes };
    }
    if (!expected.includes(response.status)) throw this.decodeError(response.status, response.body);
    return response;
  }
  private decodeError(status: number, body: Uint8Array): ApiError { try { const v = JSON.parse(new TextDecoder().decode(body)); return new ApiError(status, v.code ?? "http_error", v.message ?? `HTTP ${status}`, v.request_id ?? "", v.details ?? {}) } catch { return new ApiError(status, "http_error", `HTTP ${status}`) } }
  private json<T>(body: Uint8Array): T { return JSON.parse(new TextDecoder().decode(body)) as T }
  async health(): Promise<Health> { return this.json<Health>((await this.request("GET", "/v1/health")).body) }
  async handshake(client_name: string, client_version: string, requested_scopes: string[]): Promise<Handshake> { const v = this.json<Handshake>((await this.request("POST", "/v1/handshake", new TextEncoder().encode(JSON.stringify({ protocol: PROTOCOL, client_name, client_version, requested_scopes })), { "Content-Type": "application/json" })).body); this.handshakeInfo = v; return v }
  async getRealm(): Promise<Realm> { return this.json<Realm>((await this.request("GET", "/v1/realm")).body) }
  async createProject(name: string, idempotencyKey: string): Promise<Project> { return this.json<Project>((await this.request("POST", "/v1/projects", new TextEncoder().encode(JSON.stringify({ name })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }
  async getProject(projectId: string): Promise<Project> { return this.json<Project>((await this.request("GET", `/v1/projects/${encodeURIComponent(projectId)}`)).body) }
  async listProjects(cursor?: string, limit = 50): Promise<{ items: Project[]; next_cursor: string | null }> { return this.json((await this.request("GET", `/v1/projects?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`)).body) }
  async createTimeline(projectId: string, timelineId: string, idempotencyKey: string): Promise<Record<string, unknown>> { return this.json((await this.request("POST", `/v1/projects/${encodeURIComponent(projectId)}/timelines`, new TextEncoder().encode(JSON.stringify({ timeline_id: timelineId })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }
  async listTimelines(projectId: string, cursor?: string, limit = 50): Promise<{ items: Record<string, unknown>[]; next_cursor: string | null }> { return this.json((await this.request("GET", `/v1/projects/${encodeURIComponent(projectId)}/timelines?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`)).body) }
  async getTimeline(timelineId: string): Promise<Record<string, unknown>> { return this.json((await this.request("GET", `/v1/timelines/${encodeURIComponent(timelineId)}`)).body) }
  async createShot(timelineId: string, shot: Record<string, unknown>, idempotencyKey: string): Promise<Record<string, unknown>> { return this.json((await this.request("POST", `/v1/timelines/${encodeURIComponent(timelineId)}/shots`, new TextEncoder().encode(JSON.stringify(shot)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }
  async getShot(shotId: string): Promise<Record<string, unknown>> { return this.json((await this.request("GET", `/v1/shots/${encodeURIComponent(shotId)}`)).body) }
  async createReference(timelineId: string, reference: Record<string, unknown>, idempotencyKey: string): Promise<Record<string, unknown>> { return this.json((await this.request("POST", `/v1/timelines/${encodeURIComponent(timelineId)}/references`, new TextEncoder().encode(JSON.stringify(reference)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }
  async getReference(referenceId: string): Promise<Record<string, unknown>> { return this.json((await this.request("GET", `/v1/references/${encodeURIComponent(referenceId)}`)).body) }
  async ingestObject(data: Uint8Array, mediaType: string, idempotencyKey: string, filename?: string): Promise<ManagedObject> { const headers: HeadersLike = { "Content-Type": mediaType, "Idempotency-Key": idempotencyKey }; if (filename) headers["X-Filename"] = filename; return this.json<ManagedObject>((await this.request("POST", "/v1/objects", data, headers, [200, 201])).body) }
  async getObject(objectId: string, byteRange?: [number, number?]): Promise<ByteResponse> { const headers: HeadersLike = {}; if (byteRange) { if (byteRange[0] < 0 || (byteRange[1] !== undefined && byteRange[1] < byteRange[0])) throw new Error("invalid byte range"); headers.Range = `bytes=${byteRange[0]}-${byteRange[1] ?? ""}` } const r = await this.request("GET", `/v1/objects/${encodeURIComponent(objectId)}`, undefined, headers, [200, 206]); return { data: r.body, status: r.status, headers: r.headers, etag: r.headers.ETag ?? r.headers.etag, content_range: r.headers["Content-Range"] ?? r.headers["content-range"] } }
  async headObject(objectId: string, byteRange?: [number, number?]): Promise<ByteResponse> { const headers: HeadersLike = {}; if (byteRange) headers.Range = `bytes=${byteRange[0]}-${byteRange[1] ?? ""}`; const r = await this.request("HEAD", `/v1/objects/${encodeURIComponent(objectId)}`, undefined, headers, [200, 206]); return { data: r.body, status: r.status, headers: r.headers, etag: r.headers.ETag ?? r.headers.etag, content_range: r.headers["Content-Range"] ?? r.headers["content-range"] } }
  async admitTask(input: { capability_id: string; capability_digest: string; input_object_ids: string[]; schema_version?: string; settlement_effect?: Record<string, unknown> }, idempotencyKey: string): Promise<Task> { return this.json<Task>((await this.request("POST", "/v1/tasks", new TextEncoder().encode(JSON.stringify({ schema_version: "1", ...input })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }
  async getTask(taskId: string): Promise<Task> { return this.json<Task>((await this.request("GET", `/v1/tasks/${encodeURIComponent(taskId)}`)).body) }
  async claimTask(executorId: string, capabilityIds: string[], idempotencyKey: string): Promise<Record<string, unknown> | undefined> { const r = await this.request("POST", "/v1/tasks/claim", new TextEncoder().encode(JSON.stringify({ executor_id: executorId, capability_ids: capabilityIds })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 204]); return r.status === 204 ? undefined : this.json(r.body) }
  async cancelTask(taskId: string, idempotencyKey: string, expectedVersion?: number): Promise<Task> { return this.transitionTask(taskId, "cancel", idempotencyKey, expectedVersion) }
  async retryTask(taskId: string, idempotencyKey: string, expectedVersion?: number): Promise<Task> { return this.transitionTask(taskId, "retry", idempotencyKey, expectedVersion) }
  private async transitionTask(taskId: string, action: "cancel" | "retry", idempotencyKey: string, expectedVersion?: number): Promise<Task> { return this.json<Task>((await this.request("POST", `/v1/tasks/${encodeURIComponent(taskId)}/${action}`, new TextEncoder().encode(JSON.stringify(expectedVersion === undefined ? {} : { expected_version: expectedVersion })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }
  async getRun(runId: string): Promise<Record<string, unknown>> { return this.json((await this.request("GET", `/v1/runs/${encodeURIComponent(runId)}`)).body) }
  async listEvents(cursor?: string, limit = 50, aggregateId?: string): Promise<{ items: Event[]; next_cursor: string | null }> { const query = `/v1/events?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}${aggregateId ? `&aggregate_id=${encodeURIComponent(aggregateId)}` : ""}`; return this.json((await this.request("GET", query)).body) }
  async registerExecutor(executor: Executor, idempotencyKey: string): Promise<Executor> { return this.json<Executor>((await this.request("POST", "/v1/executors", new TextEncoder().encode(JSON.stringify(executor)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }
  async listCapabilities(): Promise<Capability[]> { return this.json<{ items: Capability[] }>((await this.request("GET", "/v1/capabilities")).body).items }
  async settleAttempt(attemptId: string, settlement: Record<string, unknown>, idempotencyKey: string): Promise<Task> { return this.json<Task>((await this.request("POST", `/v1/attempts/${encodeURIComponent(attemptId)}/settle`, new TextEncoder().encode(JSON.stringify(settlement)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }
  async heartbeatAttempt(attemptId: string, leaseId: string, fence: number, idempotencyKey: string): Promise<Record<string, unknown>> { return this.json((await this.request("POST", `/v1/attempts/${encodeURIComponent(attemptId)}/heartbeat`, new TextEncoder().encode(JSON.stringify({ lease_id: leaseId, fence })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }
}
