/** Generated TypeScript client; do not edit by hand.
 *
 * Rendered from the shared component manifest and OpenAPI operation projection.
 */
export const PROTOCOL = "workspace.v1" as const;
export const GENERATOR = "GENERATOR-TYPESCRIPT-CONFORMANCE" as const;
export const COMPONENT_MANIFEST_SHA256 = "43db3374e0235750a3d0dd6590926cccba73e6e67de317573f86fd812cbcf082" as const;
export const CONTRACT_SHA256 = "ae5177f64959c27346b7e09fe26ec32cb5c2d42c1645a8d52915e688e9768cc3" as const;
export const SCHEMA_MANIFEST_SHA256 = "ef9b12f20ddcb5a1b5315c4d1180aa702b8a196ab9ba044b89a4564ddfc13d50" as const;
export const SCHEMA_DIGEST = "sha256:21ee7cecb9a230e1dee787db5cb65f5ccf03ccdfb4fcce68e7b062ae1a38e9d6" as const;
export const OPERATIONS = ["addShotItem","admitDelegatedTask","admitTask","adoptManagedOutput","archiveProjectReference","archiveProjectShot","archiveReference","archiveShot","archiveTimeline","associateReference","attachVariantThumbnail","cancelRun","cancelTask","checkpointAttempt","claimTask","controlRemoteCredential","createBackup","createDocument","createGeneration","createMediaRelation","createProject","createProjectReference","createProjectShot","createReference","createShot","createTimeline","createTimelineDocument","createTimelineView","createVariant","currentProject","diffTimeline","doctor","ensureSourceFrameThumbnail","exportManagedOutput","exportRealm","failAttempt","getDocument","getGeneration","getManagedOutput","getObject","getPreferences","getProject","getProjectMediaImport","getProjectObjectLocation","getProjectParentCompositionRevision","getProjectReference","getProjectShot","getProjectShotRevision","getProjectShotTextBinding","getProjectTimeline","getProjectTimelineRevision","getRealm","getReference","getRun","getShot","getSourceFrameThumbnail","getTask","getVariant","handshake","headObject","health","heartbeatAttempt","importProjectMedia","ingestObject","ingestProjectObject","inspectTimeline","issueChildAuthority","linkReferences","listCapabilities","listDocuments","listEvents","listGenerations","listManagedOutputs","listMediaRelations","listProjectObjects","listProjectReferences","listProjectRuns","listProjectShotTextBindings","listProjectShots","listProjectTasks","listProjects","listRunEvents","listTimelineHistory","listTimelines","listVariants","markGenerationVariantsViewed","markVariantViewed","prepareReboot","promoteProjectShotCandidate","publishParentComposition","publishTimelineRender","purgeRealm","rebindProjectShotTextBinding","recordRemoteActivation","recoverProjectReference","recoverProjectShot","recoverRealm","recoverReference","recoverShot","recoverTaskPlacement","recoverTimeline","registerCapability","registerExecutor","removeShotItem","reorderShotItems","replaceParentCompositionMedia","replaceTimelineClip","requestReboot","restoreBackup","resumeAttempt","retryRun","retryTask","revokeRemoteActivation","selectProject","setPrimaryReference","setProjectShotTextBinding","setProjectShotTextBindingById","settleAttempt","tombstoneRealm","updateDocument","updateManagedOutputLifecycle","updatePreferences","updateProject","updateProjectReference","updateProjectShot","updateReference","updateShot","updateTimeline"] as const;
export type HeadersLike = Record<string, string>;
export type Transport = (method: string, path: string, headers: HeadersLike, body?: Uint8Array) => Promise<{ status: number; headers: HeadersLike; body: Uint8Array }>;
export interface ObjectLocation { object_id: string; digest: string; size: number; media_type: string; filename?: string | null; local_path: string; storage: "runtime_cas"; verified: true }
export type ManagedOutputDurability = "durable" | "temporary";
export type ManagedCoverageMode = "interval" | "clips" | "cuts" | "shots";
export interface ManagedOutput {
  association_id: string;
  project_id: string | null;
  run_id: string;
  task_id: string;
  attempt_id: string;
  output_port: string;
  group_key: string;
  variant_key: string;
  selector: { group_key: string; variant_key: string };
  object_id: string;
  digest: string;
  manifest_ref: string | null;
  size: number;
  filename: string;
  media_type: string;
  ordinal: number;
  role: string;
  producer: Record<string, unknown>;
  provenance: Record<string, unknown>;
  durability: ManagedOutputDurability;
  regeneration?: Record<string, unknown> | null;
  coverage?: Record<string, unknown> | null;
  state: string;
  version: number;
  lifecycle: Record<string, unknown>;
  [key: string]: unknown;
}
export interface ManagedOutputPage { items: ManagedOutput[]; next_cursor: string | null; }
export interface ManagedOutputAdoption { association_id?: string; manifest_ref?: string | null; object_id?: string; digest?: string; size?: number; filename?: string; media_type?: string; output_port?: string; selector?: Record<string, unknown>; ordinal?: number; role?: string; durability?: ManagedOutputDurability; }
export interface ManagedOutputLifecycle { operation: "lease" | "release" | "pin" | "unpin" | "expire" | "reclaim" | "promote"; expected_version: number; lease_id?: string; lease_owner?: string; lease_seconds?: number; provenance?: Record<string, unknown>; }
export type PreferenceScope = "user" | "project";
export interface PreferenceResource { scope: PreferenceScope; actor_id: string | null; project_id: string | null; document_id: string; content: string; version: number; created_at: string | null; updated_at: string | null }
export type PreferenceMutationResult = PreferenceResource & { readonly receipt: Record<string, unknown> | null };
export type MutationResult<T> = T & { readonly receipt: Record<string, unknown> };

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public request_id = "", public details: Record<string, unknown> = {}) {
    super(code + ": " + message);
    this.name = "ApiError";
  }
}

export class WorkspaceClient {
  constructor(private readonly baseUrl: string, private readonly token?: string, private readonly transport?: Transport) {}

  supports(operationId: string): boolean { return (OPERATIONS as readonly string[]).includes(operationId); }

    async call(operationId: string, method: string, path: string, body?: Uint8Array, headers: HeadersLike = {}, expected: number[] = [200]): Promise<{ status: number; headers: HeadersLike; body: Uint8Array }> {
    if (!this.supports(operationId)) throw new Error("unknown workspace operation: " + operationId);
    const requestHeaders: HeadersLike = { Accept: "application/json", ...headers };
    if (this.token) requestHeaders.Authorization ??= "Bearer " + this.token;
    let response: { status: number; headers: HeadersLike; body: Uint8Array };
    if (this.transport) response = await this.transport(method, path, requestHeaders, body);
    else {
      const responseObject = await fetch(this.baseUrl.replace(/\/$/, "") + path, { method, headers: requestHeaders, body: body as BodyInit | undefined });
      const responseHeaders: HeadersLike = {};
      responseObject.headers.forEach((value, key) => { responseHeaders[key] = value; });
      response = { status: responseObject.status, headers: responseHeaders, body: new Uint8Array(await responseObject.arrayBuffer()) };
    }
    if (!expected.includes(response.status)) {
      let value: Record<string, unknown> = {};
      try { value = JSON.parse(new TextDecoder().decode(response.body)) as Record<string, unknown>; } catch { /* non-JSON error */ }
      throw new ApiError(response.status, String(value.code ?? "http_error"), String(value.message ?? ("HTTP " + response.status)), String(value.request_id ?? ""), (value.details ?? {}) as Record<string, unknown>);
    }
    return response;
  }

  private json<T>(body: Uint8Array): T { return JSON.parse(new TextDecoder().decode(body)) as T; }
  private page<T>(body: Uint8Array): { items: T[]; next_cursor: string | null } {
    const value = this.json<{ items: T[]; next_cursor: string | null }>(body);
    if (!Array.isArray(value.items) || (value.next_cursor !== null && typeof value.next_cursor !== "string")) throw new Error("invalid page response");
    return value;
  }
  private mutation<T>(body: Uint8Array): MutationResult<T> {
    const value = this.json<{ data?: T; receipt?: Record<string, unknown> }>(body);
    if (!value.data || !value.receipt) throw new Error("invalid mutation response: committed receipt is required");
    return Object.assign(value.data, { receipt: value.receipt }) as MutationResult<T>;
  }
  private preferencesPath(scope: PreferenceScope, projectId?: string): string {
    if (scope !== "user" && scope !== "project") throw new Error("preference scope must be user or project");
    if (scope === "user" && projectId !== undefined) throw new Error("user preferences cannot select a project");
    return "/v1/preferences/" + scope + (projectId !== undefined ? "?project_id=" + encodeURIComponent(projectId) : "");
  }
  private preferenceResource(value: unknown, scope: PreferenceScope): PreferenceResource {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid preference resource");
    const v = value as Record<string, unknown>;
    const fields = ["scope", "actor_id", "project_id", "document_id", "content", "version", "created_at", "updated_at"];
    if (Object.keys(v).length !== fields.length || fields.some(key => !(key in v))) throw new Error("invalid preference resource fields");
    const owner = scope === "user" ? v.actor_id : v.project_id;
    const other = scope === "user" ? v.project_id : v.actor_id;
    if (v.scope !== scope || typeof owner !== "string" || !owner || other !== null || v.document_id !== "preferences:" + scope + ":" + owner || typeof v.content !== "string" || !Number.isInteger(v.version) || (v.version as number) < 0 || [v.created_at, v.updated_at].some(item => item !== null && typeof item !== "string")) throw new Error("invalid preference resource ownership, content or version");
    return v as unknown as PreferenceResource;
  }
  private preferenceMutation(body: Uint8Array, scope: PreferenceScope): PreferenceMutationResult {
    const value = this.json<Record<string, unknown>>(body);
    if (!value || Object.keys(value).length !== 2 || !("data" in value) || !("receipt" in value)) throw new Error("invalid preference mutation response");
    const resource = this.preferenceResource(value.data, scope);
    if (scope === "project") return this.mutation<PreferenceResource>(body);
    if (value.receipt !== null) throw new Error("invalid user preference mutation: null receipt is required");
    Object.defineProperty(resource, "receipt", { value: null, enumerable: false, writable: false });
    return resource as PreferenceMutationResult;
  }
  async getPreferences(scope: PreferenceScope, projectId?: string): Promise<PreferenceResource> {
    return this.preferenceResource(this.json((await this.call("getPreferences", "GET", this.preferencesPath(scope, projectId))).body), scope);
  }
  async updatePreferences(scope: PreferenceScope, content: string, expectedVersion: number, idempotencyKey: string, projectId?: string): Promise<PreferenceMutationResult> {
    const path = this.preferencesPath(scope, projectId);
    return this.preferenceMutation((await this.call("updatePreferences", "PUT", path, new TextEncoder().encode(JSON.stringify({ content, expected_version: expectedVersion })), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body, scope);
  }
  async handshake(clientName: string, clientVersion: string, requestedScopes: string[]): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("handshake", "POST", "/v1/handshake", new TextEncoder().encode(JSON.stringify({ protocol: PROTOCOL, client_name: clientName, client_version: clientVersion, requested_scopes: requestedScopes })), { "Content-Type": "application/json" })).body);
  }
  async createProject(name: string, idempotencyKey: string, slug?: string, metadata?: Record<string, unknown>): Promise<MutationResult<Record<string, unknown>>> {
    const payload: Record<string, unknown> = { name }; if (slug !== undefined) payload.slug = slug; if (metadata !== undefined) payload.metadata = metadata;
    return this.mutation<Record<string, unknown>>((await this.call("createProject", "POST", "/v1/projects", new TextEncoder().encode(JSON.stringify(payload)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body);
  }
  async listManagedOutputs(taskId: string, cursor?: string, limit = 50): Promise<ManagedOutputPage> {
    const query = "?limit=" + limit + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "");
    return this.page<ManagedOutput>(
      (await this.call("listManagedOutputs", "GET", "/v1/tasks/" + encodeURIComponent(taskId) + "/managed-outputs" + query)).body,
    );
  }
  async getManagedOutput(associationId: string): Promise<ManagedOutput> {
    return this.json<ManagedOutput>((await this.call("getManagedOutput", "GET", "/v1/managed-outputs/" + encodeURIComponent(associationId))).body);
  }
  async getProjectObjectLocation(projectId: string, objectId: string): Promise<ObjectLocation> {
    return this.json<ObjectLocation>((await this.call("getProjectObjectLocation", "GET", "/v1/projects/" + encodeURIComponent(projectId) + "/objects/" + encodeURIComponent(objectId) + "/location")).body);
  }
  async adoptManagedOutput(associationId: string, idempotencyKey: string, body: ManagedOutputAdoption = {}): Promise<MutationResult<ManagedOutput>> {
    return this.mutation<ManagedOutput>((await this.call("adoptManagedOutput", "POST", "/v1/managed-outputs/" + encodeURIComponent(associationId) + "/adopt", new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body);
  }
  async updateManagedOutputLifecycle(associationId: string, body: ManagedOutputLifecycle, idempotencyKey: string): Promise<MutationResult<ManagedOutput>> {
    return this.mutation<ManagedOutput>((await this.call("updateManagedOutputLifecycle", "POST", "/v1/managed-outputs/" + encodeURIComponent(associationId) + "/lifecycle", new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body);
  }
  async registerCapability(capability: Record<string, unknown>, idempotencyKey?: string): Promise<Record<string, unknown>> {
    const headers: HeadersLike = { "Content-Type": "application/json" }; if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    return this.json<Record<string, unknown>>((await this.call("registerCapability", "POST", "/v1/capabilities", new TextEncoder().encode(JSON.stringify({ status: "ready", required_resource_keys: [], estimated_scratch_bytes: 0, estimated_output_bytes: 0, ...capability })), headers, [200, 201])).body);
  }
  async failAttempt(attemptId: string, leaseId: string, fence: number, error: unknown, runtimeEpoch: number | string, idempotencyKey?: string): Promise<MutationResult<Record<string, unknown>>> {
    const headers: HeadersLike = { "Content-Type": "application/json" }; if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    return this.mutation<Record<string, unknown>>((await this.call("failAttempt", "POST", "/v1/attempts/" + encodeURIComponent(attemptId) + "/fail", new TextEncoder().encode(JSON.stringify({ lease_id: leaseId, fence, runtime_epoch: runtimeEpoch, error })), headers)).body);
  }
  async prepareReboot(attemptId: string, leaseId: string, fence: number, runtimeEpoch: number): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("prepareReboot", "POST", "/v1/attempts/" + encodeURIComponent(attemptId) + "/prepare-reboot", new TextEncoder().encode(JSON.stringify({ lease_id: leaseId, fence, runtime_epoch: runtimeEpoch })), { "Content-Type": "application/json" })).body);
  }
  async checkpointAttempt(attemptId: string, leaseId: string, fence: number, nonce: string, authorization: string, state: Record<string, unknown>, runtimeEpoch: number): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("checkpointAttempt", "POST", "/v1/attempts/" + encodeURIComponent(attemptId) + "/checkpoint", new TextEncoder().encode(JSON.stringify({ lease_id: leaseId, fence, nonce, authorization, state, runtime_epoch: runtimeEpoch })), { "Content-Type": "application/json" }, [200, 201])).body);
  }
  async publishParentComposition(projectId: string, timelineId: string, publication: Record<string, unknown>, idempotencyKey: string): Promise<MutationResult<Record<string, unknown>>> {
    const payload = { ...publication, project_id: projectId, timeline_id: timelineId };
    return this.mutation<Record<string, unknown>>((await this.call("publishParentComposition", "POST", "/v1/projects/" + encodeURIComponent(projectId) + "/timelines/" + encodeURIComponent(timelineId) + "/composition-revisions", new TextEncoder().encode(JSON.stringify(payload)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body);
  }
  async getProjectShotRevision(projectId: string, shotId: string, revision: string): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("getProjectShotRevision", "GET", "/v1/projects/" + encodeURIComponent(projectId) + "/shots/" + encodeURIComponent(shotId) + "/revisions/" + encodeURIComponent(revision))).body);
  }
  async getProjectTimelineRevision(projectId: string, timelineId: string, revision: string): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("getProjectTimelineRevision", "GET", "/v1/projects/" + encodeURIComponent(projectId) + "/timelines/" + encodeURIComponent(timelineId) + "/revisions/" + encodeURIComponent(revision))).body);
  }
  async listDocuments(projectId: string, cursor?: string, limit = 50, kind?: string): Promise<{ items: Record<string, unknown>[]; next_cursor: string | null }> {
    const query = "?limit=" + limit + (cursor ? "&cursor=" + encodeURIComponent(cursor) : "") + (kind !== undefined ? "&kind=" + encodeURIComponent(kind) : "");
    return this.page<Record<string, unknown>>((await this.call("listDocuments", "GET", "/v1/projects/" + encodeURIComponent(projectId) + "/documents" + query)).body);
  }
  async getProjectTimeline(projectId: string, timelineId: string): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("getProjectTimeline", "GET", "/v1/projects/" + encodeURIComponent(projectId) + "/timelines/" + encodeURIComponent(timelineId))).body);
  }
  async getProjectParentCompositionRevision(projectId: string, timelineId: string, revision: string): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("getProjectParentCompositionRevision", "GET", "/v1/projects/" + encodeURIComponent(projectId) + "/timelines/" + encodeURIComponent(timelineId) + "/composition-revisions/" + encodeURIComponent(revision))).body);
  }
  async inspectTimeline(projectId: string, timelineId: string, options: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("inspectTimeline", "POST", "/v1/projects/" + encodeURIComponent(projectId) + "/timelines/" + encodeURIComponent(timelineId) + "/inspect", new TextEncoder().encode(JSON.stringify(options)), { "Content-Type": "application/json" })).body);
  }
  async createTimelineView(projectId: string, timelineId: string, options: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return this.json<Record<string, unknown>>((await this.call("createTimelineView", "POST", "/v1/projects/" + encodeURIComponent(projectId) + "/timelines/" + encodeURIComponent(timelineId) + "/views", new TextEncoder().encode(JSON.stringify(options)), { "Content-Type": "application/json" })).body);
  }
  async updateTimelineDocument(projectId: string, timelineId: string, expectedVersion: number, idempotencyKey: string, config: Record<string, unknown>, registry: Record<string, unknown>): Promise<MutationResult<Record<string, unknown>>> {
    const body = { expected_version: expectedVersion, content: { config, registry } };
    return this.mutation<Record<string, unknown>>((await this.call("updateDocument", "PATCH", "/v1/projects/" + encodeURIComponent(projectId) + "/documents/timeline%3A" + encodeURIComponent(timelineId), new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body);
  }
}
