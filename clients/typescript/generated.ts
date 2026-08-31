/** Generated TypeScript client; do not edit by hand.
 *
 * Rendered from the shared component manifest and OpenAPI operation projection.
 */
export const PROTOCOL = "workspace.v1" as const;
export const GENERATOR = "GENERATOR-TYPESCRIPT-CONFORMANCE" as const;
export const COMPONENT_MANIFEST_SHA256 = "a3cdf22214af24b6a5b9482015bbef90196f969c67e6da3f47547ad1e5cc7ea2" as const;
export const CONTRACT_SHA256 = "fb68900a091d417d59b3ee9d5015d529c3a934159765b7be9ddbfaa78048209f" as const;
export const SCHEMA_MANIFEST_SHA256 = "b9802ac560fcd33e3c5c3603b2e92c81bd9f05bebef648e837e81508430393f5" as const;
export const OPERATIONS = ["admitTask","archiveReference","archiveShot","archiveTimeline","cancelRun","cancelTask","checkpointAttempt","claimTask","createBackup","createDocument","createGeneration","createMediaRelation","createProject","createReference","createShot","createTimeline","createVariant","diffTimeline","doctor","exportRealm","failAttempt","getDocument","getGeneration","getObject","getProject","getRealm","getReference","getRun","getShot","getTask","getTimeline","getVariant","handshake","headObject","health","heartbeatAttempt","ingestObject","listCapabilities","listDocuments","listEvents","listGenerations","listMediaRelations","listProjectObjects","listProjectReferences","listProjectRuns","listProjectShots","listProjectTasks","listProjects","listRunEvents","listTimelineHistory","listTimelines","listVariants","prepareReboot","purgeRealm","recoverRealm","recoverReference","recoverShot","recoverTimeline","registerCapability","registerExecutor","requestReboot","restoreBackup","resumeAttempt","retryRun","retryTask","settleAttempt","tombstoneRealm","updateDocument","updateProject","updateReference","updateShot","updateTimeline"] as const;
export type HeadersLike = Record<string, string>;
export type Transport = (method: string, path: string, headers: HeadersLike, body?: Uint8Array) => Promise<{ status: number; headers: HeadersLike; body: Uint8Array }>;

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
}
