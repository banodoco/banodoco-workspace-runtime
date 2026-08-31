/** Generated TypeScript client; do not edit by hand.
 *
 * Rendered from the shared component manifest and OpenAPI operation projection.
 */
export const PROTOCOL = "workspace.v1" as const;
export const GENERATOR = "GENERATOR-TYPESCRIPT-CONFORMANCE" as const;
export const COMPONENT_MANIFEST_SHA256 = "4a8d98dab5c674fc52b4f20ff168a1f4b646f71d39078b935285aa25e90eeef9" as const;
export const CONTRACT_SHA256 = "9567a7b8759e18ce28134b1268a11fad1b5cf1ad81078eba4b8fd24041cc19ff" as const;
export const SCHEMA_MANIFEST_SHA256 = "b9802ac560fcd33e3c5c3603b2e92c81bd9f05bebef648e837e81508430393f5" as const;
export const OPERATIONS = ["addShotItem","admitTask","archiveProjectReference","archiveProjectShot","archiveReference","archiveShot","archiveTimeline","associateReference","cancelRun","cancelTask","checkpointAttempt","claimTask","createBackup","createDocument","createGeneration","createMediaRelation","createProject","createProjectReference","createProjectShot","createReference","createShot","createTimeline","createTimelineDocument","createVariant","currentProject","diffTimeline","doctor","exportRealm","failAttempt","getDocument","getGeneration","getObject","getProject","getProjectReference","getProjectShot","getRealm","getReference","getRun","getShot","getTask","getTimeline","getVariant","handshake","headObject","health","heartbeatAttempt","ingestObject","linkReferences","listCapabilities","listDocuments","listEvents","listGenerations","listMediaRelations","listProjectObjects","listProjectReferences","listProjectRuns","listProjectShots","listProjectTasks","listProjects","listRunEvents","listTimelineHistory","listTimelines","listVariants","prepareReboot","purgeRealm","recoverProjectReference","recoverProjectShot","recoverRealm","recoverReference","recoverShot","recoverTimeline","registerCapability","registerExecutor","removeShotItem","reorderShotItems","requestReboot","restoreBackup","resumeAttempt","retryRun","retryTask","selectProject","setPrimaryReference","settleAttempt","tombstoneRealm","updateDocument","updateProject","updateProjectReference","updateProjectShot","updateReference","updateShot","updateTimeline"] as const;
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
