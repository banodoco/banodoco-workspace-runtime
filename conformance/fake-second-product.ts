/** Runnable neutral second-product actor; imports only the generated client. */
import { WorkspaceClient, type Capability, type Executor } from "../packages/typescript/src/generated.js";

const text = new TextEncoder();
const bytes = (value: Uint8Array) => new TextDecoder().decode(value);

const CONTROL_SCOPES = ["projects:read", "projects:write", "objects:read", "objects:write", "tasks:read", "tasks:write"];
const WORKER_SCOPES = ["worker:register", "worker:execute", "tasks:read", "objects:read", "objects:write"];

export async function runSecondProduct(control: WorkspaceClient, execution: WorkspaceClient): Promise<Record<string, unknown>> {
  const steps: string[] = [];
  const health = await control.health();
  if (health.status !== "ok" || health.protocol !== "workspace.v1") throw new Error("health contract failed");
  steps.push("health");
  const session = await control.handshake("neutral-gallery-control", "0.1.0", CONTROL_SCOPES);
  const workerSession = await execution.handshake("neutral-gallery-worker", "0.1.0", WORKER_SCOPES);
  if (!session.actor_id || !session.realm_id || !session.schema_digest || !CONTROL_SCOPES.every((scope) => session.scopes.includes(scope)) || !workerSession.actor_id || !WORKER_SCOPES.every((scope) => workerSession.scopes.includes(scope))) throw new Error("scoped handshake contract failed");
  steps.push("scoped-handshake");

  const project = await control.createProject("Neutral second product", "second-product-project-1");
  const readProject = await control.getProject(project.project_id);
  const projectList = await control.listProjects();
  if (readProject.project_id !== project.project_id || !projectList.items.some((item) => item.project_id === project.project_id)) throw new Error("project CRUD contract failed");
  steps.push("project-create-read-list");

  const source = text.encode("neutral managed bytes");
  const object = await control.ingestProjectObject(project.project_id, source, "application/octet-stream", "second-product-object-1", "neutral.bin");
  const full = await control.getObject(object.object_id);
  const head = await control.headObject(object.object_id);
  const ranged = await control.getObject(object.object_id, [0, 3]);
  if (bytes(full.data) !== bytes(source) || head.status !== 200 || ranged.status !== 206 || bytes(ranged.data) !== bytes(source.slice(0, 4)) || !object.digest || !full.etag || !full.etag.includes(object.digest)) throw new Error("managed object byte contract failed");
  steps.push("managed-object-get-head-range-etag");

  const timelineId = "second-product-timeline-1";
  await control.createTimeline(project.project_id, timelineId, "second-product-timeline-1");
  const listedTimelines = await control.listTimelines(project.project_id);
  const timeline = await control.getTimeline(timelineId);
  const shot = await control.createShot(timelineId, { shot_id: "second-product-shot-1", start_ms: 0, duration_ms: 1000, reference_ids: [] }, "second-product-shot-1");
  const reference = await control.createReference(timelineId, { reference_id: "second-product-reference-1", object_id: object.object_id, role: "source" }, "second-product-reference-1");
  const updatedTimeline = await control.updateTimeline(timelineId, 1, "second-product-timeline-update-1", [shot], [reference]);
  const readShot = await control.getShot("second-product-shot-1");
  const readReference = await control.getReference("second-product-reference-1");
  if (!listedTimelines.items.some((item) => item.timeline_id === timelineId) || timeline.timeline_id !== timelineId || updatedTimeline.version !== 2 || readShot.shot_id !== shot.shot_id || readReference.reference_id !== reference.reference_id) throw new Error("minimum composition contract failed");
  steps.push("timeline-shot-reference-create-read-update");

  const capability: Capability = await execution.registerCapability({ capability_id: "render.neutral", definition_digest: `sha256:${"c".repeat(64)}`, status: "ready", required_resource_keys: ["cpu"], estimated_scratch_bytes: 0, estimated_output_bytes: 1 }, "second-product-capability-1");
  const executor: Executor = { executor_id: "astrid-pack-host", max_concurrency: 1, resource_keys: ["cpu"], capabilities: [capability], protocol: "workspace.v1" };
  await execution.registerExecutor(executor, "second-product-executor-1");
  const capabilities = await control.listCapabilities();
  if (!capabilities.items.some((item) => item.capability_id === capability.capability_id && item.status === "ready")) throw new Error("capability registration contract failed");
  steps.push("register-capability-executor");

  const cancelled = await control.admitTask({ capability_id: capability.capability_id, capability_digest: capability.definition_digest, input_object_ids: [object.object_id], project: project.project_id }, "second-product-cancel-1");
  const cancelResult = await control.cancelTask(cancelled.task_id, "second-product-cancel-action-1", cancelled.version);
  if (cancelResult.state !== "cancelled") throw new Error("cancel transition failed");
  const retried = await control.retryTask(cancelled.task_id, "second-product-retry-1", cancelResult.version);
  if (retried.state !== "queued") throw new Error("retry transition failed");
  steps.push("task-cancel-retry");

  const task = await control.admitTask({ capability_id: capability.capability_id, capability_digest: capability.definition_digest, input_object_ids: [object.object_id], project: project.project_id }, "second-product-render-1");
  const run = await control.getRun(task.run_id);
  const observed = await control.getTask(task.task_id);
  const events = await control.listEvents(undefined, 100, task.task_id);
  if (run.id !== task.run_id || observed.task_id !== task.task_id || events.items.length < 1 || events.items.some((event, index) => index > 0 && event.sequence < events.items[index - 1].sequence)) throw new Error("task run event observation failed");
  steps.push("task-run-events");

  const attempt = await execution.claimTask(executor.executor_id, [capability.capability_id], "second-product-claim-1", health.runtime_epoch);
  if (!attempt || "waiting_reason" in attempt || typeof attempt.attempt_id !== "string") throw new Error("executor claim failed");
  const heartbeat = await execution.heartbeatAttempt(attempt.attempt_id, String(attempt.lease_id), Number(attempt.fence), "second-product-heartbeat-1", health.runtime_epoch);
  if (heartbeat.fence !== attempt.fence) throw new Error("attempt heartbeat fence failed");
  const output = { object_id: "sha256:11bcbcd5fbfa83797a3a527732545ef01ea43db608afa292aa8d58b7b053d3b4", digest: "sha256:11bcbcd5fbfa83797a3a527732545ef01ea43db608afa292aa8d58b7b053d3b4", media_type: "application/octet-stream", filename: "render.bin", size: 21 };
  const settled = await execution.settleAttempt(attempt.attempt_id, { attempt_id: attempt.attempt_id, lease_id: attempt.lease_id, fence: attempt.fence, runtime_epoch: health.runtime_epoch, outputs: [{ name: output.filename, kind: "object", digest: output.digest, media_type: output.media_type, size: output.size, data_base64: "bmV1dHJhbCByZW5kZXIgb3V0cHV0" }] }, "second-product-settle-1");
  if (settled.state !== "succeeded") throw new Error("fenced settlement failed");
  const settledOutput = await execution.getObject(output.object_id);
  if (bytes(settledOutput.data) !== "neutral render output") throw new Error("settled output was not readable from CAS");
  let duplicateRejected = false;
  try { await execution.settleAttempt(attempt.attempt_id, { attempt_id: attempt.attempt_id, lease_id: attempt.lease_id, fence: attempt.fence, runtime_epoch: health.runtime_epoch, outputs: [] }, "second-product-settle-duplicate"); } catch { duplicateRejected = true; }
  if (!duplicateRejected) throw new Error("duplicate settlement was accepted");
  steps.push("claim-heartbeat-fenced-settlement-cas-output");
  return { product: "neutral-gallery", realm_id: session.realm_id, project_id: project.project_id, object_id: object.object_id, task_id: task.task_id, steps };
}

const processLike = globalThis as unknown as { process?: { argv: string[] } };
if (processLike.process?.argv[1]?.endsWith("fake-second-product.js")) {
  const argv = processLike.process.argv;
  const endpoint = argv[argv.indexOf("--endpoint") + 1];
  const token = argv[argv.indexOf("--token") + 1];
  const workerToken = argv[argv.indexOf("--worker-token") + 1];
  if (!endpoint || !token || !workerToken) throw new Error("usage: fake-second-product --endpoint URL --token TOKEN --worker-token TOKEN");
  runSecondProduct(new WorkspaceClient(endpoint, token), new WorkspaceClient(endpoint, workerToken)).then((result) => console.log(JSON.stringify(result))).catch((error) => { console.error(error); (globalThis as any).process.exitCode = 1; });
}
