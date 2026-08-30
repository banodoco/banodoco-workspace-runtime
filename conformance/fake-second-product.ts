/** Conformance actor imports only the generated neutral client. */
import { WorkspaceClient, type Executor, type Capability } from "../packages/typescript/src/generated.js";

export async function runSecondProduct(client: WorkspaceClient): Promise<string> {
  const session = await client.handshake("neutral-gallery", "0.1.0", ["realm:read", "project:write"]);
  const project = await client.createProject("Neutral project", "project-neutral-1");
  const object = await client.ingestObject(new TextEncoder().encode("data"), "application/octet-stream", "object-neutral-1", "clip.bin");
  const capabilities: Capability[] = await client.listCapabilities();
  const render = capabilities.find((capability) => capability.capability_id === "render.basic");
  if (!render) throw new Error("render.basic is not registered");
  const executor: Executor = { executor_id: "neutral-executor", max_concurrency: 1, resource_keys: ["cpu"], capabilities: [render], protocol: "workspace.v1" };
  await client.registerExecutor(executor, "executor-neutral-1");
  const task = await client.admitTask({ capability_id: render.capability_id, capability_digest: render.definition_digest, input_object_ids: [object.object_id] }, "task-neutral-1");
  await client.listEvents(undefined, 50, task.task_id);
  return `${session.realm_id}:${project.project_id}:${object.object_id}`;
}
