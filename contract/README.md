# Workspace protocol contracts

`openapi/workspace-v1.yaml` is the canonical HTTP contract for the neutral
workspace runtime.  The schemas under `schemas/` are the closed JSON Schema
definitions referenced by the OpenAPI document.  They intentionally contain no
Astrid, REIGH, or product-specific types.

The protocol uses a clean, digest-pinned version (`workspace.v1`).  A client
must complete the handshake before using any non-health operation.  Every
state-changing request carries an idempotency key and mutating resources expose
an opaque `version` for optimistic concurrency.
