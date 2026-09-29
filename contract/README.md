# Workspace protocol contracts

## Timeline shot composition boundary

The separately versioned shot-composition contract in
`schemas/shot-composition.json` is Runtime-owned. It defines publication
identity, exact-head/CAS context, dependencies, occurrences, and the known
shot-payload core. The payload stays open so consumers can preserve opaque app
extensions. Runtime-managed media metadata owns media identity and kind, and
the schema marks `ManagedMediaRegistry` as a Runtime-specific registry.

Nested `TimelineConfig` and clip semantics belong to the pinned
`@banodoco/timeline-schema` package. Runtime materializes that package's JSON
Schema and references it from the parent config and internal-timeline payload;
the shot envelope does not carry a second hand-maintained config definition.
Audio is optional in the shot payload. Nested timeline audio clips/bindings
remain authoritative, and a legacy aggregate descriptor is read-only when
present. Unknown payload fields are preserved by consumers. Visible clip
duration is source duration divided once by positive speed, with parent
occurrence duration acting as a visible interval cap; renderer frame rounding
is checked against the shared vectors.

`openapi/workspace-v1.yaml` is the canonical HTTP contract for the neutral
workspace runtime.  The schemas under `schemas/` are the closed JSON Schema
definitions referenced by the OpenAPI document.  They intentionally contain no
Astrid, REIGH, or product-specific types.

The protocol uses a clean, digest-pinned version (`workspace.v1`).  A client
must complete the handshake before using any non-health operation.  Every
state-changing request carries an idempotency key and mutating resources expose
an opaque `version` for optimistic concurrency.

Task admission may include an immutable `storage_estimate` derived from the
same canonical input snapshot as the task spec. `scratch_bytes` is the peak
additional temporary space needed while the task runs; `output_bytes` is the
maximum final output written before temporary data is released. The runtime
checks their sum against current free space at admission and again at claim.
When the field is absent, the registered capability estimates remain the
backward-compatible fallback.

## Astrid binding

Astrid binds a typed task family, project identity, ordered CAS/input
references, and idempotency key to a Runtime-owned workspace task and run.
Workers claim and settle that work through the Runtime contract. Settlement,
output provenance, receipts, and event history remain Runtime-owned and are
the canonical readback surface for Reigh's gallery and timeline consumers.
Product clients must not bypass this boundary with a direct database client or
legacy task-table fallback.

## Output locations

Runtime owns durable output bytes in the realm CAS at
`cas/sha256/<first-two>/<remaining-digest>`. Attempt scratch and settlement
staging are temporary and are not public result paths. Managed-output rows are
the portable readback identity. An explicit export materializes bytes under
the separately configured export root; the returned `destination.filename` is
the authoritative local filename. If a requested export filename already
exists or is too long for the host's temporary-name byte budget, Runtime keeps
the same root and chooses a deterministic association-scoped direct filename
rather than overwriting it or failing on the private staging sibling.
