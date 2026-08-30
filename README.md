# Banodoco Workspace Runtime

Independent neutral runtime and protocol repository for the Astrid Stage 1 beta and later REIGH integration.

The repository contains the first independently runnable neutral-runtime slice. It is dependency-free Python and can be exercised without any product checkout or hosted service. The daemon owns one realm's SQLite database, append-only SHA-256 CAS, migrations, task/event ledger, credentials, and loopback HTTP boundary.

## Custody

- Initial branch: `main`
- No remote is configured by the seed operation.
- The Stage 1 oracle worktree is `../banodoco-workspace-runtime-oracle` on `megado/astrid-stage1-beta`.
- The exact Astrid source baseline and frozen roadmap inputs are recorded in the external Phase 0 custody receipt and in the oracle worktree.

## Development boundary

The runtime owns durable structured state, migrations, task/lease semantics, capability registration, append-only CAS accounting, backup/restore, and the language-neutral protocol. Product repositories consume generated clients and never open its database or storage directly.

## Run it

```bash
python3 -m runtime_protocol doctor --root .runtime --json
python3 -m runtime_protocol start --root .runtime
```

`start` prints the loopback endpoint and owner credential path, then keeps the
daemon alive until SIGINT/SIGTERM. The test suite demonstrates the workspace.v1
HTTP boundary, project CRUD, managed object ingest and authenticated byte
reads (`ETag`/`Range`), deterministic worker claim/settlement, restart
reconnect, hash verification, path safety, and sole-owner refusal.

The HTTP binding in this slice is intentionally a small runtime transport
shim used by tests; canonical OpenAPI and generated product bindings belong to
the protocol/conformance lane. No runtime module imports a product checkout.
