# Banodoco Workspace Runtime

Independent neutral runtime and protocol repository for the Astrid Stage 1 beta and later REIGH integration.

This seed commit intentionally contains scaffolding only. Runtime code, schemas, generated clients, bootstrap, migration, conformance, and release evidence are added through the gated Megado packet graph. The repository must remain independently runnable with the Astrid, REIGH, and Reigh Worker checkouts absent from its import path.

## Custody

- Initial branch: `main`
- No remote is configured by the seed operation.
- The Stage 1 oracle worktree is `../banodoco-workspace-runtime-oracle` on `megado/astrid-stage1-beta`.
- The exact Astrid source baseline and frozen roadmap inputs are recorded in the external Phase 0 custody receipt and in the oracle worktree.

## Development boundary

The runtime owns durable structured state, migrations, task/lease semantics, capability registration, append-only CAS accounting, backup/restore, and the language-neutral protocol. Product repositories consume generated clients and never open its database or storage directly.
