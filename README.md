# Banodoco Workspace Runtime

Independent neutral runtime and protocol repository for the Astrid Stage 1 beta and later REIGH integration.

The repository contains the first independently runnable neutral-runtime slice. It is dependency-free Python and can be exercised without any product checkout or hosted service. The daemon owns one realm's canonical SQLite database, append-only SHA-256 CAS, task/event ledger, credentials, and loopback HTTP boundary. Realm creation is explicit; startup and doctor never migrate or repair an existing root.

## Custody

- Initial branch: `main`
- No remote is configured by the seed operation.
- The Stage 1 oracle worktree is `../banodoco-workspace-runtime-oracle` on `megado/astrid-stage1-beta`.
- The exact Astrid source baseline and frozen roadmap inputs are recorded in the external Phase 0 custody receipt and in the oracle worktree.

## Development boundary

The runtime owns durable structured state, task/lease semantics, capability registration, append-only CAS accounting, verified backup/restore/replacement, and the language-neutral protocol. Product repositories consume generated clients and never open its database or storage directly.

## Run it

The local launcher accepts an absolute `--data-root` support directory on
lifecycle commands, or `BANODOCO_LOCAL_DATA_ROOT`. This directory directly
contains the installation's `runtime/` and `credentials/` trees.
`banodoco-local relocate --data-root /old/support --destination /new/support --plan`
previews a same-filesystem move of that complete support tree. Execution uses
`--confirm "RELOCATE <realm-id>"`, verifies the owner before stopping it,
cold-starts at the new location, and restores the old tree if cutover fails.
The optional backup path is recorded in the plan; relocation does not perform
a backup/restore or migrate a legacy realm.

Local consumers can resolve a project object through
`get_project_object_location(project_id, object_id)` in Python or
`getProjectObjectLocation(projectId, objectId)` in TypeScript. The authenticated
lookup verifies ownership, size, and SHA-256 bytes before returning the current
CAS path. Paths are valid for the local runtime host at lookup time; task and
managed-output receipts remain portable and do not embed them.

```bash
python3 -m runtime_protocol doctor --root .runtime --json
python3 -m runtime_protocol create --root .runtime
python3 -m runtime_protocol start --root .runtime
```

Backups are verified before publication into a new inactive sibling. Replacement
requires support custody outside the movable realm root; the default in-root
`root/support` layout remains valid for ordinary startup but is rejected before
replacement moves. Use one stable sibling support directory for the daemon,
backup authentication key, credentials, epoch floor, and catalog:

```bash
python3 -m runtime_protocol create --root ./runtime-realm
python3 -m runtime_protocol start --root ./runtime-realm --support-root ./runtime-support
# Stop the daemon before using the offline CLI backup command.
python3 -m runtime_protocol backup --root ./runtime-realm \
  --support-root ./runtime-support --destination ./realm-backup
python3 -m runtime_protocol replace --root ./runtime-realm \
  --support-root ./runtime-support --backup ./realm-backup
```

The `backup` command is the durable backup operation. Upgrades use a temporary
same-filesystem rollback copy and remove it after success or successful
rollback; an upgrade failure that cannot roll back reports the retained recovery
path. To keep a pre-upgrade snapshot intentionally, add `--retain-backup`;
`--archive-root` is accepted only with that flag. The launcher's automatic
upgrade path never opts in.

Replacement keeps the old realm available until the new owner passes admission,
then removes it by default. Add `--retain-superseded` to `replace` when you
explicitly want a retained copy. The authenticated `v1/replace` request accepts
the same opt-in as `retain_superseded: true`. A failed rollback preserves both
recovery roots and reports their paths. Replacement still rotates owner
credentials and advances the Runtime epoch before publishing readiness.

Do not create full-realm copies before routine start, reconnect, repair, or
migration. Runtime transaction staging is temporary and operation-owned;
durable copies are created only by an explicit user backup request.

`start` prints the loopback endpoint and owner credential path, then keeps the
daemon alive until SIGINT/SIGTERM. The test suite demonstrates the workspace.v1
HTTP boundary, project CRUD, managed object ingest and authenticated byte
reads (`ETag`/`Range`), deterministic worker claim/settlement, restart
reconnect, hash verification, path safety, and sole-owner refusal.

The HTTP binding in this slice is the canonical Stage 1 runtime transport
boundary used by the daemon and product integrations. OpenAPI and generated
product bindings consume this same protocol contract in the
protocol/conformance lane. No runtime module imports a product checkout.
