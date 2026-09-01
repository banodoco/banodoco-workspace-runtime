# Astrid B12 operator runbook

This runbook is explicit: choose one source and one selected neutral realm.
These commands never guess a source, stop a process by name, combine project
trees, or delete source data.

## Preflight and dry run

Use a fresh archive/destination parent on a volume with enough capacity for
source, archive, active backup, destination, signed destination backup,
rollback copy, activation temporary, CAS, evidence, and the safety margin.
Compact redundancy is the default; use `--redundancy extreme` only when the
historical full-copy allocation is explicitly required. Run the offline dry
run first:

```bash
PYTHONPATH=/path/to/runtime python -m tools.astrid_migrate \
  --source-root /absolute/source \
  --archive-root /absolute/migration/source-archive \
  --destination-root /absolute/migration/destination --dry-run
```

The source must explicitly contain `.astrid/astrid.sqlite3` or a root-level
`astrid.sqlite3`; nested databases are not inferred.

## Bind authorizations

```bash
astrid-live-migrate issue-authorizations \
  --source-root /absolute/source \
  --archive-root /absolute/migration/source-archive \
  --destination-root /absolute/migration/destination \
  --realm-id REALM_ID --output /absolute/operator/b12-authorizations.json
```

The output is owner-only and contains exactly the six B12 authorization IDs:

```text
AUTH-LIVE-INPUT-B12
AUTH-WRITER-STOP-B12
AUTH-LIVE-MIGRATION-B12
AUTH-ACTIVATION-B12
AUTH-ROLLBACK-B12
AUTH-REACTIVATION-B12
```

## Stop writers

Stop the actual Astrid/editor/bridge writers with the host supervisor. Do not
delete a stale-looking lock. After confirming no writer remains, write a
receipt containing the exact source root:

```json
{"format_version":1,"source_root":"/absolute/source","stopped":true,"writer_count":0,"method":"named-supervisor-or-manual-audit"}
```

The live command re-reads this receipt and probes all known source locks. A
missing/changed receipt, held lock, or nonzero writer count fails closed.

## Run B12

The neutral support catalog must already select `REALM_ID`, point to the
explicit active root, and contain owner-only `activation-trust.json`.

```bash
astrid-live-migrate live-migrate --confirm 'MIGRATE LIVE ASTRID' \
  --source-root /absolute/source \
  --active-root /absolute/Banodoco/runtime/realms/REALM_ID \
  --support-root /absolute/Banodoco/runtime \
  --archive-root /absolute/migration/source-archive \
  --destination-root /absolute/migration/destination \
  --evidence-root /absolute/migration/migration-evidence-b12 \
  --realm-id REALM_ID \
  --authorization-file /absolute/operator/b12-authorizations.json \
  --writer-stop-receipt /absolute/operator/writer-stop.json \
  --redundancy compact
```

This invokes serialized B12: verified backups, import, reconciliation,
activation, rollback, reactivation, and JSON evidence. Derived siblings are
`<archive>-live-pre-migration-backup`, `-live-destination-backup`, and
`-live-rollback` in compact mode. Compact activates and reactivates directly
from the verified signed destination backup through an activation temporary;
it does not create `-live-candidate` or `-live-reactivated`. The explicit
`--redundancy extreme` mode additionally creates those two historical restore
trees. The terminal receipt is `activated-destination-b12.json` with journal
state `reactivated`.

## Nested intro source

Only use this with the exact identified nested database. It clones and rewrites
known media locators in the clone; it never edits source data:

```bash
astrid-live-migrate normalize-nested-source \
  --source-root /absolute/Astrid/projects/astrid-intro \
  --database /absolute/Astrid/projects/astrid-intro/.astrid/source-projects-root-kernel/astrid.sqlite3 \
  --destination-root /absolute/migration/astrid-intro-normalized
```

Review `normalization-manifest.json`, then dry-run against the normalized root.
