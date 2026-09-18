# RT worker handoff — review round 3 final completion

The Runtime foundation final completion pass was applied in the delivery
worktree on branch `otto/shot-composition-unification-20260917`, starting from
candidate `9f516f4`. The host should commit these worktree changes after the
independent final review.

Closed findings:

- Occurrence-only linked reuse now resolves the complete committed shot row,
  verifies its stored internal timeline revision row and payload, and includes
  recursive child/internal media in the final closure. Dependency rows and the
  returned manifest are built from that resolved set. A regression covers a
  publication omitting both `shot_revisions` and
  `internal_timeline_revisions`.
- `composition_revision_occurrences` now persists authored `ordinal` values.
  Canonical schema shape, required columns, publication inserts, and revision
  integrity checks are updated. Integrity compares the exact occurrence
  sequence and all authored fields; order and identity tampering are unhealthy.
- The product TypeScript client now exposes every declared OpenAPI operation,
  including `getProjectTimeline`, `replaceTimelineClip`, and
  `publishTimelineRender`. The timeline document helper uses the project-
  scoped read.
- The old unscoped `GET /v1/timelines/{timeline_id}` was removed from
  OpenAPI, server routing, generated Python/TypeScript clients, operation
  metadata, and the neutral conformance actor. The project-scoped timeline
  read is the only public timeline/head read.

Validation run:

- `python3 generators/generate.py --check` — passed.
- `node tools/generate_typescript_conformance.mjs --check --contract contract/openapi/workspace-v1.yaml --schema-manifest contract/manifest.json --component-manifest contract/component-manifest.json --source-root . --fixture-root conformance/fixtures` — passed.
- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. pytest -q tests/test_shot_composition_runtime.py tests/test_runtime_upgrade.py tests/test_t3_foundation_contract.py tests/test_schema_validation.py tests/test_client_parity.py tests/test_typescript_generator.py --disable-warnings --maxfail=1` — 28 passed.
- `PYTHONDONTWRITEBYTECODE=1 python3 -B -c 'import ast; ...'` — syntax parsed for the five requested Runtime Python modules.
- `git diff --check` — passed.

The TypeScript package has no installed `node_modules` in this worktree, so its
`npm test` build was not available; the requested generator/conformance check
does not require that dependency. No commit was created.
