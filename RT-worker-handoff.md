# RT worker handoff

Implemented the Runtime-owned one-level shot-composition foundation on branch
`otto/shot-composition-unification-20260917`.

Validation run:

- `python3 generators/generate.py --check` — passed.
- `node tools/generate_typescript_conformance.mjs --check --contract contract/openapi/workspace-v1.yaml --schema-manifest contract/manifest.json --component-manifest contract/component-manifest.json --source-root . --fixture-root conformance/fixtures` — passed.
- `PYTHONPATH=. pytest -q tests/test_shot_composition_runtime.py tests/test_runtime_upgrade.py tests/test_t3_foundation_contract.py tests/test_schema_validation.py tests/test_client_parity.py tests/test_typescript_generator.py --disable-warnings --maxfail=1` — 23 passed.
- `python3 -m py_compile runtime_protocol/*.py packages/python/banodoco_workspace_client/generated.py tests/test_shot_composition_runtime.py` — passed.
- `npm test` in `packages/typescript` could not run because `tsc` is not installed in the worktree environment.
- HTTP daemon tests could not run here because the sandbox denies loopback socket bind (`PermissionError: [Errno 1] Operation not permitted`).

The requested commit was attempted with:

```text
git commit -m "Add atomic one-level shot composition publication"
```

Git could not create its worktree index lock because the administrative Git
directory is outside the writable sandbox:
`Operation not permitted: .../.git/worktrees/shot-composition-unification-20260917/index.lock`.
The source and tests remain in this worktree, uncommitted.
