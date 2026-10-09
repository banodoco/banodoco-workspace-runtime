# I-08 gateway diagnostics result

Gate status: INCOMPLETE. I-08 is not eligible for acceptance.

The bounded Astrid slice was continued in the recorded delivery worktree. It includes the C2 diagnostic projection, total-observation timeout boundary, local/shared redaction, reserved status/setup/auth routes, help migration, and focused public-surface tests. No Runtime, Worker, app, provider, live/GPU, spend, installed qualification, commit, merge, fetch, push, primary-checkout, or destructive operation was performed. No selected production execution is claimed; the I-06 selected-placement gate remains unresolved.

Blocking command and state:

`pytest -q tests/test_gateway_diagnostics_i08.py tests/test_setup_lifecycle_kernel.py tests/test_auth.py tests/test_pack_gateway_routes.py tests/test_pipeline_dispatch_aliases.py tests/v10/test_domain_cli_tasks_runs.py tests/test_skills_package_data.py` returned 1. Result: 81 passed, 25 subtests passed, 1 failed. The failure is `tests/test_gateway_diagnostics_i08.py::test_public_help_auth_and_status_diagnostic_routes`: `main(["tasks", "--help"])` raises `SystemExit(0)` from argparse instead of returning integer 0. The shell command `python -m astrid tasks --help` independently returned 0, but the gateway-call behavior required by the focused test is not complete.

Passing evidence:

- Focused C2 and public checks before the final added task-help assertion: 10 passed, return code 0.
- Recorded I-07 lower-level Astrid matrix: 125 passed, 25 subtests passed, 2 warnings, return code 0.
- C1/C2 raw and canonical verification passed; C1 raw is `b5036e16eab503afd15a4ec5b11cb178a01c6e895016b0545493e93314404783`, canonical is `sha256:658c18bbdeb4f950806dc05ef265c0ffab422cbfd5ce17293fec6145e2f72515`; C2 raw is `1f8b9d99854150bf5a34afcff56758eb40af70adecef5be30933bb40def115ef`, canonical is `sha256:ca251dfbcadc6fbc68a5404495f2f0fd42128c821ce47a3560d2952399278d37`.
- The frozen C2 JSON Schema accepted local and shared diagnostic fixtures; return code 0.
- AST parsing, `py_compile`, and `git diff --check` passed; return code 0.
- Public entry help, product help, setup help, status help, doctor help, auth help, and task help each returned 0 from the shell CLI.
- App contract and C2 fixture tests passed: 21 tests, return code 0.

Known unrelated or environment-limited failures retained from I-07:

- The lower-level preservation probe had 95 passed and 3 failures: isolated VibeComfy unavailable; machine-local Runtime data-root migration guard fired before the unsafe-endpoint assertion; documented I-05 generated-client parity seam for `replace_parent_composition_media`.
- Default Python 3.14 Astrid collection returned 2 because `python-dotenv` was absent; no dependency was installed. The Astrid Python 3.11 virtual environment was used for the passing matrix.
- Real public status and doctor observation returned 1 with valid C2 `runtime_unavailable` diagnostics because the machine-local `banodoco-local` did not expose the delivery Runtime `workspace inspect` command. These outputs were bounded and observer-only.

This packet deliberately does not claim C03-diagnostic or C06 PASS. The next safe action is to correct the gateway help boundary, rerun the focused command above, then refresh this evidence packet and its hashes.
