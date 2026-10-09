# Plan A Runtime composition correction — XHARD implementation brief

Work only in this repository/worktree. Do not touch any primary checkout, other worktree, ref/remote, running service, actual realm, GPU/provider/RunPod path, or Plan B. Do not merge or push. Preserve the existing untracked `evidence/` directory and unrelated work.

The candidate already implements Runtime-owned two-phase local Worker activation. Astra's release review identified the final bounded defect:

1. Installed startup does not assemble `RuntimeDaemon`'s existing all-three-or-none `local_worker_profiles`, `local_worker_preparer`, and `local_worker_inspector` arguments.
2. The prior proof's inspector copied Worker-reported identity. Runtime requires an independent OS/process observation seam and mismatch rejection.

Implement the smallest aligned correction:

- Extend the existing `banodoco_local.bootstrap.SourceProfile` manifest with a single bounded, strictly validated Worker configuration sufficient to identify the installed Worker Python/environment and approved launch/profile metadata. Existing source-profile authority fences remain: the configuration must not override Runtime-derived workspace UUID, realm/support roots, credential paths, Runtime PID, or actual observed process identity. Reject unknown/authority-bearing fields with actionable errors. Keep compatibility for profiles with no Worker configuration only if startup then fails closed/actionably for local Worker launch; do not issue a usable Worker credential through an unverified path.
- Thread the validated configuration through `LocalRuntimeBoundary._argv()` into `runtime_protocol.cli start`, using a bounded manifest/file argument if necessary. Restart must reuse this same path naturally.
- Add one Runtime-owned composition factory. It must build `LocalWorkerProfile`, a cross-interpreter preparer speaking the existing private Worker protocol (`reigh.local-worker-control/v1` / `python -m source.runtime.supervisor --prepared-control-fd` or the exact existing installed entrypoint), and an independent process inspector. Runtime Python is >=3.11; Worker Python is >=3.10,<3.11. Do not import Worker Python implementation into Runtime. Reuse `RuntimeDaemon` all-three-or-none composition and existing issuance/activation ordering. Do not create another supervisor or redesign the public generated schema.
- Configuration/factory validation must not start an engine. Actual start remains the existing owner-only `start-worker` endpoint. Missing or invalid config must fail with actionable diagnostics. If a complete production OS inspector cannot be implemented safely and portably in this bounded correction, implement the shared config/factory and an explicit fail-closed inspector/preflight boundary—never pass through Worker-reported identity as observation and never claim production readiness.

Tests must be focused and deterministic, with no live GPU/actual realm:

- SourceProfile validation and serialization, argv threading, CLI/factory assembly.
- Matching fixture with a separate inspector-owned inventory proving activation occurs before credential enablement.
- At least one independent inventory mismatch (birth identity or listener socket owner) rejected by Runtime, with abort/cleanup and no usable credential.
- The test inspector must not derive its inventory from the Worker report.

Inspect only directly relevant code and package metadata. Implement with `apply_patch`, run focused pytest and package/static checks, and commit only intended product/test files in this candidate. Return a concise summary with commit SHA, changed files, exact commands/results, and any precise remaining bridge. Do not broad-scan.

This is XHARD because the correctness hinges on cross-interpreter private-protocol composition and an independent OS-observation authority boundary; a plausible but circular inspector would be security-invalid even if tests passed.
