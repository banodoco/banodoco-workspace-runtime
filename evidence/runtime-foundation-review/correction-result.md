# Runtime foundation correction result — RF-01 / RF-02

## Result

RF-01 and RF-02 are corrected in the Runtime delivery worktree. The adopted Plan A authority model is preserved; no I-06/I-07 work, provider/live qualification, C1/C2 rewrite, fetch, merge, commit, push, or primary-checkout write was performed.

### RF-01

- Runtime-owned recovery now terminally reconciles the superseded attempt row (`attempts.settled=1`) inside the same recovery transaction before the task is requeued. The attempt row, lease/fence identity, and event chain remain durable, so the old settlement is still fenced.
- `task.runtime_recovered` records the recovered `attempt_id` and `recovery_disposition=runtime_owned_attempt_reconciled`.
- The same closure is applied to Runtime-owned lease-expiry requeue and non-external cancellation paths so they cannot strand an unreachable lifecycle blocker.
- Verified external placement remains the opposite path: `provider_state_unknown`, unsettled attempt, stale binding/reservations, blind claim/retry refusal, and lifecycle blocking until authorized checkpoint reconciliation.

### RF-02

- New run/task `spec_json` stores no `execution_request`; `tasks.execution_request_json` is the sole durable request authority.
- Public task and attempt specs remove the request from `spec`; the request is exposed only as the top-level contract field.
- Creation request hashing and existing-row replay comparison include the normalized first-class request explicitly. Identical normalized replay returns the original task/binding; a mismatched request conflicts.
- The single Runtime-created `execution_bindings` row remains the binding authority.

Bounded legacy compatibility is read-only and limited to an inventoried pre-correction row whose outer runtime `spec_json` contains `execution_request` while `tasks.execution_request_json` is null. The reader normalizes that value, gives precedence to a non-null first-class column, strips it from public specs, and uses it only for old-row claim/replay comparison. New writes never recreate this shape, and no nested request inside the product `spec` is accepted.

## Acceptance evidence

- Focused RF-01/RF-02 regressions: 19 passed.
- Corrected affected I-04 matrix: 102 passed.
- Corrected affected I-05 matrix: 111 passed.
- Full Runtime suite: 470 passed, 12 warnings.
- TypeScript package build/tests: 6 passed.
- Python generator `--check`: rc 0.
- TypeScript conformance generator `--check`: rc 0.
- Client/schema parity and contract fixture tests: included in the 111-test I-05 matrix and passed.
- `git diff --check`: rc 0.
- Changed-path manifest: 45 product paths, all SHA-256-verified; evidence files are not included in that product-path custody manifest.

The Runtime-required Python 3.10 interpreter is present but has no pytest module (`python3.10 -m pytest` rc 1 before collection). Tests therefore ran with the available Python 3.14.3 and `PYTHONPATH=.:packages/python`; `python3.10 -m py_compile` passed. Exact commands and return codes are in [`correction-commands.log`](correction-commands.log), and hashes are in [`correction-changed-paths.tsv`](correction-changed-paths.tsv).

Frozen C1/C2 bytes were not edited. This result makes no C2 installed/live acceptance claim; the existing expected C2 source/generated applicability handoff remains for I-09.
