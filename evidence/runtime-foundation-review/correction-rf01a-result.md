# Runtime foundation correction result — RF-01A

## Result

RF-01A is corrected in the specified Runtime delivery worktree. The boot
recovery predicate now treats a verified external binding with status `claimed`
or `stale` as unresolved provider uncertainty. The cancellation-produced stale
binding therefore takes the existing `provider_state_unknown` preservation
branch before Runtime-owned reconciliation.

The correction is limited to `runtime_protocol/store.py` and directly affected
regressions in `tests/test_execution_binding_contract.py`. It does not alter the
authorized checkpoint resume/reset path, RF-02 request/binding authority, or
Runtime-owned successor reconciliation. No I-06/I-07 work, RF-02 redesign,
C1/C2 rewrite, fetch, merge, commit, push, provider call, live data, GPU/spend
effect, or primary-checkout write was performed. Product changes remain
uncommitted in the candidate worktree.

## Required transition evidence

The new canonical-API regressions cover both:

- task cancellation → Runtime close/reopen → close/reopen again;
- run cancellation → Runtime close/reopen → close/reopen again.

At cancellation and after each boot they inspect durable rows and assert:

- `cancel_requested` and `waiting_reason=provider_state_unknown` remain;
- the same attempt remains `settled=0`, with original attempt/lease/fence/
  executor/runtime-epoch identity retained;
- the single execution binding remains `stale`, with verified actual placement
  and executor incarnation retained;
- the reservation remains unreleased with its original lease token and fence;
- the old settlement is rejected;
- blind claim returns no claim and blind retry requires authorized checkpoint
  resume;
- interruption inspection remains unsafe because the attempt, stale binding,
  and reservation are still blockers;
- recovery events use `recovery=provider_state_unknown` and do not record
  `runtime_owned_attempt_reconciled`.

The existing Runtime-owned recovery regression remains green, including
successor settlement and stale old-settlement rejection.

The two new regressions fail on an isolated copy of the pre-fix predicate with
`2 failed, 14 deselected` because the binding becomes `prepared` after the
first restart. They pass on the corrected candidate.

## Validation

- Focused RF-01/RF-02 suite: `22 passed`.
- Affected I-04 matrix: `105 passed`.
- Affected I-05 matrix: `114 passed`.
- Full Runtime suite: `473 passed, 12 warnings`.
- Python generator `--check`: rc 0.
- TypeScript conformance generator `--check`: rc 0.
- TypeScript package build/tests: `6 passed`, build rc 0.
- Client/schema/contract parity set: `15 passed`.
- Python 3.10 and Python 3.14 syntax compilation: rc 0.
- `git diff --check`: rc 0.

Exact commands, return codes, versions, environmental limits, and the isolated
pre-fix negative receipt are in [`correction-rf01a-commands.log`](correction-rf01a-commands.log).

## Custody and limits

The successor manifest [`correction-rf01a-changed-paths.tsv`](correction-rf01a-changed-paths.tsv)
contains all 45 non-evidence product paths: 43 hashes are unchanged from the
round-2 manifest and two are changed in this correction:

- `runtime_protocol/store.py` — `sha256`:
  `edebe606884fc3a0bc8d388e2f0006ea2fb67f2eff4ca43b4eaa5cf4b4740c21`;
- `tests/test_execution_binding_contract.py` — `sha256`:
  `4f19a6687d9f6aa379f8473ff625a8cba1ae49af90589bf498914d27e2e77841`.

The manifest path set matches the 45 current product paths and all 45 hashes
verify. The prior correction manifest and historical evidence remain intact.

The control evidence identifies the frozen canonical bytes as C1
`sha256:658c18bbdeb4f950806dc05ef265c0ffab422cbfd5ce17293fec6145e2f72515`
and C2
`sha256:ca251dfbcadc6fbc68a5404495f2f0fd42128c821ce47a3560d2952399278d37`.
They were not edited. This receipt makes no C2 diagnostic, installed, provider,
or live acceptance claim. Python 3.10.18 is installed but has no pytest module;
the passing tests used Python 3.14.3. No provider/live data was used.
