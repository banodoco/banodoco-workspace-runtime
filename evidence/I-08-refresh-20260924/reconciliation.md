# I-08 refresh reconciliation — 2026-09-25

Result: **PASS for the bounded I-08 refresh.** The two named current-main
gateway collisions remain retained by the delivery copies, and the explicitly
expanded `help.py` scope now integrates current-main setup/status census text
with the retained delivery auth/help behavior.

## Scope and custody

- Run: `astrid-dirty-main-integration-publish-20260924`
- Route: `normal` → `worker_normal`; no oracle/reviewer invocation used.
- Product worktree: `/Users/peteromalley/Documents/reigh-workspace/Astrid/.otto/worktrees/astrid-dirty-main-integration-publish-20260924`
- Evidence worktree: `/Users/peteromalley/Documents/reigh-workspace/banodoco-workspace-runtime/.otto/worktrees/astrid-dirty-main-integration-publish-20260924/evidence/I-08-refresh-20260924`
- Primary dirty mains, refs/remotes, prior evidence, Runtime/Worker/provider/GPU/RunPod state were not mutated.
- Product changed path: `Astrid/astrid/core/gateway/help.py` only. New paths are evidence only: `reconciliation.md`, `commands.log`, `primary-fingerprints.tsv`, and `I-08-refresh-result.md`.

## Exact collision disposition

| path | current-main SHA-256 | delivery SHA-256 | disposition |
|---|---|---|---|
| `Astrid/astrid/core/gateway/__init__.py` | `15c9f950cb159fcf14b4ad4320cd7f40b95bdf083540bb698e6f9945f08cbf4e` | `3309803474d7911745505a8d711959a3878ee9b093141fecc374f810b3b4d460` | retain delivery; it includes current-main setup/status routing plus the existing auth and public `SystemExit` boundary |
| `Astrid/astrid/core/gateway/dispatch.py` | `2827f11f50b4391228c2eabd0b149e378895ff51e7e1d01787614bd72d47e88c` | `c15f1f373f66f373e066f4a2a3236ae8ea0f59836a3af502262c4e87f5b7f57f` | retain delivery; it includes current-main dispatch cleanup/setup/status/observer behavior plus C2 collection, redaction, nested help handling, and route cleanup |
| `Astrid/astrid/core/gateway/help.py` | `0e9d1ccffba7cf69513cd127c81891f1ba8f5d7c3df50d022887524378b89dd1` | `89edcae6a10fcdb06aa7b5683801276d835d9ef4b9420cff11c0f502caf75e8e` | integrate current-main setup/status wording and seven-family/reserved-command census with delivery auth/help text; final is the prior I-08 path identity |

The I-02 preserved collision copies agree with these identities:

- `__init__.py.base` `e264e739db9a047d85510f6a6ebba629b5e8772e55288b5014233cd3a29803a1`
- `__init__.py.current-main` `15c9f950cb159fcf14b4ad4320cd7f40b95bdf083540bb698e6f9945f08cbf4e`
- `__init__.py.delivery` `3309803474d7911745505a8d711959a3878ee9b093141fecc374f810b3b4d460`
- `dispatch.py.base` `329caff2fe2b5ceeb1c08031a79874eafc6743ddc28e291e247ced5a271a04ac`
- `dispatch.py.current-main` `2827f11f50b4391228c2eabd0b149e378895ff51e7e1d01787614bd72d47e88c`
- `dispatch.py.delivery` `c15f1f373f66f373e066f4a2a3236ae8ea0f59836a3af502262c4e87f5b7f57f`

## Verification

- Full required I-08 matrix: **PASS**, `82 passed, 25 subtests`, return code 0.
- Diagnostic/observer subset: **PASS**, `11 passed`, return code 0.
- Unaffected I-07 setup/auth/routing matrix: **PASS**, `71 passed, 25
  subtests`, return code 0.
- AST/compile and `git diff --check` for the I-08 paths: **PASS**, return code 0.
- Public entry/help/setup/status/doctor/auth/tasks help commands: each return
  code 0. Real shared `status --diagnostic` and `doctor --diagnostic` return
  code 1 with the expected unavailable local Runtime condition; no-start,
  observer-only behavior remains bounded.

## Scope closure

The explicit help.py expansion is complete and all requested deterministic
checks pass. I-06 placement, I-09 generated-client/reconciliation, and I-10
H3/timeline issues remain held and untouched. No provider, GPU, RunPod, upload,
spend, repair, start, commit, merge, fetch, or push action was used.
