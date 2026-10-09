# I-06 — trusted placement issuer and minimum Worker integration

## Correction result — credential-backed placement issuer integration

This is the continuation of the existing `astrid-dirty-main-integration-publish-20260924`
I-06 XHARD task, Plan A only. It does not create a new review or task budget.

The correction closes the credential reuse hazard in the existing Runtime
`CredentialStore`, but I-06/C05-placement remains **blocked at the exact
production issuer boundary** and is not a production PASS. The selected route
still has no authorized producer that obtains actual provider account, pod,
profile, and a stable executor incarnation before Runtime Worker credential
issuance. The current fail-closed Worker gate and Astrid host checks are
retained.

`CredentialStore.provision` now reuses a token only when actor, normalized
scopes, and the complete JSON-safe metadata contract match. A placement or
incarnation change replaces the token and sidecar in place, so the old bearer
cannot inherit the new placement; reconnects for the same executor incarnation
retain the token. The new Runtime test covers this replacement and verifies
that no Runtime attempt/binding state is opened, settled, or reset by the
credential-store operation. `RuntimeDaemon._provision_credentials` was not
given an invented metadata hook: it still has no authoritative selected-route
placement producer to call.

## Disposition

I-06 is a deterministic contract pass with a production qualification gap. The
Plan-A C05-placement disposition is **not a production PASS**: the selected
route has no credential-backed placement issuer for actual account/pod/profile
and executor-incarnation evidence. The gap is now fail-closed and precisely
reported; no fixture-only result is presented as production authority.

The Runtime foundation round-3 corrected overlay remains the dependency
baseline. The Runtime product change in this correction is limited to safe
credential reuse/replacement. The Runtime already
owns the single `execution_request` / `execution_bindings` model, and its
uncertainty, recovery, attempt, lease, epoch, fence, and incarnation semantics
remain unchanged.

## Product changes

The I-06 product changes are limited to the selected Worker/host route:

- `reigh-worker/source/runtime/supervisor.py`: forwards
  `ASTRID_EXECUTION_TARGET_JSON` as a selector so it cannot disappear at the
  Worker boundary, then rejects a targeted Plan-A launch before VibeComfy or
  GenericPackHost spawn when no credential-backed placement issuer is
  available. The selector is explicitly not evidence.
- `reigh-worker/tests/test_worker_composition.py`: deterministic proof that a
  targeted route fails before spawn without a trusted issuer.
- `banodoco-workspace-runtime/runtime_protocol/auth.py`: compares complete
  credential metadata during reuse and replaces credentials when placement or
  incarnation changes; metadata cannot override actor/scopes and must be
  JSON-safe.
- `banodoco-workspace-runtime/tests/test_production_worker_credentials_luna.py`:
  reconnect/replacement coverage for placement metadata, old-bearer invalidation,
  and unchanged Runtime attempt state.
- `Astrid/astrid/core/execution/generic_host.py`: requires the Runtime-issued
  binding to carry `actual_target`, exact `credential_claim` verification with
  a valid evidence digest, and a non-empty executor incarnation; actual target
  identity and selector identity must match. The host consumes this evidence;
  it does not mint it.
- `Astrid/tests/core/execution/test_generic_host_contract.py`: coverage for
  missing, forged, and mismatched placement evidence, while retaining the
  existing binding, storage, lease, and session checks.

The Astrid file and test were already dirty/untracked in the supplied consumer
worktree. Only the I-06 hunk was changed; unrelated user work was preserved.
The complete current-file hashes and custody labels are in
`changed-paths.tsv`.

## Selected Plan-A route trace

1. **Request selector.** Runtime normalizes and persists the request target as
   a selector. A body-supplied execution binding is not accepted as authority.
   `claim_next` selects the prepared Runtime binding only when the requested
   selector matches it.

2. **Credential-backed registration/claim.** The HTTP boundary binds the
   bearer credential to the executor. For a targeted binding, Runtime reads
   placement only from authenticated credential metadata and rejects missing,
   malformed, unverified, or mismatched evidence. The claim persists the
   selected target together with the actual target, verification, and
   incarnation in the one Runtime binding row.

3. **Actual placement evidence and credential retention.** The normal Runtime
   daemon provisions the Worker credential with actor/scopes and the Worker
   discovery profile carries Runtime identity, process, and neutral HC-03
   facts. Neither is an account, pod, profile, or incarnation issuer. The
   corrected `CredentialStore` retains an authorized issuer's envelope in the
   actor sidecar, and the authenticated Runtime identity can then expose that
   metadata to `_trusted_execution_placement`; the store does not create or
   authenticate it. No selected-route producer was found that can populate
   authenticated placement metadata. Direct Runtime tests inject that metadata
   as a fixture only, and the tests/results explicitly do not prove production
   credential issuance.

4. **Worker/host boundary.** The Worker now rejects a non-empty target selector
   before starting a provider-facing VibeComfy session or spawning the host
   when the issuer is absent. If a Runtime claim reaches the Astrid host, the
   host requires and cross-checks the exact verified placement projection before
   opening an execution session. Configuration, environment, startup
   attestation, and executor self-report are not upgraded into evidence.

5. **Settlement and recovery.** Runtime settlement and recovery re-check the
   executor, actual placement, verification, incarnation, attempt, lease,
   epoch, and fence. The stored evidence is carried through the existing
   binding projection; no second binding store, scheduler, policy engine, or
   provider escape hatch was added.

Source anchors for this trace are Runtime
`runtime_protocol/service.py` (`_trusted_execution_placement`, `claim_next`,
`_assert_attempt_identity`), Runtime `runtime_protocol/store.py`
(`normalize_verified_execution_placement`, `execution_placement_matches`,
`bind_execution_attempt`), Worker `source/runtime/supervisor.py`
(`_reject_unissued_execution_target`, `launch_generic_pack_host`), and Astrid
`astrid/core/execution/generic_host.py`
(`_assert_verified_placement_binding`, `_execution_contract`).

## Bypass disposition

| Surface | Disposition |
| --- | --- |
| Request `target` selector | Closed by Runtime selector-to-authenticated-placement matching; selector alone never claims placement. |
| Forged binding in claim body | Rejected by the existing closed claim wire contract; deterministic test retained. |
| Missing/unverified/mismatched credential evidence | Runtime claim waits or rejects closed; host now rejects missing/forged/mismatched evidence before execution. |
| Missing/stale/replayed attempt identity | Existing Runtime attempt/lease/epoch/fence/incarnation checks remain authoritative and passed the focused/full suites. |
| Worker environment/config/startup target attestation | Not evidence. Targeted Worker launch now fails before provider/host spawn when no issuer exists. |
| Worker HC-03 readiness facts and Runtime actor/scopes | Registration/readiness identity only, not placement proof; not used as placement evidence. |
| Astrid target adapter/reconciler and existing RunPod attach surfaces | Observation/fixture surfaces, not wired credential issuers on this selected Worker route; no production claim made. |
| Legacy Supabase/task-table and personal RunPod/watchers | Outside the selected post-cutover Plan-A Runtime → Worker → GenericPackHost capability; not used or qualified. |

## Worker decision and qualification limit

`reigh-worker` **does need a product change**, because the existing Worker
would otherwise permit a selector to cross the launcher boundary without a
credential-backed placement producer. The minimum change is the fail-closed
selector gate plus deterministic coverage above. The neutral Worker remains a
Runtime client/host launcher and does not become a second task authority.

The exact remaining blocker is external authority: a trusted issuer must bind
the actual provider account/pod/profile and stable executor incarnation to the
Runtime-issued Worker credential before `claim_next`, and must make that same
evidence available for host and settlement checks. The current local
credential provisioning surface can provision actor/scoped tokens but does not
issue that placement claim. Production issuance cannot be proven under this
run's no-provider/no-live/no-spend constraints. This is therefore a
qualification boundary, not an architecture invention or a waiver.

## Correction acceptance matrix

| Requirement | Result |
| --- | --- |
| Source-backed trust trace | **Partial / blocker remains.** Runtime trust begins at the bearer credential sidecar and is consumed by `_trusted_execution_placement`; the selected route has no authorized producer for provider account/pod/profile plus incarnation. Selector, environment, readiness, and self-report remain non-authoritative. |
| Deterministic positive production launch/claim path | **Not available.** The existing Runtime claim/binding, Astrid consumer, and settlement identity checks are wired as consumers, but no production credential issuance path can honestly be added within the exact source boundary without inventing an issuer or metadata injection hook. Fixture consumer tests remain clearly labeled as such. |
| Missing authority before provider-facing effects | **Pass.** Worker rejects the targeted launch before VibeComfy/GenericPackHost spawn when no credential-backed issuer exists; Astrid retains exact host validation. |
| Missing/forged/mismatched evidence, selector bypass, stale/replayed identity | **Pass in existing affected suites.** Runtime claim/attempt/lease/epoch/fence/incarnation checks and Worker/Astrid negative coverage remain green. |
| Credential reuse/replacement | **Pass.** Exact metadata match preserves the same token; changed placement/incarnation replaces it and invalidates the old bearer; no attempt/binding row is touched. |
| Existing Runtime semantics / RF-01A | **Pass.** Full Runtime and foundation regressions remain green; no C1/C2 or claim/binding/attempt/recovery/settlement redesign was made. |

The positive production path is therefore intentionally not claimed. The
precise next dependency is the already selected route's authorized upstream
issuer/provisioner, which must return authenticated provider-observed account,
pod, profile, evidence digest, and stable executor incarnation before calling
`_provision_credentials`. No provider, live/GPU infrastructure, spend, or
arbitrary metadata injection was used to fill that gap.

## Checks

- Runtime placement/identity/claim/settlement/security/conformance focused
  tests, including credential reuse/replacement: **50 passed**.
- Full Runtime suite: **474 passed**.
- Worker composition/exit/readiness/profile/session affected suite:
  **78 passed**.
- Astrid execution contract/reconciler/target/epoch/startup affected suite:
  **54 passed**.
- Runtime generator/parity checks: **22 passed**; Python generator and
  TypeScript conformance `--check` commands passed.
- AST parsing of the six relevant I-06 product/test files: passed.
- `git diff --check` passed in Runtime, Worker, and Astrid worktrees.
- Frozen C1 raw SHA-256 is
  `b5036e16eab503afd15a4ec5b11cb178a01c6e895016b0545493e93314404783`; its
  canonical digest remains
  `sha256:658c18bbdeb4f950806dc05ef265c0ffab422cbfd5ce17293fec6145e2f72515`.
- Frozen C2 raw SHA-256 is
  `1f8b9d99854150bf5a34afcff56758eb40af70adecef5be30933bb40def115ef`; its
  canonical digest remains
  `sha256:ca251dfbcadc6fbc68a5404495f2f0fd42128c821ce47a3560d2952399278d37`.
- A full Worker collection was attempted: 628 tests were collected, but
  collection stopped on the pre-existing unrelated missing optional module
  `models.ltx2` in `tests/test_clear_conditioning_byte_identity.py`. Broad
  engine qualification is out of I-06 scope; the affected Worker suite above
  is green.

Correction source hashes:

- `runtime_protocol/auth.py`:
  `9c1886376a85ebfb7f1c0516b83b596e31cfebdd4579d6ae53a2a7eec14c94a8`
- `tests/test_production_worker_credentials_luna.py`:
  `9adf33a825c827722ee4fb4a5688e24064fb2f07e0fdad706b0d8ec04d2a3af7`

No provider was invoked, no live or GPU infrastructure was used, no money was
spent, and no commit, merge, fetch, push, primary-checkout write, or destructive
operation was performed. Product changes remain uncommitted in the delivery
worktrees.
