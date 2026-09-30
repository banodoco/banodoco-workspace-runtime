# R02/R04 local direct-host witness: blocked at the private activation boundary

Date: 2026-09-30. This is a boundary finding, not a composition receipt.
Implementation stopped under the user's instruction to avoid inventing a
missing contract. No runtime, generated operation, host, or H3 source changed.

## Inspected identities

- Runtime worktree: `h3-b3-local-witness-20260930`, initially clean at commit
  `a278cd460018976940ae21fc2cad563a29a29649`, tree
  `41817e38beb837a81ffc3f76bac7c0a756793bd0`.
- Astrid candidate: `h3-full-merge-megado-plan-20260930`, clean at commit
  `ff07c784c08d703d39cae991a01e9e305cde15eb`, tree
  `2ac7f2dea8b685a236c858a7be84be21b58aae6e`.

## Exact missing boundary

GenericHost accepts a grant containing operation/channel identity, credential
path, incarnation, evidence digest, and its actual PID/birth identity. It sends
one `astrid.local-worker-activation-accepted/v1` frame and closes the socket
(`astrid/core/execution/generic_host.py:6324`, especially lines 6394–6410).
There is no accepted-grant receipt or requery on this private channel. Its
ready-file activation identity is published later, after credential gating,
preflight and registration (lines 6592–6718).

Consequently, after losing that ACK frame, an independent OS observer can
verify the same live process, executable/source, group/session and applicable
listener, but cannot establish that this incarnation accepted this grant while
the bearer is still disabled. Recording/enabling from liveness alone would
replace acceptance evidence with an assumption. Enabling first to obtain the
ready marker would reverse the required authority ordering. Adding an
acceptance journal, reconnect/query command, or second activation message
would define a new private contract; none was added.

The existing qualified launcher requires a successful private acknowledgement
before reobservation, recording and enable. An acknowledgement exception takes
the revoke/abort path; it does not recover acceptance
(`runtime_protocol/remote_worker_activation.py:128–257`). This is safe failure
behavior, not the requested successful lost-ACK composition witness.

There is also no existing direct-machine observation shape to simply pass to
that launcher: its validator requires provider-account identity and an
attached child with two lanes (lines 76–117), and activation checks the provider
account against placement (lines 154–155). Those facts cannot be fabricated
for local CPU processes. The installed local alternative launches
`source.runtime.supervisor` and requires four distinct Worker/host/engine/
listener identities and their lineage
(`local_worker_composition.py:193–202`, `local_worker.py:345–403`). It is not a
one-host CPU topology. `host_bootstrap.ensure_pack_host` owns normal startup
and cleanup but neither exposes a parked preparer nor repairs this acceptance
boundary.

## Relevant real HTTP diagnostic

With a disposable production-mode RuntimeDaemon and an explicitly disabled
credential, the existing GenericHost `_await_enabled_runtime_credential`
returned, while a generated-client authenticated handshake failed with
`401 unauthorized`. Its poll calls `RuntimeProtocolClient.health`, which maps
to the public `/v1/health` route (`generic_host.py:2019,6413`,
`runtime_protocol/server.py:42,138`). Health therefore does not prove bearer
enablement. The daemon was stopped in `finally` and the temporary realm
removed. This diagnostic is not a launched host or an ACK-loss witness.

## Checks run without source edits

Runtime, from its selected worktree, using
`/opt/homebrew/opt/python@3.14/bin/python3.14`:

```sh
python3 -m pytest -q tests/test_local_worker_composition.py tests/test_local_worker_placement.py tests/test_remote_worker_activation.py tests/test_remote_activation_http.py tests/test_remote_worker_deployment.py
```

Result: **99 passed**, 6.08 seconds.

Astrid, from its selected candidate:

```sh
/Users/peteromalley/Documents/reigh-workspace/Astrid/.venv/bin/python -m pytest -q tests/core/execution/test_generic_host_activation.py tests/sdk/test_host_bootstrap_source_identity.py tests/packs/h3_av/test_runtime_contract.py
```

Result: **41 passed**, 31.39 seconds; one existing VibeComfy template fallback
PendingDeprecationWarning. Passing fixture tests do not supply the missing
real private acceptance evidence or prove the health gate authenticates.

`git diff --check` passed in both worktrees. Parent-interpreter `__file__`
probes verified that the four inspected Runtime modules originate in the
selected Runtime worktree, and Astrid host_bootstrap, generic_host,
process_group and generated workspace client originate in the selected Astrid
candidate. This checks inspected parent origins only, not all dependencies or
subprocess provenance. No new host composition was launched.

## Required owner handoff and limits

R02/R04 must supply or explicitly define the private boundary for independently
recovering accepted grant identity after ACK loss while still disabled, and
the applicable direct-machine observation/topology. An authenticated existing
operation must establish enablement; public health cannot do so. Existing
Runtime credential/activation/claim/fence/settlement operations and Astrid
process-custody/socket helpers can then be reused without a public operation
or duplicate worker framework.

A real witness cannot yet run through all the requested steps. Waiting-parent/
child capacity and exact cleanup remain unproved as one composition. Runtime
owner approval of the consumed source/private interfaces also remains
outstanding; source identity and these tests are not approval. No RunPod/GPU,
remote-provider, external-orchestrator, main promotion or H3 delivery-contract
change occurred. B3/C4, D14/D15 and live H3 success remain unqualified.
