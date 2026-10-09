# I-07 setup/kernel integration result

## Disposition

I-07 bounded Plan A setup/root/launcher/observer/execution-kernel source work is
complete in the Astrid delivery worktree. This is source/fixture acceptance
only. It does not claim composed selected execution, a production placement
PASS, installed or live qualification, or any provider effect.

Astra's I-06 ruling remains in force: I-06 C05-placement still gates composed
selected execution. The selected route has no authorized producer for actual
provider account, pod/profile, and stable executor-incarnation evidence. I-07
therefore consumes the accepted Runtime authority and the I-06 fail-closed
Worker/Astrid consumers; injected placement remains fixture evidence only.

No Runtime or Worker product source change was required for this bounded
integration. The Runtime worktree already exposes the accepted
workspace create|attach|inspect, up, status, and doctor authority and
the canonical request/binding/attempt contract. No second binding store,
issuer, metadata hook, scheduler, policy engine, compatibility authority, or
generated-client rewrite was added.

## Exact I-07 product paths

The complete non-evidence product/test path manifest is in
changed-paths.tsv. It contains these 11 Astrid paths:

- astrid/core/gateway/__init__.py
- astrid/core/gateway/dispatch.py
- astrid/core/gateway/help.py
- astrid/setup.py
- astrid/runtime_cli.py
- astrid/skills/__init__.py
- astrid/skills/state.py
- tests/sdk/test_rrp_launcher_boundary.py
- tests/test_pipeline_dispatch_aliases.py
- tests/test_skills_package_data.py
- tests/test_setup_lifecycle_kernel.py

The changes are an integration of the existing SL setup/lifecycle owner
surface with the current dirty-main Astrid overlay. The Runtime and Worker
product paths are intentionally absent from the manifest because no source
change was needed.

## Integration decisions

- SetupRequest requires explicit create or attach, one UUID, one absolute
  non-symlink support root, and one absolute non-symlink realm root.
  inspect is read-only and up cannot implicitly create or select a realm.
- One execute_setup core drives preview, strict check, and apply. It reports
  proposed effects and visible stages; only apply composes state and then
  starts Runtime. A failed start retains the configured workspace/choices and
  emits a root-bound retry command.
- Guided input and JSON/flag input normalize through the same request document.
  Omitted target_profile/integrations remain omitted and retain a same-root,
  same-UUID durable selection; an explicit empty integrations array clears that
  retained choice.
- Astrid uses a thin RuntimeCLI facade over the installed
  banodoco-local/astrid-runtime command surface. It validates the exact
  UUID/root/support-root identity before and after lifecycle calls and does not
  own a catalog, store, process supervisor, or second launcher.
- setup and status are reserved gateway routes outside the stable seven
  product-family census. status and doctor use observer-only Runtime
  commands; they do not connect, launch, create support state, start a pack
  host, or invoke execution-side discovery.
- Skill setup selection is persisted beside existing skill state, and sync
  receives the effective retained/requested integrations. Preview uses proposed
  state without writing it. Existing disable/restore behavior remains on the
  same state owner.
- Existing typed Runtime client identity, generated client spelling,
  execution-request selector, Runtime-issued binding, and I-06 exact host
  verification remain the authority. Body-supplied binding authority is not
  introduced and generated outputs are unchanged.

## Acceptance evidence

- I-07 setup/lifecycle kernel tests: 45 passed, 25 subtests, rc 0.
  This covers explicit create/attach, repeat/resume, guided/JSON parity,
  omitted versus explicit-empty choices, preview/check non-starting behavior,
  visible apply/start stages, failed-start retention, observer-only status and
  doctor, exact root identity, launcher boundary, and skill-state retention.
- Astrid affected I-06/I-07 execution and typed-client matrix:
  125 passed, 25 subtests, rc 0.
- Runtime workspace/lifecycle/binding/parity focused matrix:
  41 passed, rc 0.
- Runtime real bootstrap, admission, mutex/identity, workspace, and lifecycle
  regressions: 41 passed, rc 0 (10 known multiprocessing warnings).
- Runtime I-05/I-06 binding, credential, generated-client, schema, and
  conformance regressions: 50 passed, rc 0.
- Runtime generator/parity checks: 23 passed, rc 0; Python generator
  check, TypeScript conformance check, and git diff check passed.
- Worker affected composition/exit/preflight/session/profile matrix:
  78 passed, rc 0.
- Astrid, Runtime, and Worker AST/diff checks passed. The separate lower-level
  Astrid preservation probe passed 95 tests but had three unrelated failures:
  missing isolated vibecomfy import, an existing machine-local Runtime data-root
  migration guard, and the documented I-05 generated-client parity seam
  (replace_parent_composition_media). No I-07 source was changed for those
  failures.
- Frozen contracts are unchanged. C1 raw SHA-256 is
  b5036e16eab503afd15a4ec5b11cb178a01c6e895016b0545493e93314404783 and its
  canonical digest remains
  sha256:658c18bbdeb4f950806dc05ef265c0ffab422cbfd5ce17293fec6145e2f72515.
  C2 raw SHA-256 is
  1f8b9d99854150bf5a34afcff56758eb40af70adecef5be30933bb40def115ef and its
  canonical digest remains
  sha256:ca251dfbcadc6fbc68a5404495f2f0fd42128c821ce47a3560d2952399278d37.

## Limits and preservation

No provider, live/GPU infrastructure, real data, credential authority, spend,
commit, merge, fetch, push, install, primary-checkout write, or destructive
operation was used. The default Python 3.14 Astrid probe could not collect
execution tests because python-dotenv was absent; the existing Astrid 3.11
venv was used instead, without installation.

The lower-level Astrid packs, task execution, output behavior, Runtime
generated clients, and Worker fail-closed behavior were preserved by the
affected regression evidence above. Any positive selected-placement or
composed execution claim remains explicitly deferred to I-06 C05-placement and
later installed/live qualification.

