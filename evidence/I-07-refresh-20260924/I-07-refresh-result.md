# I-07 refresh result — current-main setup/kernel reconciliation

## Disposition

**PASS for the bounded I-07 setup/root/launcher/observer kernel refresh, with
four I-09 consumer collisions still held.** No product source edit was needed:
the Astrid delivery worktree already contains the smallest source-backed merge
of the two I-07-owned inputs. This does not complete I-09, source integration,
installed qualification, composed selected execution, or Plan A.

I-06 remains `BLOCKED_IMPLEMENTATION` for C05-placement at the missing local
owner/launch-to-credential issuance seam. The Worker remains fail closed; no
injected placement fixture is described as production authority.

## Six collision dispositions

The byte-preserved I-02 `current-main` and `delivery` copies were used as the
inputs. Exact hashes and owners are in `collision-dispositions.tsv`.

1. `astrid/runtime_cli.py` — **integrated / retained delivery**. Ignoring
   formatting, the delivery file is current-main plus the bounded timeout
   parameter, `TimeoutExpired` mapping, and five-second observer default. It
   preserves the thin installed Runtime facade, exact root/UUID validation,
   nonstarting observation, and no independent catalog/process authority.
2. `tests/test_setup_lifecycle_kernel.py` — **integrated / retained delivery**.
   The current-main/delivery diff contains formatting-only changes (including
   whitespace inside the subprocess test literal), with no assertion or setup
   behavior removed. The final delivery test covers create/attach, omitted
   versus explicit-empty choices, guided/JSON parity, preview/check no-write,
   visible apply/start/failure, failed-start retention, root identity, and
   observer-only status.
3. `tests/packs/h3_av/test_compile.py` — **still held for I-09**, with its
   I-10 H3 product dependency preserved side-by-side.
4. `tests/packs/h3_av/test_compile_generalized.py` — **still held for I-09**,
   with its I-10 H3 product dependency preserved side-by-side.
5. `tests/packs/h3_av/test_managed_asset_staging.py` — **still held for I-09**,
   with its I-10 H3 product dependency preserved side-by-side.
6. `tests/packs/h3_av/test_runtime_contract.py` — **still held for I-09**,
   with its I-10 H3 product dependency preserved side-by-side.

The four H3 tests were not selected because their current-main assertions rely
on separately held I-10-owned H3 implementation collisions, including
`astrid/packs/h3_av/src/compile.py` and the transform orchestrator. Selecting
only a test side here would silently decide I-10 behavior. Both I-02 byte copies
remain unchanged for the named owner.

## Current client and shared-file boundary

The already-replayed setup, gateway, SDK and vendored-client surfaces were
inspected without selecting another owner's files. Gateway/help drift remains
I-08-owned. The current Runtime Python generator is internally clean, but the
current cross-root Runtime/Astrid client tuple is not coherent and remains
I-09-owned:

- Runtime generated Python: schema digest `sha256:510b40ce…1a26eae0`, includes
  `replaceParentCompositionMedia`, and includes `AttemptFence.run_id`.
- Astrid vendored Python: schema digest `sha256:904574dd…7479e4f8`, omits that
  operation from `OPERATIONS`, omits `AttemptFence.run_id`, yet still exposes
  the typed `replace_parent_composition_media` method.
- Runtime Python generation `--check` passes; Runtime TypeScript conformance
  `--check` fails on the two held `clients/typescript` generated artifacts.

Those are exact I-09 successor/client inputs, not authority for I-07 to rewrite
Runtime generated outputs, Astrid's vendored SDK, or shared dispatch. No body-
supplied binding authority or second binding store was introduced.

## Deterministic evidence

- Astrid I-06/I-07 setup, launcher, execution and identity matrix: **125 passed,
  25 subtests**, return code 0.
- Worker affected composition/preflight/session/profile matrix: **78 passed**,
  return code 0.
- Runtime lifecycle/binding/schema/client matrix: **54 passed, 2 failed**. Both
  failures are the held I-09 TypeScript conformance artifacts.
- Astrid vendored-client/handshake/host selection: **46 passed, 2 failed**. One
  is the held I-09 operation-catalog mismatch; the other is the pre-existing
  machine-local data-root guard firing before the unsafe-endpoint assertion.
- I-08/H3 diagnostic run: **25 passed, 7 failed**. One failure is I-08 help text;
  six are the already recorded I-10 H3 packaged-mask/resource failures. No H3
  source was changed or live GPU/provider path invoked.
- `git diff --check` passed in all four delivery worktrees.
- Frozen C1 raw/canonical hashes remain
  `b5036e16…4404783` / `sha256:658c18bb…f72515`; C2 remains
  `1f8b9d99…115ef` / `sha256:ca251dfb…9278d37`.
- The six current primary Astrid collision bytes still match the I-02
  `current-main` copies. All four primary HEAD/status/diff/untracked
  fingerprints were unchanged between this worker's pre-evidence and final
  checks; see `primary-fingerprints.tsv`.

Exact commands, versions, exits and limitations are in `commands.log`.
`changed-paths.tsv` records that no product source changed.

## Prior evidence applicability and limits

The prior I-07 evidence remains applicable to explicit setup, retained choices,
preview/check/apply stages, failed-start retention, exact root/launcher
identity, observer-only behavior, and the fail-closed execution consumer; these
were re-run on the refreshed delivery tuple. Its old generated-client parity
claim is not current proof and is superseded by the held I-09 mismatch above.
The prior H3 results remain historical only until I-09/I-10 select their paired
test/product inputs.

No primary checkout, prior evidence, ref, remote, provider, RunPod, GPU, live
data, real workspace, credential, service, dependency installation, commit,
merge, fetch, push, or deployment was mutated. Only this new evidence directory
was written in the Runtime delivery worktree.
