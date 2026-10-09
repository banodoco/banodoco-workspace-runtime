# I-09 refresh result

**PASS — bounded successor-aware generated-client and consumer tuple reconciled.**

Runtime remains the sole contract/generator authority. The canonical Runtime
Python generator/check and TypeScript conformance generator/check pass. The
stale Runtime TypeScript conformance pair was regenerated from the current
OpenAPI/schema/component inputs. Astrid now vendors the byte-identical Runtime
Python generated client and a synchronized metadata tuple, retaining the
Runtime source commit/provenance fields. The app compatibility seam now binds
to Runtime schema digest `sha256:510b40ce55d488347001656014cd07e19c35d1a9e1f810dfc8f5c9fd1a26eae0`.

Acceptance evidence:

- Runtime focused lifecycle/binding/schema/client/generator matrix: **56 passed**.
- Runtime Python generator `--check`: **PASS**.
- Runtime TypeScript conformance `--check`: **PASS**.
- Astrid vendored-client parity gate: **8 passed**; compile check: **PASS**.
- App foundation consumer matrix with `VITE_ASTRID_WORKSPACE_V1=1`: **4 files,
  30 tests passed**.
- App C1/C2 checkers and their deterministic test files: **25 passed**;
  frozen C1/C2 raw identities are unchanged.
- Successor-aware current-root proof: **PASS**. Runtime/Astrid generated
  Python is byte-identical at SHA-256
  `d6206ad8528e56d680c031d5eaa7ba67bcce85f64ec29953dab100e85ce55838`;
  `replaceParentCompositionMedia`/`replace_parent_composition_media` and
  `AttemptFence.run_id`/`run_id: string` are present across the typed tuple.
- `git diff --check`: **PASS** in Runtime, Astrid, app, and Worker delivery
  worktrees.

Changed paths and exact hashes are in [`changed-paths.tsv`](changed-paths.tsv)
and [`source-hashes.tsv`](source-hashes.tsv). Commands and exits are in
[`commands.log`](commands.log). Primary dirty-main fingerprints are preserved
byte-for-byte before/after in [`primary-fingerprints.tsv`](primary-fingerprints.tsv).
The applicability assertions are in
[`successor-applicability.tsv`](successor-applicability.tsv).

Scope and limits:

- No frozen C1/C2 rewrite, second Runtime authority, provider/RunPod/GPU/live
  effect, install, service start, credential/workspace effect, commit, merge,
  fetch, or push was performed.
- I-06’s missing authorized local placement issuer remains an explicit source
  blocker and is not reclassified by this PASS.
- I-08 gateway/help/diagnostic behavior and I-10 H3/timeline implementation
  remain outside this worker’s scope; their prior owner evidence was consumed
  only as the required dependency. The four held H3 tests were not rewritten.
- This is deterministic source-consumer acceptance only; no installed or live
  acceptance is claimed.
