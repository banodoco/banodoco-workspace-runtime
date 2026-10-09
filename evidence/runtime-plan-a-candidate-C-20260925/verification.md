# Runtime Plan A candidate C verification — 2026-09-25

## Identity

- Candidate: `/Users/peteromalley/Documents/reigh-workspace/banodoco-workspace-runtime/.otto/worktrees/astrid-dirty-main-candidate-C-20260925`
- Detached base HEAD: `60e3efdbb9591c25c113402136bfb31b7dfcc4c4`
- Primary and delivery worktrees were treated as read-only sources.
- Product selection: 51 paths; every selected byte matches the reviewed Runtime delivery source.
- The candidate is intentionally uncommitted and detached so it remains a verification overlay at the requested base.

## Selection and reconciliation

The product set is the union of the 45-path Runtime foundation round-3 manifest and the six later I-06 additions, with the I-09 generated-client successor bytes and I-11 packaging input retained. I-06 source-integration round 3 reviewed the issuer/protocol path; I-11 bound the Runtime source tuple to the sealed wheel/sdist; I-12 requires primary custody and no actual-root mutation.

Of the 26 primary product paths overlapping this candidate, 8 are byte-identical to the candidate and 18 retain distinct current-main bytes. The distinct bytes were not overwritten or deleted: the candidate selects the reviewed delivery successor and `omitted-residuals.tsv` records both hashes and the preserved primary location. No broad primary or delivery overlay was copied.

No deferred H3, RunPod/provider, live-GPU, or new timeline/local-evaluation overlay was imported. Existing bytes already present at the base or in the reviewed Runtime successor were not rewritten as part of this construction.

## Deterministic verification

All commands ran in the candidate with Python 3.11.11 and no live service, GPU, RunPod, provider, generation, or spend path.

| Command | Result |
|---|---|
| `PYENV_VERSION=3.11.11 PYTHONPATH=.:packages/python python -m pytest -q tests/test_local_worker_placement.py` | PASS — 26 passed in 0.85s |
| `PYENV_VERSION=3.11.11 PYTHONPATH=.:packages/python python -m pytest -q tests/test_production_worker_credentials_luna.py tests/test_runtime_boundary.py tests/test_real_bootstrap.py tests/test_generated_client.py tests/test_client_parity.py tests/test_runtime_upgrade.py tests/test_operator_upgrade.py tests/test_execution_binding_contract.py tests/test_execution_identity_settlement.py tests/test_settlement_surface.py` | PASS — 69 passed in 11.81s |
| `PYENV_VERSION=3.11.11 PYTHONPATH=.:packages/python:<Astrid delivery>:<Worker delivery> python -m pytest -q tests/test_i06_composed_proof.py` | PASS — 9 passed in 0.84s |
| `git diff --check` | PASS — exit 0, no output |

The composed proof keeps its evidenced fake OS/process/engine boundary and uses the recorded Astrid/Worker delivery roots only as test imports.

## Residuals and limits

- `included-paths.tsv` is the exact SHA-256 product manifest.
- `omitted-residuals.tsv` inventories omitted delivery files, divergent primary bytes, and grouped primary control/generated residue. All remain in place; nothing was reset, cleaned, stashed, deleted, or overwritten.
- This candidate does not resolve I-12 actual-root authority, parent four-repository collision disposition, Worker Python 3.10 installed qualification, landing, or publication.
- It makes no live GPU/provider/RunPod claim.
