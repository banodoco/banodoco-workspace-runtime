# L2a Normal implementation receipt

- Runtime inspection now validates both `payload.clips` and `payload.config.clips` as lists.
- Projection prefers a non-empty top-level list, falls back to `config.clips`, preserves equal duplicates, and raises the existing `ConflictError` semantics for conflicting populated lists.
- Projection remains bounded and metadata-only; no Astrid adapter, schema, service state, media object, or browser state changed.
- Regression coverage includes config-only Maple-shaped parent media, audio, and overlay rows; top-level-only and equal duplicate lists; conflicts; malformed collections; selectors; pagination; and pinned revisions.
- Verified: `python -m pytest tests/test_timeline_native_inspection.py` — 17 passed.
- Verified: `python -m pytest tests/test_canonical_render_admission.py` — 43 passed.
- Verified: focused `py_compile` and `git diff --check` passed.
- No running-service, browser, commit, merge, push, or restart claim.
