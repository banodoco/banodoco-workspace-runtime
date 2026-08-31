# Neutral runtime semantic coverage

Base: runtime `00a08dd78493b827e9cad08c9e3ccd042a4cb876`.

This port keeps the generated Python client and public HTTP protocol as the
test boundary. It does not import or mutate the runtime store in the new
tests. Existing runtime tests that predate this port are included in the
matrix because they already prove the corresponding behavior at that boundary.

| Former Astrid/local invariant | Runtime evidence |
| --- | --- |
| Project create/update isolation, idempotency replay and mismatch-before-mutation | `tests/test_runtime_e2e.py::test_project_patch_and_run_cancel_retry_are_durable_and_idempotent`, `tests/test_neutral_semantic_coverage.py::test_project_idempotency_mismatch_has_no_second_project` |
| Media ingestion, byte integrity, ETag/range/head and CAS tamper rejection | `tests/test_runtime_e2e.py::test_project_managed_object_and_fake_worker_end_to_end`, `tests/test_runtime_e2e.py::test_cas_hash_and_path_safety`, `tests/test_generated_client.py::test_object_byte_range_etag_and_head_are_preserved`, `tests/test_neutral_semantic_coverage.py::test_http_digest_mismatch_fails_before_project_media_publication` |
| Project media isolation and relation ownership | `tests/test_runtime_e2e.py::test_project_shot_reference_crud_isolated_idempotent_and_restart_durable`, `tests/test_runtime_domains.py::test_generated_domains_preserve_project_media_and_timeline_recovery`, `tests/test_neutral_semantic_coverage.py::test_project_media_relation_rejects_foreign_object_without_relation` |
| Task/run admission, fan-in replay, receipts, events, and evidence linkage | `tests/test_runtime_domains.py::test_task_receipt_binds_committed_admission_event_and_canonical_sequence`, `tests/test_runtime_domains.py::test_generated_python_client_exercises_versioned_domains_on_real_daemon`, `tests/test_neutral_semantic_coverage.py::test_concurrent_task_replay_fans_in_to_one_runtime_admission` |
| Lease, fence, claim, settle, cancel, retry, stale effects | `tests/test_runtime_e2e.py::test_stale_lease_and_undeclared_effect_are_rejected`, `tests/test_runtime_control2.py::test_retry_is_state_guarded_and_records_transition`, `tests/test_runtime_reboot.py::test_reboot_requeues_durable_task_and_fences_old_process` |
| Timeline atomic command, history, recovery, mounted shots/references | `tests/test_runtime_domains.py::test_timeline_document_is_one_atomic_runtime_command`, `tests/test_runtime_domains.py::test_timeline_document_replay_survives_runtime_restart`, `tests/test_runtime_domains.py::test_generated_domains_preserve_project_media_and_timeline_recovery` |
| Concurrency, contention, fanout/replay, crash atomicity, restart durability | `tests/test_runtime_domains.py::test_receipts_are_identical_across_concurrent_replay_and_restart`, `tests/test_runtime_reboot.py::test_reboot_request_claim_is_atomic_under_forced_race`, `tests/test_run_controls_regressions.py::test_run_control_receipt_is_atomic_and_replayable_after_restart`, `tests/test_b6_3_sol_regressions.py::test_expired_settlement_has_zero_cas_or_object_mutation` |

The four new generated-client/HTTP tests specifically close gaps not covered
by the pre-existing runtime suite: project idempotency mismatch, foreign media
relation rejection, concurrent task replay, and HTTP digest mismatch with no
project publication. No production runtime code was changed.
