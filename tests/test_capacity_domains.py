from __future__ import annotations

from pathlib import Path

import pytest

from tools.astrid_migrate.capacity import CapacityPlan, CapacityReservation, StorageDomain, capture_activation_path, revalidate_activation_path
from tools.astrid_migrate.migrator import MigrationError


def test_sibling_destinations_share_one_locked_pool(tmp_path: Path):
    first = tmp_path / "destination-a"
    second = tmp_path / "destination-b"
    plan_a = CapacityPlan.from_allocations((("destination", first, 1),), margin_bytes=0)
    plan_b = CapacityPlan.from_allocations((("destination", second, 1),), margin_bytes=0)
    assert sorted(plan_a.domains) == sorted(plan_b.domains)
    reservation = CapacityReservation.acquire(plan=plan_a, reservation_id="first")
    try:
        with pytest.raises(MigrationError, match="already held"):
            CapacityReservation.acquire(plan=plan_b, reservation_id="second")
    finally:
        reservation.release()
    replay = CapacityReservation.acquire(plan=plan_b, reservation_id="second")
    replay.release()


def test_device_fakes_form_independent_capacity_pools(monkeypatch, tmp_path: Path):
    real = StorageDomain.identify(tmp_path)
    fake_a = StorageDomain("device-a", 101, "mount-a", real.probe_path)
    fake_b = StorageDomain("device-b", 202, "mount-b", real.probe_path)
    calls = iter((fake_a, fake_b))
    monkeypatch.setattr(StorageDomain, "identify", classmethod(lambda cls, path: next(calls)))
    plan = CapacityPlan.from_allocations((("destination", tmp_path / "a", 50), ("archive", tmp_path / "b", 70)), margin_bytes=3)
    receipt = plan.receipt(packet="TEST")
    assert {row["domain_id"] for row in receipt["domains"]} == {"device-a", "device-b"}
    assert sorted(row["required_bytes"] for row in receipt["domains"]) == [53, 73]


def test_shared_domain_aggregates_destination_and_archive_bytes():
    plan = CapacityPlan.from_allocations((("destination", ".", 100), ("archive", "./archive", 200)), margin_bytes=11)
    receipt = plan.receipt(packet="TEST")
    assert len(receipt["domains"]) == 1
    assert receipt["domains"][0]["required_bytes"] == 311


def test_symlink_swap_is_rejected_and_release_is_idempotent(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    escaped = tmp_path / "escaped"
    escaped.symlink_to(outside, target_is_directory=True)
    with pytest.raises(MigrationError, match="symlink"):
        CapacityPlan.from_allocations((("destination", escaped, 1),))

    plan = CapacityPlan.from_allocations((("destination", tmp_path / "safe", 1),))
    reservation = CapacityReservation.acquire(plan=plan, reservation_id="cleanup")
    reservation.release()
    reservation.release()
    again = CapacityReservation.acquire(plan=plan, reservation_id="replay")
    again.release()


def test_failed_probe_acquisition_releases_lock_for_immediate_retry(monkeypatch, tmp_path: Path):
    """A probe failure must not strand the lock acquired for that domain."""
    import tools.astrid_migrate.capacity as capacity

    plan = CapacityPlan.from_allocations((("destination", tmp_path / "destination", 1),), margin_bytes=0)
    original = capacity._open_directory_chain
    calls = 0

    def fail_once(path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected probe failure")
        return original(path)

    monkeypatch.setattr(capacity, "_open_directory_chain", fail_once)
    with pytest.raises(MigrationError, match="probe path"):
        CapacityReservation.acquire(plan=plan, reservation_id="failed")
    retry = CapacityReservation.acquire(plan=plan, reservation_id="retry")
    retry.release()


def test_activation_identity_fences_absent_and_replaced_targets(tmp_path: Path):
    parent = tmp_path / "authority-parent"
    parent.mkdir()
    target = parent / "active"

    absent = capture_activation_path(target)
    target.mkdir()
    with pytest.raises(MigrationError, match="presence"):
        revalidate_activation_path(target, absent)

    target.rename(parent / "active-original")
    target.mkdir()
    existing = capture_activation_path(target)
    target.rename(parent / "active-replaced")
    target.mkdir()
    with pytest.raises(MigrationError, match="identity"):
        revalidate_activation_path(target, existing)

    parent.rename(tmp_path / "authority-parent-original")
    parent.mkdir()
    with pytest.raises(MigrationError, match="identity"):
        revalidate_activation_path(target, existing)
