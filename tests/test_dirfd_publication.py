from __future__ import annotations

from pathlib import Path
import threading

import pytest

import runtime_protocol.backup as backup_module
from runtime_protocol.dirfd import atomic_json_write
from runtime_protocol.dirfd import capture_parent, close_pinned
from runtime_protocol.catalog import RealmCatalog
import tools.astrid_migrate.migrator as migrator_module
import tools.astrid_migrate.rehearsal as rehearsal_module
from runtime_protocol.service import RuntimeService
from runtime_protocol.errors import ConflictError
from tools.astrid_migrate import MigrationConfig, MigrationError, build_synthetic_fixture
from tools.astrid_migrate.recovery import RecoveryJournal
from tools.astrid_migrate.rehearsal import MigrationJournal


def _swap_on_final_rename(monkeypatch, module, parent: Path, outside: Path, target_name: str, *, mode: str):
    original = module.os.rename
    swapped = False
    real_parent = parent.with_name(parent.name + "-real")

    def hostile(source, destination, **kwargs):
        nonlocal swapped
        if destination == target_name and str(source).startswith(f".{target_name}.") and not swapped:
            swapped = True
            parent.rename(real_parent)
            if mode == "symlink":
                parent.symlink_to(outside, target_is_directory=True)
            else:
                parent.mkdir()
        return original(source, destination, **kwargs)

    monkeypatch.setattr(module.os, "rename", hostile)
    return lambda: (swapped, real_parent)


@pytest.mark.parametrize("mode", ["symlink", "replacement"])
def test_runtime_backup_last_rename_is_parent_pinned(tmp_path, monkeypatch, mode):
    active = RuntimeService(tmp_path / "active")
    parent = tmp_path / "backup-parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    state = _swap_on_final_rename(monkeypatch, backup_module, parent, outside, "backup", mode=mode)
    try:
        with pytest.raises((ConflictError, MigrationError), match="identity|symlink|parent"):
            active.backup(parent / "backup")
        swapped, real_parent = state()
        assert swapped and (real_parent / "backup").is_dir()
        assert not any(outside.iterdir())
        assert active.health()["status"] == "ok"
    finally:
        active.close()


@pytest.mark.parametrize("mode", ["symlink", "replacement"])
def test_runtime_restore_last_rename_is_parent_pinned(tmp_path, monkeypatch, mode):
    active = RuntimeService(tmp_path / "active")
    backup = tmp_path / "backup"
    active.backup(backup)
    parent = tmp_path / "restore-parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    state = _swap_on_final_rename(monkeypatch, backup_module, parent, outside, "candidate", mode=mode)
    try:
        with pytest.raises((ConflictError, MigrationError), match="identity|symlink|parent"):
            active.restore(backup, parent / "candidate")
        swapped, real_parent = state()
        assert swapped and (real_parent / "candidate").is_dir()
        assert not any(outside.iterdir())
        assert active.health()["status"] == "ok"
    finally:
        active.close()


def test_b10_archive_last_rename_is_parent_pinned(tmp_path, monkeypatch):
    source = tmp_path / "source"
    build_synthetic_fixture(source)
    parent = tmp_path / "archive-parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    config = MigrationConfig(source, parent / "archive", tmp_path / "destination")
    migrator = migrator_module.Migrator(config)
    state = _swap_on_final_rename(monkeypatch, migrator_module, parent, outside, "archive", mode="replacement")
    with pytest.raises((ConflictError, MigrationError), match="identity|symlink|parent"):
        migrator._archive(migrator.inventory())
    swapped, real_parent = state()
    assert swapped and (real_parent / "archive").is_dir()
    assert not any(outside.iterdir())


@pytest.mark.parametrize("journal_factory", [MigrationJournal, RecoveryJournal])
def test_lifecycle_journal_last_rename_is_parent_pinned(tmp_path, monkeypatch, journal_factory):
    parent = tmp_path / "journal-parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    path = parent / "migration-journal.json"
    journal = journal_factory(path)
    state = _swap_on_final_rename(monkeypatch, rehearsal_module, parent, outside, path.name, mode="replacement")
    try:
        with pytest.raises((ConflictError, MigrationError), match="identity|symlink|parent"):
            journal.bind(request="bound")
        swapped, real_parent = state()
        assert swapped and (real_parent / path.name).is_file()
        assert not any(outside.iterdir())
    finally:
        del journal


def test_atomic_publication_survives_concurrent_parent_swap_loop(tmp_path):
    """Repeated swaps may reject a write, but never redirect bytes outside the pin."""
    parent = tmp_path / "evidence-parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    real_parent = tmp_path / "evidence-parent-real"
    stop = threading.Event()

    def swap_loop():
        def restore(index, suffix):
            try:
                real_parent.rename(parent)
            except OSError:
                # A writer can create the lexical name after the symlink is
                # removed but before the original inode is restored.
                race_parent = tmp_path / f"evidence-parent-race-{index}-{suffix}"
                parent.rename(race_parent)
                real_parent.rename(parent)

        for index in range(40):
            if stop.is_set():
                return
            if parent.is_symlink():
                parent.unlink()
                restore(index, "restore")
            else:
                parent.rename(real_parent)
                try:
                    parent.symlink_to(outside, target_is_directory=True)
                    parent.unlink()
                except FileExistsError:
                    # A writer may intentionally recreate a missing parent in
                    # this tiny window. Keep those bytes in an isolated race
                    # directory and restore the original parent inode.
                    race_parent = tmp_path / f"evidence-parent-race-{index}"
                    parent.rename(race_parent)
                restore(index, "normal")

    worker = threading.Thread(target=swap_loop)
    worker.start()
    try:
        for index in range(40):
            try:
                atomic_json_write(parent / f"receipt-{index}.json", b"{}\n")
            except (ConflictError, OSError):
                pass
    finally:
        stop.set()
        worker.join(timeout=5)
        if parent.is_symlink():
            parent.unlink()
            real_parent.rename(parent)
    assert not any(outside.iterdir())
    assert all(path.is_file() for path in parent.iterdir())


def test_backup_verification_read_is_pinned_against_parent_replacement(tmp_path):
    active = RuntimeService(tmp_path / "active")
    backup = tmp_path / "backup"
    active.backup(backup)
    identity = capture_parent(backup)
    parent = backup.parent
    replacement = parent.with_name(parent.name + "-replacement")
    try:
        parent.rename(replacement)
        parent.mkdir()
        with pytest.raises(ConflictError, match="identity|parent|symlink"):
            backup_module.verify_backup(backup, directory_identity=identity)
        assert active.health()["status"] == "ok"
    finally:
        close_pinned(identity)
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
        if replacement.exists():
            replacement.rename(parent)
        active.close()


def test_backup_manifest_file_replacement_at_read_syscall_fails_closed(tmp_path, monkeypatch):
    active = RuntimeService(tmp_path / "active")
    backup = tmp_path / "backup"
    active.backup(backup)
    original_open = backup_module.os.open
    replaced = False

    def hostile(name, flags, *args, **kwargs):
        nonlocal replaced
        if name == "manifest.json" and not replaced:
            replaced = True
            (backup / "manifest.json").write_text("{}", encoding="utf-8")
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(backup_module.os, "open", hostile)
    try:
        with pytest.raises(ConflictError):
            backup_module.verify_backup(backup)
        assert replaced and active.health()["status"] == "ok"
    finally:
        active.close()


@pytest.mark.parametrize("journal_factory", [MigrationJournal, RecoveryJournal])
def test_journal_read_is_pinned_against_parent_replacement(tmp_path, journal_factory):
    parent = tmp_path / "journal-parent"
    parent.mkdir()
    path = parent / "journal.json"
    journal = journal_factory(path)
    journal.bind(request="bound")
    replacement = parent.with_name(parent.name + "-replacement")
    parent.rename(replacement)
    parent.mkdir()
    try:
        with pytest.raises((ConflictError, MigrationError), match="identity|parent|symlink|journal"):
            journal.read() if isinstance(journal, RecoveryJournal) else journal._read()
    finally:
        del journal
        parent.rmdir()
        replacement.rename(parent)


def test_catalog_read_rejects_ordinary_parent_replacement(tmp_path):
    parent = tmp_path / "support"
    parent.mkdir()
    catalog_path = parent / "catalog.json"
    catalog = RealmCatalog(catalog_path)
    catalog.register(realm_id="realm-1", display_name="Realm", data_root=str(tmp_path / "realm"))
    replacement = parent.with_name(parent.name + "-replacement")
    parent.rename(replacement)
    parent.mkdir()
    try:
        with pytest.raises(ConflictError, match="identity|parent|symlink"):
            catalog.read()
    finally:
        parent.rmdir()
        replacement.rename(parent)
