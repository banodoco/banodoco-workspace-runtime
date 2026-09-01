from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from argparse import Namespace
from pathlib import Path

import pytest

from banodoco_local.io import atomic_write_json
from runtime_protocol.catalog import RealmCatalog
from runtime_protocol.service import RuntimeService
from tools.astrid_migrate import MigrationError, build_synthetic_fixture
from tools.astrid_migrate.operator import (
    CONFIRMATION,
    LIVE_AUTHORIZATION_IDS,
    issue_authorizations,
    live_migrate,
    main,
    normalize_nested_source,
)


def _paths(tmp_path: Path):
    source = tmp_path / "source"
    fixture = build_synthetic_fixture(source)
    active = tmp_path / "active"
    support = tmp_path / "support"
    support.mkdir()
    support.joinpath("activations").mkdir()
    runtime = RuntimeService(active, display_name="Selected", realm_id="realm-test", support_root=support)
    runtime.close()
    RealmCatalog(support / "catalog.json").register(realm_id="realm-test", display_name="Selected", data_root=str(active))
    atomic_write_json(support / "activation-trust.json", {"version": 1, "key_hex": "a" * 64})
    (support / "activation-trust.json").chmod(0o600)
    return source, active, support, fixture


def _issue(source: Path, tmp_path: Path, name: str = "authorizations.json") -> Path:
    output = tmp_path / name
    result = issue_authorizations(Namespace(
        source_root=str(source), archive_root=str(tmp_path / "preflight-archive"),
        destination_root=str(tmp_path / "preflight-destination"), realm_id="realm-test",
        output=str(output), ttl_seconds=3600,
    ))
    assert result["authorization_ids"] == list(LIVE_AUTHORIZATION_IDS)
    return output


def _receipt(source: Path, tmp_path: Path) -> Path:
    path = tmp_path / "writer-stop.json"
    atomic_write_json(path, {"format_version": 1, "source_root": str(source), "stopped": True, "writer_count": 0, "method": "test-supervisor"})
    return path


def _live_args(source: Path, active: Path, support: Path, auth: Path, receipt: Path, tmp_path: Path, suffix: str = ""):
    return Namespace(
        confirm=CONFIRMATION, source_root=str(source), active_root=str(active), support_root=str(support),
        archive_root=str(tmp_path / f"archive{suffix}"), destination_root=str(tmp_path / f"destination{suffix}"),
        evidence_root=str(tmp_path / f"evidence{suffix}"), realm_id="realm-test",
        authorization_file=str(auth), writer_stop_receipt=str(receipt), display_name="Selected",
        capacity_margin_bytes=0,
    )


def test_public_b12_operator_cli_runs_synthetic_full_journey_and_keeps_source_unchanged(tmp_path):
    source, active, support, fixture = _paths(tmp_path)
    auth = _issue(source, tmp_path, "authorizations-2.json")
    receipt = _receipt(source, tmp_path)
    result = live_migrate(_live_args(source, active, support, auth, receipt, tmp_path))
    assert result["ok"] is True
    assert result["report"]["journal"]["state"] == "reactivated"
    assert result["report"]["identity"]["realm_id"] == "realm-test"
    assert fixture.source_tree_sha256 == _tree_digest(source)
    assert (active / "activation-manifest.json").is_file()
    assert list((support / "activations").glob("*.json"))
    assert json.loads((tmp_path / "evidence" / "activated-destination-b12.json").read_text())["activation_epoch"] == 3


def test_b12_rejects_nonfinite_authorization_expiry(tmp_path):
    source, active, support, _ = _paths(tmp_path)
    auth_path = _issue(source, tmp_path, "authorizations-nan.json")
    envelope = json.loads(auth_path.read_text())
    for value in envelope["authorizations"].values():
        value["expires_at"] = float("nan")
    auth_path.write_text(json.dumps(envelope), encoding="utf-8")
    receipt = _receipt(source, tmp_path)
    with pytest.raises(MigrationError, match="invalid expiry"):
        live_migrate(_live_args(source, active, support, auth_path, receipt, tmp_path, "-nan"))


def test_public_b12_requires_owner_only_authorization_and_writer_artifacts(tmp_path, capsys):
    source, active, support, _ = _paths(tmp_path)
    auth_path = _issue(source, tmp_path, "authorizations-mode.json")
    receipt = _receipt(source, tmp_path)
    auth_path.chmod(0o644)
    args = _live_args(source, active, support, auth_path, receipt, tmp_path, "-auth-mode")
    status = main([
        "live-migrate", "--confirm", CONFIRMATION,
        "--source-root", str(source), "--active-root", str(active),
        "--support-root", str(support), "--archive-root", str(args.archive_root),
        "--destination-root", str(args.destination_root), "--evidence-root", str(args.evidence_root),
        "--realm-id", args.realm_id, "--authorization-file", str(auth_path),
        "--writer-stop-receipt", str(receipt),
    ])
    assert status == 2
    assert "owner-only" in capsys.readouterr().err

    auth_path.chmod(0o600)
    receipt.chmod(0o644)
    status = main([
        "live-migrate", "--confirm", CONFIRMATION,
        "--source-root", str(source), "--active-root", str(active),
        "--support-root", str(support), "--archive-root", str(tmp_path / "archive-receipt-mode"),
        "--destination-root", str(tmp_path / "destination-receipt-mode"), "--evidence-root", str(tmp_path / "evidence-receipt-mode"),
        "--realm-id", args.realm_id, "--authorization-file", str(auth_path),
        "--writer-stop-receipt", str(receipt),
    ])
    assert status == 2
    assert "owner-only" in capsys.readouterr().err


def test_public_b12_rejects_boolean_writer_count(tmp_path):
    source, active, support, _ = _paths(tmp_path)
    auth_path = _issue(source, tmp_path, "authorizations-bool.json")
    receipt = _receipt(source, tmp_path)
    receipt.write_text(json.dumps({
        "format_version": 1,
        "source_root": str(source),
        "stopped": True,
        "writer_count": False,
        "method": "test-supervisor",
    }), encoding="utf-8")
    with pytest.raises(MigrationError, match="writer-stop receipt"):
        live_migrate(_live_args(source, active, support, auth_path, receipt, tmp_path, "-bool"))


def test_public_cli_requires_exact_six_authorizations_and_writer_receipt(tmp_path, capsys):
    source, active, support, _ = _paths(tmp_path)
    auth = _issue(source, tmp_path, "authorizations-2.json")
    envelope = json.loads(auth.read_text())
    envelope["authorizations"].pop(LIVE_AUTHORIZATION_IDS[-1])
    auth.write_text(json.dumps(envelope), encoding="utf-8")
    receipt = _receipt(source, tmp_path)
    status = main(["live-migrate", "--confirm", CONFIRMATION, "--source-root", str(source), "--active-root", str(active), "--support-root", str(support), "--archive-root", str(tmp_path / "archive"), "--destination-root", str(tmp_path / "destination"), "--evidence-root", str(tmp_path / "evidence"), "--realm-id", "realm-test", "--authorization-file", str(auth), "--writer-stop-receipt", str(receipt)])
    assert status == 2
    assert "exactly the six" in capsys.readouterr().err
    assert not (tmp_path / "evidence").exists()

    auth = _issue(source, tmp_path, "authorizations-3.json")
    bad_receipt = tmp_path / "bad-writer-stop.json"
    atomic_write_json(bad_receipt, {"format_version": 1, "source_root": str(source), "stopped": False, "writer_count": 1, "method": "test-supervisor"})
    status = main(["live-migrate", "--confirm", CONFIRMATION, "--source-root", str(source), "--active-root", str(active), "--support-root", str(support), "--archive-root", str(tmp_path / "archive-2"), "--destination-root", str(tmp_path / "destination-2"), "--evidence-root", str(tmp_path / "evidence-2"), "--realm-id", "realm-test", "--authorization-file", str(auth), "--writer-stop-receipt", str(bad_receipt)])
    assert status == 2
    assert "writer-stop receipt" in capsys.readouterr().err


def test_nested_normalizer_is_explicit_and_does_not_mutate_source(tmp_path):
    source = tmp_path / "nested-source"
    fixture = build_synthetic_fixture(source)
    nested = source / ".astrid" / "source-projects-root-kernel"
    nested.mkdir()
    database = nested / "astrid.sqlite3"
    shutil.copy2(source / ".astrid" / "astrid.sqlite3", database)
    digest = fixture.media_digest
    media = nested / "media" / "sha256" / digest[:2]
    media.mkdir(parents=True)
    shutil.copy2(source / "media" / "clip.bin", media / digest[2:])
    connection = sqlite3.connect(database)
    connection.execute("UPDATE media_locations SET realm='managed_local', locator=?", (f"/old/astrid-intro-projects/.astrid/media/sha256/{digest[:2]}/{digest[2:]}",))
    connection.commit()
    connection.close()
    before = _sha256(database)
    destination = tmp_path / "normalized"
    result = normalize_nested_source(Namespace(source_root=str(source), database=str(database), destination_root=str(destination)))
    assert result["ok"] is True
    assert _sha256(database) == before
    assert (destination / ".astrid" / "astrid.sqlite3").is_file()
    assert json.loads((destination / "normalization-manifest.json").read_text())["media_mappings"]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digest(root: Path) -> str:
    entries = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() or item.is_symlink()):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            entries.append({"path": relative, "kind": "symlink", "target": path.readlink().as_posix()})
        else:
            entries.append({"path": relative, "kind": "file", "size": path.stat().st_size, "sha256": _sha256(path)})
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
