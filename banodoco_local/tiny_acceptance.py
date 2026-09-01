"""Tiny, real B12 live-acceptance journey for routine Stage 1 proof.

The fixture is deliberately representative rather than historical: it has the
same SQLite ownership facts as the migration fixture and one managed-local
content-addressed media object, but is only a few kilobytes.  The command then
uses the public operator path, so the resulting evidence is the same evidence
produced by an explicitly authorized live migration.
"""

from __future__ import annotations

import hashlib
import json
from argparse import Namespace
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
from typing import Any

from banodoco_local.io import atomic_write_json
from banodoco_local.bootstrap import SourceProfile
from banodoco_local.paths import RuntimePaths
from runtime_protocol.catalog import RealmCatalog
from runtime_protocol.service import RuntimeService

from tools.astrid_migrate.migrator import MigrationError
from tools.astrid_migrate.operator import CONFIRMATION, _write_new_json, issue_authorizations, live_migrate
from tools.astrid_migrate.rehearsal import build_synthetic_fixture


REALM_ID = "stage1-tiny-acceptance"


def _has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            return True
    return False


def _managed_media(source: Path, digest: str) -> None:
    """Make the fixture exercise the managed-local snapshot media path."""

    payload = source / "media" / "clip.bin"
    cas_path = source / ".astrid" / "media" / "sha256" / digest[:2] / digest[2:4] / digest
    cas_path.parent.mkdir(parents=True)
    shutil.copy2(payload, cas_path)
    connection = sqlite3.connect(source / ".astrid" / "astrid.sqlite3")
    try:
        connection.execute(
            "UPDATE media_locations SET realm='managed_local', locator=? WHERE media_id=?",
            (f"/historical/Astrid/.astrid/media/sha256/{digest[:2]}/{digest[2:4]}/{digest}", "media-1"),
        )
        connection.commit()
    finally:
        connection.close()


def _provision_neutral_realm(active: Path, paths: RuntimePaths, source_checkout: Path, runtime_environment: Path) -> Path:
    """Create one disposable neutral realm and its activation trust anchor."""

    paths.ensure_support_dirs()
    runtime = RuntimeService(active, display_name="Stage 1 tiny acceptance", realm_id=REALM_ID, support_root=paths.runtime_support)
    try:
        # The service creates the neutral SQLite realm; the catalog is the
        # durable selected-realm boundary consumed by the live operator.
        RealmCatalog(paths.catalog_path).register(
            realm_id=REALM_ID,
            display_name="Stage 1 tiny acceptance",
            data_root=str(active),
        )
        RealmCatalog(paths.catalog_path).select(REALM_ID)
        atomic_write_json(
            paths.activation_trust_path,
            {"version": 1, "key_hex": secrets.token_hex(32)},
        )
        paths.activation_trust_path.chmod(0o600)
        source_manifest = paths.source_profiles_dir / "astrid.json"
        manifest = {
            "profile": "astrid",
            "runtime_checkout": str(Path(__file__).resolve().parents[1]),
            "source_checkout": str(source_checkout.resolve()),
            "runtime_environment": str(runtime_environment),
        }
        manifest = SourceProfile.from_mapping(manifest).as_dict()
        atomic_write_json(source_manifest, manifest)
        source_manifest.chmod(0o600)
        catalog = json.loads(paths.catalog_path.read_text(encoding="utf-8"))
        catalog["source_profiles"] = {"astrid": SourceProfile.from_mapping(manifest).as_dict()}
        catalog["realms"][0]["source_profile"] = "astrid"
        atomic_write_json(paths.catalog_path, catalog)
    finally:
        runtime.close()
    return source_manifest


def _cold_open(active: Path, support: Path) -> dict[str, Any]:
    """Open the activated realm in a fresh service and perform integrity checks."""

    runtime = RuntimeService(
        active,
        display_name="Stage 1 tiny acceptance",
        realm_id=REALM_ID,
        support_root=support,
    )
    try:
        doctor = runtime.doctor()
        if runtime.realm["id"] != REALM_ID or not doctor.get("ok"):
            raise MigrationError("activated tiny realm failed cold-open integrity check")
        project_count = runtime.store.conn.execute("SELECT count(*) FROM projects").fetchone()[0]
        object_count = runtime.store.conn.execute("SELECT count(*) FROM objects").fetchone()[0]
        if project_count < 1 or object_count < 1:
            raise MigrationError("activated tiny realm is missing migrated facts or media")
        return {
            "ok": True,
            "realm_id": runtime.realm["id"],
            "health": runtime.health(),
            "doctor": doctor,
            "project_count": project_count,
            "object_count": object_count,
        }
    finally:
        runtime.close()


def run_tiny_acceptance(output_root: str | Path, source_checkout: str | Path, runtime_environment: str | Path) -> dict[str, Any]:
    """Run the routine tiny B12 journey under ``output_root``.

    ``output_root`` is intentionally fresh and owns source, support, active
    realm, operator receipts, migration artifacts, and evidence.  No existing
    data is removed or replaced.
    """

    root = Path(output_root).expanduser()
    if not root.is_absolute():
        raise ValueError("tiny acceptance output root must be absolute")
    # Canonicalize the caller's output parent before composing operator paths;
    # macOS commonly exposes /tmp as a symlink to /private/tmp, and the
    # fail-closed B12 path checks correctly reject symlink traversal.
    root = root.resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError(f"tiny acceptance output root is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    astrid_checkout = Path(source_checkout).expanduser()
    environment = Path(runtime_environment).expanduser()
    if not astrid_checkout.is_absolute() or not astrid_checkout.is_dir() or astrid_checkout.is_symlink():
        raise ValueError(f"tiny acceptance requires an existing absolute Astrid source checkout: {astrid_checkout}")
    if not environment.is_absolute() or not environment.is_dir() or _has_symlink_component(environment):
        raise ValueError(f"tiny acceptance requires an existing absolute runtime environment: {environment}")
    interpreter = environment / "bin" / "python"
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise ValueError(f"tiny acceptance runtime environment has no executable Python: {interpreter}")
    probe = subprocess.run(
        [
            str(interpreter),
            "-c",
            "from pathlib import Path; import banodoco_local, banodoco_workspace_client, sys; root=Path(sys.executable).parent.parent; [Path(module.__file__).resolve().relative_to(root) for module in (banodoco_local, banodoco_workspace_client)]",
        ],
        cwd=str(environment),
        env={"PATH": os.defpath},
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        raise ValueError("tiny acceptance runtime environment must import banodoco_local and banodoco_workspace_client")

    source = root / "source"
    home = root / "home"
    paths = RuntimePaths.current_mac(home)
    support = paths.runtime_support
    active = paths.realms_dir / REALM_ID
    # The neutral product support root owns the current-Mac realm layout.  The
    # offline migrator deliberately rejects an active realm nested below its
    # support argument, so its serialized B12 activation registry uses this
    # disposable sidecar while the selected neutral catalog/trust remain in
    # the real support root.
    migration_support = root / "migration-support"
    archive = root / "archive"
    destination = root / "destination"
    evidence = root / "evidence"
    authorizations_path = root / "b12-authorizations.json"
    writer_receipt_path = root / "writer-stop.json"

    fixture = build_synthetic_fixture(source)
    _managed_media(source, fixture.media_digest)
    source_manifest = _provision_neutral_realm(active, paths, astrid_checkout, environment)
    migration_support.mkdir()
    (migration_support / "activations").mkdir()
    shutil.copy2(paths.catalog_path, migration_support / "catalog.json")
    shutil.copy2(paths.activation_trust_path, migration_support / "activation-trust.json")
    (migration_support / "activation-trust.json").chmod(0o600)

    issue_authorizations(
        Namespace(
            source_root=str(source),
            archive_root=str(archive),
            destination_root=str(destination),
            realm_id=REALM_ID,
            output=str(authorizations_path),
            ttl_seconds=3600,
        )
    )
    _write_new_json(
        writer_receipt_path,
        {
            "format_version": 1,
            "source_root": str(source.resolve()),
            "stopped": True,
            "writer_count": 0,
            "method": "tiny-fixture-no-writers",
        },
    )

    # This is deliberately the same production operator bridge exposed by
    # ``astrid-live-migrate live-migrate``.  Compact is fixed for this routine
    # fixture; extreme/full-corpus is available only through the explicit
    # operator command.
    live_result = live_migrate(
        Namespace(
            confirm=CONFIRMATION,
            source_root=str(source),
            active_root=str(active),
            support_root=str(migration_support),
            archive_root=str(archive),
            destination_root=str(destination),
            evidence_root=str(evidence),
            realm_id=REALM_ID,
            authorization_file=str(authorizations_path),
            writer_stop_receipt=str(writer_receipt_path),
            display_name="Stage 1 tiny acceptance",
            capacity_margin_bytes=None,
            redundancy="compact",
        )
    )
    report = live_result["report"]
    cold_open = _cold_open(active, support)
    terminal_receipt = evidence / "activated-destination-b12.json"
    if not terminal_receipt.is_file():
        raise MigrationError("B12 did not preserve its terminal reactivation receipt")

    summary = {
        "ok": True,
        "packet": "B12",
        "mode": "tiny-acceptance",
        "redundancy": report["journal"]["binding"]["redundancy"],
        "realm_id": REALM_ID,
        "source_root": str(source),
        "source_checkout": str(astrid_checkout.resolve()),
        "runtime_environment": str(environment.resolve()),
        "source_bytes": sum(path.stat().st_size for path in source.rglob("*") if path.is_file()),
        "support_root": str(support),
        "migration_support_root": str(migration_support),
        "neutral_home": str(home),
        "source_manifest": str(source_manifest),
        "active_root": str(active),
        "archive_root": str(archive),
        "destination_root": str(destination),
        "evidence_root": str(evidence),
        "authorization_file": str(authorizations_path),
        "writer_stop_receipt": str(writer_receipt_path),
        "terminal_receipt": str(terminal_receipt),
        "journal_state": report["journal"]["state"],
        "cold_open": cold_open,
        "managed_media_digest": fixture.media_digest,
    }
    atomic_write_json(root / "tiny-acceptance.json", summary)
    return summary


__all__ = ["REALM_ID", "run_tiny_acceptance"]
