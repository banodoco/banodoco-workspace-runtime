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
from pathlib import Path
import secrets
import shutil
import sqlite3
from typing import Any

from banodoco_local.io import atomic_write_json
from runtime_protocol.catalog import RealmCatalog
from runtime_protocol.service import RuntimeService

from .migrator import MigrationError
from .operator import CONFIRMATION, _write_new_json, issue_authorizations, live_migrate
from .rehearsal import build_synthetic_fixture


REALM_ID = "stage1-tiny-acceptance"


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


def _provision_neutral_realm(active: Path, support: Path) -> None:
    """Create one disposable neutral realm and its activation trust anchor."""

    support.mkdir(parents=True)
    (support / "activations").mkdir()
    runtime = RuntimeService(active, display_name="Stage 1 tiny acceptance", realm_id=REALM_ID, support_root=support)
    try:
        # The service creates the neutral SQLite realm; the catalog is the
        # durable selected-realm boundary consumed by the live operator.
        RealmCatalog(support / "catalog.json").register(
            realm_id=REALM_ID,
            display_name="Stage 1 tiny acceptance",
            data_root=str(active),
        )
        RealmCatalog(support / "catalog.json").select(REALM_ID)
        atomic_write_json(
            support / "activation-trust.json",
            {"version": 1, "key_hex": secrets.token_hex(32)},
        )
        (support / "activation-trust.json").chmod(0o600)
    finally:
        runtime.close()


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


def run_tiny_acceptance(output_root: str | Path) -> dict[str, Any]:
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

    source = root / "source"
    support = root / "support"
    active = root / "active"
    archive = root / "archive"
    destination = root / "destination"
    evidence = root / "evidence"
    authorizations_path = root / "b12-authorizations.json"
    writer_receipt_path = root / "writer-stop.json"

    fixture = build_synthetic_fixture(source)
    _managed_media(source, fixture.media_digest)
    _provision_neutral_realm(active, support)

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
            support_root=str(support),
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
        "source_bytes": sum(path.stat().st_size for path in source.rglob("*") if path.is_file()),
        "support_root": str(support),
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
