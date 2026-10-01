from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import shutil
import socket
import stat
import sys
import time
import math
from pathlib import Path
from urllib.parse import urlsplit

from .daemon import RuntimeDaemon, WORKER_SCOPES
from .local_worker_composition import load_local_worker_composition
from .local_worker_composition import CONTROL_VERSION
from .local_worker_handoff import (
    TRANSFER_VERSION,
    peer_pid,
    peer_uid,
    receive_frame,
    send_authority_transfer,
    send_frame,
    validate_inherited_authority_descriptors,
)
from .orderly_handoff import HandoffRecord, RECORD_VERSION, digest, nonce_digest
from .catalog import process_birth_identity
from .backup import create_backup, restore_backup, structured_export
from .errors import RuntimeErrorBase
from .handoff_recovery import resolve_aborted_predecessor as _resolve_aborted_predecessor
from .store import RealmStore
from .upgrade import (
    DEFAULT_UPGRADE_TIMEOUT_SECONDS,
    GENERIC_MEDIA_TYPE_REPAIR_CONFIRMATION,
    migrate_historical_managed_outputs,
    migrate_canonical_v24_to_v25,
    repair_generic_media_types,
    upgrade_realm,
)


def _parser():
    parser = argparse.ArgumentParser(prog="banodoco-runtime", description="Neutral loopback workspace runtime")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start", help="start the loopback daemon")
    start.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    start.add_argument("--support-root")
    start.add_argument("--export-root", help="existing absolute directory for exact managed-output exports")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=0)
    start.add_argument("--display-name", default="Workspace")
    start.add_argument("--realm-id")
    start.add_argument("--owner-lock")
    start.add_argument("--bootstrap-token-file")
    start.add_argument("--admission-timeout", type=float, help="bounded startup integrity budget in seconds")
    start.add_argument("--worker-profile", help="absolute installed local Worker composition profile")
    start.add_argument("--handoff-record")
    start.add_argument("--handoff-worker-fd", type=int)
    start.add_argument("--handoff-listener-fd", type=int)
    start.add_argument("--handoff-capability-fd", type=int)
    create = sub.add_parser("create", help="explicitly create one fresh canonical realm")
    create.add_argument("--root", required=True)
    create.add_argument("--display-name", default="Workspace")
    create.add_argument("--realm-id")
    doctor = sub.add_parser("doctor", help="read-only runtime health check")
    doctor.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--support-root")
    upgrade = sub.add_parser("upgrade", help="offline upgrade one stopped legacy realm to the canonical format")
    upgrade.add_argument("--root", required=True)
    upgrade.add_argument("--archive-root")
    upgrade.add_argument("--timeout", type=float, default=DEFAULT_UPGRADE_TIMEOUT_SECONDS)
    upgrade.add_argument("--confirm", required=True)
    variant_state = sub.add_parser("migrate-variant-state", help="offline migrate one stopped canonical v24 realm to v25")
    variant_state.add_argument("--root", required=True)
    variant_state.add_argument("--timeout", type=float, default=DEFAULT_UPGRADE_TIMEOUT_SECONDS)
    variant_state.add_argument("--confirm", required=True)
    reconcile = sub.add_parser("migrate-managed-outputs", help="materialize verified associations for historical settled render outputs")
    reconcile.add_argument("--root", required=True)
    reconcile.add_argument("--project-id")
    reconcile.add_argument("--task-id")
    reconcile.add_argument("--timeout", type=float, default=DEFAULT_UPGRADE_TIMEOUT_SECONDS)
    reconcile.add_argument("--confirm", required=True)
    repair = sub.add_parser("repair-media-types", help="repair generic published MIME values from managed filenames")
    repair.add_argument("--root", required=True)
    repair.add_argument("--project-id")
    repair.add_argument("--task-id")
    repair.add_argument("--generation-id")
    repair.add_argument("--timeout", type=float, default=DEFAULT_UPGRADE_TIMEOUT_SECONDS)
    repair.add_argument("--confirm", required=True)
    backup = sub.add_parser("backup", help="create a verified self-contained realm backup")
    backup.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    backup.add_argument("--support-root")
    backup.add_argument("--destination", required=True)
    restore = sub.add_parser("restore", help="restore a backup into a new inactive realm")
    restore.add_argument("--backup", required=True)
    restore.add_argument("--destination", required=True)
    replace = sub.add_parser("replace", help="activate a verified backup as the running realm")
    replace.add_argument("--root", required=True)
    replace.add_argument("--backup", required=True)
    replace.add_argument("--support-root")
    replace.add_argument("--display-name", default="Workspace")
    replace.add_argument("--realm-id")
    export = sub.add_parser("export", help="export structured realm state")
    export.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    export.add_argument("--destination")
    export.add_argument("--json", action="store_true")
    purge = sub.add_parser("purge", help="irreversibly remove a tombstoned realm (offline only)")
    purge.add_argument("--root", required=True)
    purge.add_argument("--confirm", required=True)
    identity = sub.add_parser("identity", help="capture or verify local release identities")
    identity.add_argument("operation", choices=("pre-live", "candidate-core", "verify"))
    identity.add_argument("--component", action="append", default=[])
    identity.add_argument("--pre-live")
    identity.add_argument("--receipt")
    identity.add_argument("--output")
    return parser


_HANDOFF_POINTER = "orderly-handoff-request.json"


def _owned_handoff_request(
    pointer: object,
    record: object,
    *,
    daemon: RuntimeDaemon,
    support_root: Path,
) -> tuple[dict, dict, Path]:
    """Strictly validate untrusted OWNED input before A opens a channel."""

    pointer_keys = {
        "version", "handoff_id", "record_path", "socket_path",
        "coordinator_pid", "coordinator_birth_id",
    }
    record_keys = {
        "version", "state", "handoff_id", "realm_id", "realm_root",
        "support_root", "deadline_monotonic", "deadline_unix_ms",
        "nonce_digest", "sealed_record_digest", "old_owner", "export",
        "export_sealed_digest", "adopter", "record_digest",
        "predecessor_active_ref_digest",
    }
    if not isinstance(pointer, dict) or set(pointer) != pointer_keys:
        raise RuntimeErrorBase("orderly handoff pointer shape is invalid")
    if not isinstance(record, dict) or set(record) != record_keys:
        raise RuntimeErrorBase("orderly handoff OWNED record shape is invalid")
    if pointer.get("version") != TRANSFER_VERSION or record.get("version") != RECORD_VERSION:
        raise RuntimeErrorBase("orderly handoff version is invalid")
    handoff_id = pointer.get("handoff_id")
    if not isinstance(handoff_id, str) or not handoff_id or len(handoff_id) > 256:
        raise RuntimeErrorBase("orderly handoff identity is invalid")
    if record.get("handoff_id") != handoff_id or record.get("state") != "OWNED":
        raise RuntimeErrorBase("orderly handoff request does not match owner A")
    for key in ("record_path", "socket_path"):
        if not isinstance(pointer.get(key), str) or not pointer[key]:
            raise RuntimeErrorBase(f"orderly handoff {key} is invalid")
    record_path = Path(pointer["record_path"])
    socket_path = Path(pointer["socket_path"])
    if (
        not record_path.is_absolute()
        or not socket_path.is_absolute()
        or record_path.parent != support_root
        or record_path.name != f"orderly-handoff-record-{handoff_id}.json"
        or socket_path.name != "coordinator.sock"
    ):
        raise RuntimeErrorBase("orderly handoff rendezvous paths are invalid")
    try:
        record_info = record_path.lstat()
        socket_parent_info = socket_path.parent.lstat()
        socket_info = socket_path.lstat()
    except OSError as exc:
        raise RuntimeErrorBase("orderly handoff rendezvous paths are unavailable") from exc
    if (
        record_path.is_symlink()
        or not stat.S_ISREG(record_info.st_mode)
        or record_info.st_uid != os.getuid()
        or stat.S_IMODE(record_info.st_mode) != 0o600
        or socket_path.parent.is_symlink()
        or not stat.S_ISDIR(socket_parent_info.st_mode)
        or socket_parent_info.st_uid != os.getuid()
        or stat.S_IMODE(socket_parent_info.st_mode) != 0o700
        or socket_path.is_symlink()
        or not stat.S_ISSOCK(socket_info.st_mode)
        or socket_info.st_uid != os.getuid()
        or socket_info.st_mode & 0o077
    ):
        raise RuntimeErrorBase("orderly handoff rendezvous paths are not owner-only")
    coordinator_pid = pointer.get("coordinator_pid")
    if isinstance(coordinator_pid, bool) or not isinstance(coordinator_pid, int) or coordinator_pid <= 0:
        raise RuntimeErrorBase("orderly handoff coordinator PID is invalid")
    if not isinstance(pointer.get("coordinator_birth_id"), str) or not pointer["coordinator_birth_id"]:
        raise RuntimeErrorBase("orderly handoff coordinator birth identity is invalid")
    deadline = record.get("deadline_monotonic")
    deadline_unix = record.get("deadline_unix_ms")
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(float(deadline))
        or float(deadline) <= time.monotonic()
        or isinstance(deadline_unix, bool)
        or not isinstance(deadline_unix, int)
        or deadline_unix <= int(time.time() * 1000)
    ):
        raise RuntimeErrorBase("orderly handoff deadline is invalid")
    old_owner = record.get("old_owner")
    expected_owner_keys = {"pid", "birth_id", "runtime_instance_id", "runtime"}
    if not isinstance(old_owner, dict) or set(old_owner) != expected_owner_keys:
        raise RuntimeErrorBase("orderly handoff owner identity is invalid")
    pid = old_owner.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid != os.getpid():
        raise RuntimeErrorBase("orderly handoff owner PID is invalid")
    if (
        old_owner.get("birth_id") != process_birth_identity()
        or old_owner.get("runtime_instance_id") != daemon.instance_id
        or old_owner.get("runtime") != daemon.runtime_identity()
    ):
        raise RuntimeErrorBase("orderly handoff request does not match owner A")
    if (
        record.get("realm_id") != daemon.service.realm["id"]
        or not isinstance(record.get("realm_root"), str)
        or Path(record["realm_root"]) != daemon.root
        or record.get("support_root") != str(support_root)
        or record.get("nonce_digest") is not None
        or record.get("sealed_record_digest") is not None
        or record.get("export") is not None
        or record.get("export_sealed_digest") is not None
        or record.get("adopter") is not None
    ):
        raise RuntimeErrorBase("orderly handoff request does not match owner A")
    return pointer, record, socket_path


def _close_inherited_handoff_descriptors(*values: object) -> None:
    for value in set(values):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            continue
        try:
            os.close(value)
        except OSError:
            pass


def _owner_handoff_request(daemon: RuntimeDaemon, support_root: Path) -> bool:
    """Serve one authenticated A-side handoff after SIGUSR1.

    The durable pointer and record carry no raw capability.  The fresh nonce
    exists only on this connected owner-only channel and the transferred
    in-memory frame.
    """

    pointer_path = support_root / _HANDOFF_POINTER
    try:
        observed = pointer_path.lstat()
        if pointer_path.is_symlink() or not stat.S_ISREG(observed.st_mode):
            raise RuntimeErrorBase("orderly handoff pointer is invalid")
        if observed.st_uid != os.getuid() or observed.st_mode & 0o077:
            raise RuntimeErrorBase("orderly handoff pointer is not owner-only")
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeErrorBase("orderly handoff pointer is unavailable") from exc
    if (
        not isinstance(pointer, dict)
        or not isinstance(pointer.get("record_path"), str)
        or not pointer["record_path"]
    ):
        raise RuntimeErrorBase("orderly handoff pointer shape is invalid")
    record = HandoffRecord(Path(pointer["record_path"])).read()
    pointer, record, socket_path = _owned_handoff_request(
        pointer, record, daemon=daemon, support_root=support_root
    )
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    raw_nonce = None
    prepared_handoff = False
    released_handoff = False
    exported_fds: list[int] = []
    try:
        channel.settimeout(max(0.1, float(record["deadline_monotonic"]) - time.monotonic()))
        channel.connect(str(socket_path))
        if (
            peer_uid(channel) != os.getuid()
            or peer_pid(channel) != int(pointer["coordinator_pid"])
            or process_birth_identity(peer_pid(channel)) != pointer["coordinator_birth_id"]
        ):
            raise RuntimeErrorBase("orderly handoff coordinator identity is invalid")
        send_frame(channel, {
            "version": TRANSFER_VERSION,
            "command": "owner_hello",
            "handoff_id": record["handoff_id"],
            "owner_pid": os.getpid(),
            "owner_birth_id": process_birth_identity(),
            "record_digest": record["record_digest"],
        })
        challenge = receive_frame(channel)
        if challenge != {
            "version": TRANSFER_VERSION,
            "command": "seal_challenge",
            "handoff_id": record["handoff_id"],
            "record_digest": record["record_digest"],
        }:
            raise RuntimeErrorBase("orderly handoff seal challenge is invalid")
        raw_nonce = secrets.token_hex(32)
        capability_digest = nonce_digest(raw_nonce)
        send_frame(channel, {
            "version": TRANSFER_VERSION,
            "command": "seal_capability",
            "handoff_id": record["handoff_id"],
            "nonce_digest": capability_digest,
        })
        sealed_ack = receive_frame(channel)
        sealed = HandoffRecord(Path(str(pointer["record_path"]))).read()
        if sealed_ack != {
            "version": TRANSFER_VERSION,
            "command": "sealed",
            "handoff_id": record["handoff_id"],
            "nonce_digest": capability_digest,
            "sealed_record_digest": sealed.get("sealed_record_digest"),
        } or sealed.get("nonce_digest") != capability_digest:
            raise RuntimeErrorBase("orderly handoff sealed record is invalid")
        common = {
            "version": CONTROL_VERSION,
            "handoff_id": record["handoff_id"],
            "nonce_digest": capability_digest,
            "sealed_record_digest": sealed["sealed_record_digest"],
            "sealed_record": sealed,
            "old_owner": {
                "pid": os.getpid(),
                "birth_id": process_birth_identity(),
            },
            "deadline_monotonic": record["deadline_monotonic"],
            "deadline_unix_ms": record["deadline_unix_ms"],
        }
        prepared = daemon.begin_orderly_worker_handoff(common)
        if prepared.get("state") == "active_work":
            send_frame(channel, {
                "version": TRANSFER_VERSION,
                "command": "refused_active_work",
                "handoff_id": record["handoff_id"],
            })
            return False
        prepared_handoff = True
        send_frame(channel, {
            "version": TRANSFER_VERSION,
            "command": "seal_export",
            "handoff_id": record["handoff_id"],
            "sealed_record_digest": sealed["sealed_record_digest"],
            "export": prepared["export"],
        })
        export_sealed = receive_frame(channel)
        bound_record = HandoffRecord(Path(str(pointer["record_path"]))).read()
        if (
            export_sealed != {
                "version": TRANSFER_VERSION,
                "command": "export_sealed",
                "handoff_id": record["handoff_id"],
                "export_sealed_digest": bound_record.get("export_sealed_digest"),
                "export_record_digest": bound_record.get("record_digest"),
            }
            or bound_record.get("export") != prepared["export"]
        ):
            raise RuntimeErrorBase("orderly handoff export seal is invalid")
        daemon.seal_orderly_worker_handoff(
            str(record["handoff_id"]),
            {
                "version": CONTROL_VERSION,
                "command": "handoff_seal",
                "handoff_id": record["handoff_id"],
                "nonce": raw_nonce,
                "nonce_digest": capability_digest,
                "sealed_record_digest": sealed["sealed_record_digest"],
                "export_sealed_digest": bound_record["export_sealed_digest"],
                "export_record_digest": bound_record["record_digest"],
                "export": prepared["export"],
                "old_owner": common["old_owner"],
            },
        )
        transfer = {
            "version": TRANSFER_VERSION,
            "handoff_id": record["handoff_id"],
            "deadline_unix_ms": record["deadline_unix_ms"],
            "deadline_monotonic": record["deadline_monotonic"],
            "nonce": raw_nonce,
            "nonce_digest": capability_digest,
            "sealed_record_digest": sealed["sealed_record_digest"],
            "export_sealed_digest": bound_record["export_sealed_digest"],
            "export_record_digest": bound_record["record_digest"],
            "old_owner": common["old_owner"],
            "old_runtime": prepared["old_runtime"],
            "export": prepared["export"],
        }
        exported_fds = [
            int(prepared["worker_control_fd"]),
            int(prepared["listener_fd"]),
        ]
        send_authority_transfer(
            channel,
            transfer,
            worker_control_fd=exported_fds[0],
            listener_fd=exported_fds[1],
        )
        for descriptor in exported_fds:
            os.close(descriptor)
        exported_fds = []
        accepted = receive_frame(channel)
        if accepted != {
            "version": TRANSFER_VERSION,
            "command": "custody_accepted",
            "handoff_id": record["handoff_id"],
            "sealed_record_digest": sealed["sealed_record_digest"],
        }:
            raise RuntimeErrorBase("orderly handoff custody acknowledgement is invalid")
        daemon.release_orderly_worker_handoff(record["handoff_id"])
        released_handoff = True
        send_frame(channel, {
            "version": TRANSFER_VERSION,
            "command": "owner_released",
            "handoff_id": record["handoff_id"],
            "owner_pid": os.getpid(),
        })
        return True
    except BaseException:
        if prepared_handoff and not released_handoff:
            try:
                daemon.cancel_orderly_worker_handoff(
                    str(record["handoff_id"]), reason_code="coordinator_transfer_failed"
                )
            except BaseException:
                # The original Runtime still owns the graph but could not
                # prove rollback.  Its ordinary stop path performs the
                # verified owned cleanup rather than exporting ambiguity.
                daemon.stop()
        raise
    finally:
        for descriptor in exported_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raw_nonce = None
        channel.close()


def _adopter_handoff_frame(args) -> tuple[socket.socket, dict, tuple[str, int]]:
    supplied = (
        args.handoff_record,
        args.handoff_worker_fd,
        args.handoff_listener_fd,
        args.handoff_capability_fd,
    )
    if not all(value is not None for value in supplied):
        _close_inherited_handoff_descriptors(*supplied)
        raise RuntimeErrorBase("owner B requires every orderly handoff descriptor")
    try:
        capability = socket.socket(fileno=int(args.handoff_capability_fd))
    except BaseException:
        _close_inherited_handoff_descriptors(*supplied)
        raise
    try:
        record_path = HandoffRecord(Path(args.handoff_record))
        while True:
            record = record_path.read()
            remaining = max(
                0.1,
                min(
                    float(record["deadline_monotonic"]) - time.monotonic(),
                    (int(record["deadline_unix_ms"]) - int(time.time() * 1000)) / 1000,
                ),
            )
            capability.settimeout(remaining)
            frame = receive_frame(capability)
            try:
                contender_nonce = frame.get("nonce") if isinstance(frame, dict) else None
                contender_digest = nonce_digest(contender_nonce)
            except RuntimeErrorBase:
                contender_digest = None
            valid = (
                isinstance(frame, dict)
                and record.get("state") == "COMMITTED_ORPHAN"
                and record.get("adopter") is None
                and frame.get("version") == TRANSFER_VERSION
                and frame.get("command") == "adopt"
                and frame.get("handoff_id") == record.get("handoff_id")
                and frame.get("sealed_record_digest") == record.get("sealed_record_digest")
                and frame.get("export_sealed_digest") == record.get("export_sealed_digest")
                and frame.get("committed_record_digest") == record.get("record_digest")
                and frame.get("export") == record.get("export")
                and frame.get("old_owner") == record.get("old_owner")
                and contender_digest == record.get("nonce_digest")
            )
            if valid:
                break
            send_frame(capability, {
                "version": TRANSFER_VERSION,
                "command": "adopt_rejected",
                "handoff_id": record.get("handoff_id"),
                "record_digest": record.get("record_digest"),
            })
            if time.monotonic() >= float(record["deadline_monotonic"]):
                raise RuntimeErrorBase("owner B handoff capability deadline expired")
        old_runtime = frame.get("old_runtime")
        endpoint = str(old_runtime.get("endpoint") or "") if isinstance(old_runtime, dict) else ""
        parsed = urlsplit(endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.port is None:
            raise RuntimeErrorBase("owner B handoff endpoint is invalid")
        expected = (parsed.hostname, int(parsed.port))
        validate_inherited_authority_descriptors(
            int(args.handoff_worker_fd), int(args.handoff_listener_fd),
            expected_listener=expected,
        )
    except BaseException:
        capability.close()
        _close_inherited_handoff_descriptors(
            args.handoff_worker_fd, args.handoff_listener_fd,
        )
        raise
    return capability, frame, expected


def _retry_same_adopter_step(deadline_monotonic: float, operation):
    """Retry only transport-shaped lost acknowledgements for the bound owner B."""

    last_error = None
    for _attempt in range(3):
        try:
            return operation()
        except (OSError, TimeoutError) as exc:
            last_error = exc
            if time.monotonic() >= deadline_monotonic:
                break
            time.sleep(min(0.02, max(0.0, deadline_monotonic - time.monotonic())))
    assert last_error is not None
    raise last_error


def _complete_adopter_publication(
    daemon: RuntimeDaemon,
    handoff_record: HandoffRecord,
    handoff_frame: dict[str, object],
    handoff_result: dict[str, object],
) -> dict[str, object]:
    """Finalize B with durable checkpoints while claim admission stays closed."""

    handoff_id = str(handoff_frame["handoff_id"])
    sealed_record_digest = str(handoff_frame["sealed_record_digest"])
    deadline_monotonic = float(handoff_frame["deadline_monotonic"])
    birth_id = process_birth_identity()
    expected_owner = {
        "pid": os.getpid(),
        "birth_id": birth_id,
        "runtime_instance_id": daemon.instance_id,
        "runtime": daemon.runtime_identity(),
    }
    observed = handoff_record.read()
    if observed.get("state") == "COMMITTED_ORPHAN":
        finalizing = handoff_record.transition(
            expected_state="COMMITTED_ORPHAN",
            new_state="FINALIZING",
            handoff_id=handoff_id,
            sealed_record_digest=sealed_record_digest,
            expected_record_digest=str(handoff_frame["adopter_record_digest"]),
            updates={
                "new_owner": expected_owner,
                "result": dict(handoff_result),
                "finalization": {
                    "final_ack": None,
                    "ready_surfaces": False,
                },
            },
        )
    elif observed.get("state") in {"FINALIZING", "ADOPTED"}:
        if (
            observed.get("handoff_id") != handoff_id
            or observed.get("sealed_record_digest") != sealed_record_digest
            or observed.get("new_owner") != expected_owner
            or observed.get("result") != dict(handoff_result)
            or observed.get("adopter") != {
                "pid": os.getpid(),
                "birth_id": birth_id,
                "runtime_instance_id": daemon.instance_id,
            }
        ):
            raise RuntimeErrorBase("only the bound owner B may resume finalization")
        if observed.get("state") == "ADOPTED":
            daemon.open_orderly_handoff_claims(handoff_id, observed)
            return observed
        finalizing = observed
    else:
        raise RuntimeErrorBase("orderly handoff is not resumable by owner B")

    checkpoints = finalizing.get("finalization")
    if not isinstance(checkpoints, dict) or set(checkpoints) != {
        "final_ack", "ready_surfaces",
    }:
        raise RuntimeErrorBase("orderly handoff finalization checkpoints are invalid")
    if checkpoints["final_ack"] is None:
        final_ack = _retry_same_adopter_step(
            deadline_monotonic,
            lambda: daemon.finalize_orderly_handoff(handoff_id),
        )
        if (
            not isinstance(final_ack, dict)
            or set(final_ack) != {
                "request_digest", "worker_ack_digest", "host_ack_digest", "ack",
            }
        ):
            raise RuntimeErrorBase("Runtime final acknowledgement evidence is invalid")
        finalizing = handoff_record.checkpoint_finalizing(
            handoff_id=handoff_id,
            sealed_record_digest=sealed_record_digest,
            expected_record_digest=str(finalizing["record_digest"]),
            final_ack={
                key: str(final_ack[key])
                for key in (
                    "request_digest", "worker_ack_digest", "host_ack_digest",
                )
            },
            ready_surfaces=False,
        )
        checkpoints = finalizing["finalization"]
    if not checkpoints["ready_surfaces"]:
        _retry_same_adopter_step(
            deadline_monotonic,
            lambda: daemon.publish_orderly_handoff_surfaces(handoff_id),
        )
        finalizing = handoff_record.checkpoint_finalizing(
            handoff_id=handoff_id,
            sealed_record_digest=sealed_record_digest,
            expected_record_digest=str(finalizing["record_digest"]),
            final_ack=dict(checkpoints["final_ack"]),
            ready_surfaces=True,
        )
    daemon.arm_orderly_handoff_claims(handoff_id, finalizing)
    adopted = handoff_record.transition(
        expected_state="FINALIZING",
        new_state="ADOPTED",
        handoff_id=handoff_id,
        sealed_record_digest=sealed_record_digest,
        expected_record_digest=str(finalizing["record_digest"]),
        updates={
            "publication_predecessor_digest": str(finalizing["record_digest"]),
        },
    )
    daemon.open_orderly_handoff_claims(handoff_id, adopted)
    return adopted


def _abort_failed_adopter_after_cleanup(
    daemon: RuntimeDaemon,
    handoff_record: HandoffRecord | None,
    handoff_frame: dict[str, object] | None,
) -> Exception | None:
    """Write ABORTED only after B proves complete graph/listener cleanup."""

    observed_before = None
    if handoff_record is not None:
        try:
            observed_before = handoff_record.read()
        except Exception:
            observed_before = None
    terminal_audit = (
        isinstance(observed_before, dict)
        and observed_before.get("state") == "ADOPTED"
    )
    if terminal_audit:
        try:
            daemon.latch_orderly_handoff_operator_audit(
                record_path=str(handoff_record.path),
                record=observed_before,
                reason="post_adopted_publication_invariant_failed",
            )
        except Exception as audit_error:
            return audit_error
    try:
        daemon.stop()
    except Exception as cleanup_error:
        # RuntimeDaemon.stop durably latches cleanup uncertainty.  Retain the
        # custody state so neither a new owner nor replacement graph can claim
        # that the old authority was safely destroyed.
        return cleanup_error
    cleanup_proof = daemon.last_handoff_cleanup_proof()
    if not isinstance(cleanup_proof, dict) or cleanup_proof.get("complete") is not True:
        return RuntimeErrorBase("owner B cleanup proof is incomplete")
    if terminal_audit:
        return RuntimeErrorBase(
            "durable ADOPTED publication requires explicit operator audit"
        )
    if handoff_record is not None and handoff_frame is not None:
        try:
            observed = handoff_record.read()
            if observed.get("state") in {"COMMITTED_ORPHAN", "FINALIZING"}:
                failed_state = str(observed["state"])
                aborted = handoff_record.transition(
                    expected_state=failed_state,
                    new_state="ABORTED",
                    handoff_id=str(handoff_frame["handoff_id"]),
                    sealed_record_digest=str(handoff_frame["sealed_record_digest"]),
                    expected_record_digest=str(observed["record_digest"]),
                    updates={
                        "abort_reason": "owner_b_start_failed",
                        "cleanup_receipt": cleanup_proof,
                        "cleanup_receipt_digest": digest(cleanup_proof),
                    },
                )
                if (
                    isinstance(aborted, dict)
                    and aborted.get("predecessor_active_ref_digest") is not None
                ):
                    _resolve_aborted_predecessor(
                        daemon.support_root,
                        handoff_record=handoff_record,
                        aborted=aborted,
                    )
        except Exception as record_error:
            return record_error
    return None


def _emit_post_admission_report(value: dict[str, object]) -> None:
    """Best-effort operator output after authority is already published.

    A closed stdout is observational. It must not unwind the owner loop and
    destroy an authenticated, claim-ready Runtime graph.
    """

    try:
        print(json.dumps(value, sort_keys=True), flush=True)
    except (BrokenPipeError, OSError):
        try:
            descriptor = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(descriptor, sys.stdout.fileno())
            finally:
                os.close(descriptor)
        except (OSError, ValueError):
            pass


def _attempt_owner_handoff(daemon: RuntimeDaemon, support_root: Path) -> bool:
    """Reject unauthenticated A-side requests without entering stop cleanup."""

    try:
        return _owner_handoff_request(daemon, support_root)
    except (RuntimeErrorBase, OSError, TimeoutError, KeyError, TypeError, ValueError) as exc:
        if daemon.local_worker_launcher is None:
            raise
        # The coordinator sees only a closed authenticated channel when A
        # rejects after rendezvous.  Preserve one credential-safe diagnostic in
        # A's existing stderr/runtime log so an installed failure can be
        # distinguished without weakening the fail-closed handoff boundary.
        if isinstance(exc, RuntimeErrorBase):
            details = exc.details if isinstance(exc.details, dict) else {}
            handoff_error_code = details.get("handoff_error_code")
            handoff_stage = details.get("handoff_stage")
            diagnostic = {
                "event": "orderly_handoff_owner_a_refused",
                "error_code": (
                    handoff_error_code
                    if isinstance(handoff_error_code, str)
                    else exc.code
                ),
                "stage": (
                    handoff_stage
                    if isinstance(handoff_stage, str)
                    else "owner_a_request"
                ),
            }
        else:
            diagnostic = {
                "event": "orderly_handoff_owner_a_refused",
                "error_code": "owner_handoff_error",
                "stage": "owner_a_request",
            }
        try:
            print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr, flush=True)
        except (BrokenPipeError, OSError, ValueError):
            pass
        return False


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "identity":
        from . import release_identity
        try:
            if args.operation == "verify":
                if not args.receipt:
                    raise release_identity.ReleaseIdentityError("identity verify requires --receipt")
                result = {"ok": True, "identity": release_identity.load_receipt(args.receipt)["identity"]}
            else:
                components = {}
                for value in args.component:
                    if "=" not in value:
                        raise release_identity.ReleaseIdentityError("--component must use COMPONENT_ID=CHECKOUT")
                    component, checkout = value.split("=", 1)
                    components[component] = checkout
                if args.operation == "pre-live":
                    result = release_identity.create_pre_live_identity(components, output=args.output)
                else:
                    if not args.pre_live:
                        raise release_identity.ReleaseIdentityError("candidate-core requires --pre-live")
                    result = release_identity.create_candidate_core_identity(args.pre_live, components, output=args.output)
            print(json.dumps(result, sort_keys=True, indent=2))
            return 0
        except release_identity.ReleaseIdentityError as exc:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
            return 1
    if args.command == "doctor":
        root = Path(args.root)
        result = RealmStore.inspect_realm(
            root,
            catalog_path=(Path(args.support_root) / "catalog.json") if args.support_root else None,
        )
        if result.get("state") == "uninitialized":
            result["next_action"] = "banodoco-runtime create --root <realm>"
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("ok") else 1
    if args.command == "upgrade":
        try:
            result = upgrade_realm(
                args.root,
                archive_root=args.archive_root,
                timeout_seconds=args.timeout,
                confirmation=args.confirm,
            )
        except RuntimeErrorBase as exc:
            print(json.dumps({"ok": False, "error": exc.as_dict()}, sort_keys=True))
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "migrate-variant-state":
        try:
            result = migrate_canonical_v24_to_v25(
                args.root,
                timeout_seconds=args.timeout,
                confirmation=args.confirm,
            )
        except RuntimeErrorBase as exc:
            print(json.dumps({"ok": False, "error": exc.as_dict()}, sort_keys=True))
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "migrate-managed-outputs":
        try:
            result = migrate_historical_managed_outputs(
                args.root,
                project_id=args.project_id,
                task_id=args.task_id,
                timeout_seconds=args.timeout,
                confirmation=args.confirm,
            )
        except RuntimeErrorBase as exc:
            print(json.dumps({"ok": False, "error": exc.as_dict()}, sort_keys=True))
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "repair-media-types":
        try:
            result = repair_generic_media_types(
                args.root,
                project_id=args.project_id,
                task_id=args.task_id,
                generation_id=args.generation_id,
                timeout_seconds=args.timeout,
                confirmation=args.confirm,
            )
        except RuntimeErrorBase as exc:
            print(json.dumps({"ok": False, "error": exc.as_dict()}, sort_keys=True))
            return 1
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "create":
        store = RealmStore.initialize(args.root, display_name=args.display_name, realm_id=args.realm_id)
        try:
            result = {"state": "created", "realm_id": store.realm["id"], "root": str(store.root)}
        finally:
            store.close()
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "backup":
        # Online backup goes through the owning HTTP service. The CLI is an
        # offline surface and must acquire that same realm-owner fence.
        store = RealmStore(args.root)
        try:
            key_path = (Path(args.support_root).expanduser().resolve() / "backup-auth.key") if args.support_root else None
            result = create_backup(store, args.destination, key_path=key_path)
        finally:
            store.close()
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "restore":
        result = restore_backup(args.backup, args.destination)
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "replace":
        root = Path(args.root).expanduser().resolve()
        daemon = RuntimeDaemon(root, support_root=args.support_root, display_name=args.display_name, realm_id=args.realm_id, production_worker_credentials=True)
        try:
            # Replacement is coordinated offline so a damaged active root is
            # never admitted merely to reach the recovery command.
            result = daemon.replace_from_backup(args.backup)
        finally:
            daemon.stop()
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "export":
        # Export is an offline surface; share the same owner fence as startup
        # instead of opening a second connection with a different authority.
        store = RealmStore(args.root)
        try:
            value = structured_export(store)
        finally:
            store.close()
        if args.destination:
            from .util import atomic_json_write
            atomic_json_write(Path(args.destination).expanduser().resolve(), value)
        print(json.dumps(value, sort_keys=True))
        return 0
    if args.command == "purge":
        root = Path(args.root).expanduser().resolve()
        # Refuse even a correctly confirmed purge while a daemon owns the
        # realm.  The destructive operation remains explicit and offline.
        store = RealmStore(root)
        try:
            realm_id = store.realm["id"]
            if args.confirm != f"PURGE {realm_id}":
                raise SystemExit(f"confirmation must be exactly: PURGE {realm_id}")
            if store.realm_lifecycle()["state"] != "tombstoned":
                raise SystemExit("realm must be tombstoned before purge")
        finally:
            store.close()
        shutil.rmtree(root)
        print(json.dumps({"state": "purged", "realm_id": realm_id, "root": str(root)}, sort_keys=True))
        return 0
    daemon = None
    capability_channel = None
    handoff_frame = None
    handoff_record = None
    try:
        composition = None
        if getattr(args, "worker_profile", None):
            if not args.realm_id:
                raise RuntimeErrorBase("--worker-profile requires --realm-id")
            composition = load_local_worker_composition(
                args.worker_profile,
                workspace_uuid=args.realm_id,
                realm_root=Path(args.root).expanduser().resolve(),
                support_root=Path(args.support_root).expanduser().resolve() if args.support_root else Path(args.root).expanduser().resolve() / "support",
                runtime_instance_id="pending-startup",
            )
        handoff_supplied = any(
            value is not None
            for value in (
                args.handoff_record, args.handoff_worker_fd,
                args.handoff_listener_fd, args.handoff_capability_fd,
            )
        )
        if handoff_supplied:
            if composition is None:
                raise RuntimeErrorBase("orderly handoff requires the installed Worker profile")
            capability_channel, handoff_frame, _expected_listener = _adopter_handoff_frame(args)
            handoff_record = HandoffRecord(Path(args.handoff_record))
            handoff_record_value = handoff_record.read()
            # Start with health-only admission.  The host can construct B's
            # exact epoch-bound registration body only after rebind_prepare;
            # daemon.adopt_orderly_worker_handoff installs that preview before
            # enabling the retained bearer and issuing rebind_commit.
            actor = "astrid-pack-host"
            registration_bodies = {
                "/v1/capabilities": [],
                "/v1/executors": [],
            }
        else:
            actor, registration_bodies = None, None
        daemon = RuntimeDaemon(
            args.root,
            support_root=args.support_root,
            export_root=args.export_root,
            display_name=args.display_name,
            host=args.host,
            port=args.port,
            realm_id=args.realm_id,
            owner_lock=args.owner_lock,
            bootstrap_token_file=args.bootstrap_token_file,
            production_worker_credentials=True,
            admission_timeout=args.admission_timeout,
            local_worker_profiles=composition.profiles if composition else None,
            local_worker_preparer=composition.preparer if composition else None,
            local_worker_inspector=composition.inspector if composition else None,
            inherited_listener_fd=args.handoff_listener_fd if handoff_supplied else None,
            handoff_registration_actor=actor,
            handoff_registration_bodies=registration_bodies,
            handoff_predecessor_active_ref_digest=(
                handoff_record_value.get("predecessor_active_ref_digest")
                if handoff_supplied else None
            ),
            handoff_predecessor_old_owner=(
                handoff_frame.get("old_owner") if handoff_supplied else None
            ),
            handoff_id=(
                handoff_record_value.get("handoff_id") if handoff_supplied else None
            ),
            handoff_record_path=(
                Path(args.handoff_record) if handoff_supplied else None
            ),
            handoff_record_path_raw=(
                args.handoff_record if handoff_supplied else None
            ),
            handoff_record_digest=(
                handoff_record_value.get("record_digest")
                if handoff_supplied else None
            ),
            handoff_expected_listener=(
                _expected_listener if handoff_supplied else None
            ),
        ).start()
        handoff_result = None
        if handoff_supplied:
            handoff_frame = dict(handoff_frame)
            handoff_frame["worker_control_fd"] = int(args.handoff_worker_fd)
            send_frame(capability_channel, {
                "version": TRANSFER_VERSION,
                "command": "descriptors_accepted",
                "handoff_id": handoff_frame["handoff_id"],
                "runtime_pid": os.getpid(),
                "runtime_birth_id": process_birth_identity(),
                "runtime_instance_id": daemon.instance_id,
            })
            adopter_bound = receive_frame(capability_channel)
            observed_bound = handoff_record.read()
            expected_adopter = {
                "pid": os.getpid(),
                "birth_id": process_birth_identity(),
                "runtime_instance_id": daemon.instance_id,
            }
            if (
                adopter_bound != {
                    "version": TRANSFER_VERSION,
                    "command": "adopter_bound",
                    "handoff_id": handoff_frame["handoff_id"],
                    "adopter_record_digest": observed_bound.get("record_digest"),
                    "adopter": expected_adopter,
                }
                or observed_bound.get("state") != "COMMITTED_ORPHAN"
                or observed_bound.get("adopter") != expected_adopter
            ):
                raise RuntimeErrorBase("owner B sole-adopter binding is invalid")
            handoff_frame["adopter_record_digest"] = observed_bound["record_digest"]
            handoff_frame["new_owner"] = {
                "pid": os.getpid(),
                "birth_id": process_birth_identity(),
            }
            capability_channel.close()
            capability_channel = None
            handoff_result = daemon.adopt_orderly_worker_handoff(handoff_frame)
            _retry_same_adopter_step(
                float(handoff_frame["deadline_monotonic"]),
                lambda: _complete_adopter_publication(
                    daemon, handoff_record, handoff_frame, handoff_result
                ),
            )
            # Drop the only product-process reference to the raw capability.
            handoff_frame.pop("nonce", None)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        if capability_channel is not None:
            capability_channel.close()
        cleanup_error = None
        if daemon is not None:
            cleanup_error = _abort_failed_adopter_after_cleanup(
                daemon, handoff_record, handoff_frame
            )
        # Installed operator entrypoints must fail as a stable JSON boundary;
        # never leak a traceback for an unsupported format or bad root.
        effective_error = cleanup_error or exc
        error = effective_error.as_dict() if isinstance(effective_error, RuntimeErrorBase) else {"code": "startup_error", "message": str(effective_error)}
        print(json.dumps({"ok": False, "error": error}, sort_keys=True))
        return 1
    _emit_post_admission_report({"endpoint": daemon.endpoint, "realm_id": daemon.service.realm["id"], "credential_file": str(daemon.credential_path), "worker_credential_file": str(daemon.worker_credential_path), "worker_actor": "astrid-pack-host", "worker_scopes": list(WORKER_SCOPES), "worker_profile_configured": bool(daemon.local_worker_profiles), "orderly_handoff": handoff_result})
    stop = False
    handoff_requested = False
    def handle(*_):
        nonlocal stop
        stop = True
    def request_handoff(*_):
        nonlocal handoff_requested
        handoff_requested = True
    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, request_handoff)
    relinquished = False
    try:
        while not stop:
            if handoff_requested:
                handoff_requested = False
                try:
                    relinquished = _attempt_owner_handoff(
                        daemon, Path(args.support_root).expanduser().resolve()
                    )
                except RuntimeErrorBase:
                    stop = True
                    break
                if relinquished:
                    break
            time.sleep(0.2)
    finally:
        if not relinquished:
            try:
                daemon.stop()
            finally:
                if args.handoff_record:
                    handoff_path = Path(args.handoff_record)
                    parent = handoff_path.parent
                    try:
                        identity = parent.lstat()
                        if (
                            parent.name.startswith(f"astrid-handoff-{os.getuid()}-")
                            and
                            not parent.is_symlink()
                            and stat.S_ISDIR(identity.st_mode)
                            and identity.st_uid == os.getuid()
                            and stat.S_IMODE(identity.st_mode) == 0o700
                        ):
                            shutil.rmtree(parent)
                    except OSError:
                        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
