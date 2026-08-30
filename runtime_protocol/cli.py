from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path

from .daemon import RuntimeDaemon
from .backup import create_backup, restore_backup, structured_export
from .store import RealmStore


def _parser():
    parser = argparse.ArgumentParser(prog="banodoco-runtime", description="Neutral loopback workspace runtime")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start", help="start the loopback daemon")
    start.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    start.add_argument("--support-root")
    start.add_argument("--host", default="127.0.0.1")
    start.add_argument("--port", type=int, default=0)
    start.add_argument("--display-name", default="Workspace")
    start.add_argument("--realm-id")
    start.add_argument("--owner-lock")
    start.add_argument("--bootstrap-token-file")
    doctor = sub.add_parser("doctor", help="read-only runtime health check")
    doctor.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    doctor.add_argument("--json", action="store_true")
    backup = sub.add_parser("backup", help="create a verified self-contained realm backup")
    backup.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    backup.add_argument("--destination", required=True)
    restore = sub.add_parser("restore", help="restore a backup into a new inactive realm")
    restore.add_argument("--backup", required=True)
    restore.add_argument("--destination", required=True)
    export = sub.add_parser("export", help="export structured realm state")
    export.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    export.add_argument("--destination")
    export.add_argument("--json", action="store_true")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "doctor":
        root = Path(args.root)
        if not root.exists() or not (root / "realm.sqlite3").exists():
            result = {"state": "uninitialized", "ok": True, "next_action": "banodoco-runtime start"}
        else:
            try:
                store = RealmStore(root, acquire_owner=False)
                result = store.doctor()
                store.close()
            except Exception as exc:
                result = {"state": "unhealthy", "ok": False, "error": str(exc)}
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("ok") else 1
    if args.command == "backup":
        store = RealmStore(args.root, acquire_owner=False)
        try:
            result = create_backup(store, args.destination)
        finally:
            store.close()
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "restore":
        result = restore_backup(args.backup, args.destination)
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "export":
        store = RealmStore(args.root, acquire_owner=False)
        try:
            value = structured_export(store)
        finally:
            store.close()
        if args.destination:
            from .util import atomic_json_write
            atomic_json_write(Path(args.destination).expanduser().resolve(), value)
        print(json.dumps(value, sort_keys=True))
        return 0
    daemon = RuntimeDaemon(args.root, support_root=args.support_root, display_name=args.display_name, host=args.host, port=args.port, realm_id=args.realm_id, owner_lock=args.owner_lock, bootstrap_token_file=args.bootstrap_token_file).start()
    print(json.dumps({"endpoint": daemon.endpoint, "realm_id": daemon.service.realm["id"], "credential_file": str(daemon.credential_path)}, sort_keys=True), flush=True)
    stop = False
    def handle(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)
    try:
        while not stop:
            time.sleep(0.2)
    finally:
        daemon.stop()
    return 0
