from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path

from .daemon import RuntimeDaemon
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
    doctor = sub.add_parser("doctor", help="read-only runtime health check")
    doctor.add_argument("--root", default=os.environ.get("BANODOCO_RUNTIME_ROOT", ".runtime"))
    doctor.add_argument("--json", action="store_true")
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
    daemon = RuntimeDaemon(args.root, support_root=args.support_root, display_name=args.display_name, host=args.host, port=args.port).start()
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
