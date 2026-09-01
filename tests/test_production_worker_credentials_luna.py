from __future__ import annotations

import json
import stat

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES


def test_pack_host_credential_is_scoped_distinct_and_persistent(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    first = RuntimeDaemon(
        root,
        support_root=support,
        production_worker_credentials=True,
    ).start()
    try:
        worker_path = first.worker_credential_path
        assert worker_path is not None
        assert worker_path == support / "credentials" / "astrid-pack-host.token"
        assert first.worker_token != first.token
        assert stat.S_IMODE(worker_path.stat().st_mode) == 0o600
        metadata_path = worker_path.with_suffix(".json")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        assert metadata == {"actor": WORKER_ACTOR, "scopes": sorted(WORKER_SCOPES)}
        worker_token = worker_path.read_text(encoding="utf-8").strip()

        # A pack host can perform worker work but cannot inherit owner/admin
        # project authority merely because it was launched by the runtime.
        with pytest.raises(RuntimeError) as forbidden:
            Api(first.endpoint, worker_token).create_project("not-owner", "Not Owner")
        assert forbidden.value.status == 401
    finally:
        first.stop()

    second = RuntimeDaemon(
        root,
        support_root=support,
        production_worker_credentials=True,
    ).start()
    try:
        assert second.worker_credential_path == worker_path
        assert second.worker_token == worker_token
        assert json.loads(second.worker_credential_path.with_suffix(".json").read_text(encoding="utf-8")) == metadata
    finally:
        second.stop()
