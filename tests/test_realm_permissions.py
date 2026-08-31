from __future__ import annotations

import stat

from runtime_protocol.daemon import RuntimeDaemon


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_realm_support_tree_is_owner_only(tmp_path):
    realm = tmp_path / "realm"
    support = tmp_path / "support"
    daemon = RuntimeDaemon(realm, support_root=support).start()
    try:
        assert _mode(realm) == 0o700
        assert _mode(realm / "cas") == 0o700
        assert _mode(realm / "cas" / "sha256") == 0o700
        assert _mode(realm / "staging") == 0o700
        assert _mode(realm / "realm.sqlite3") == 0o600
        assert _mode(realm / "owner.lock") == 0o600
    finally:
        daemon.stop()
