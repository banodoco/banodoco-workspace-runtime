from __future__ import annotations

import inspect

from runtime_protocol.service import RuntimeService
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.store import RealmStore


def test_task_level_settlement_surface_is_absent() -> None:
    handler_source = inspect.getsource(RuntimeHandler)
    assert "self.runtime.settle(" not in handler_source
    assert "self.runtime.settle_attempt(path[2]" in handler_source
    assert not hasattr(RuntimeService, "settle")
    assert not hasattr(RealmStore, "settle_task")
