from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

from .auth import CredentialStore
from .catalog import LiveDiscovery, RealmCatalog, process_birth_identity
from .server import RuntimeHTTPServer, RuntimeHandler
from .service import RuntimeService
from .util import atomic_json_write


class RuntimeDaemon:
    """Loopback-only daemon owning one realm and its storage."""

    def __init__(self, root, *, support_root=None, display_name="Workspace", host="127.0.0.1", port=0, realm_id=None, owner_lock=None, bootstrap_token_file=None, reboot_executor=None, reboot_allowlist=None):
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("runtime daemon only binds to loopback")
        self.root = Path(root).expanduser().resolve()
        self.support_root = Path(support_root).expanduser().resolve() if support_root else self.root / "support"
        self.host, self.port, self.display_name = host, port, display_name
        self.realm_id = realm_id
        self.owner_lock = Path(owner_lock).expanduser().resolve() if owner_lock else None
        self.bootstrap_token_file = Path(bootstrap_token_file).expanduser().resolve() if bootstrap_token_file else None
        # Reboot is deliberately disabled unless a host supplies an executor.
        # The service additionally validates that any configured command is in
        # its small, explicit allowlist.
        self.reboot_executor = reboot_executor
        self.reboot_allowlist = reboot_allowlist
        self.instance_id = uuid.uuid4().hex
        self.service = None
        self.httpd = None
        self.thread = None
        self.catalog = RealmCatalog(self.support_root / "catalog.json")
        self.discovery = LiveDiscovery(self.support_root / "discovery.json")
        self.credentials = CredentialStore(self.support_root / "credentials")
        self.token = None
        self.worker_token = None
        self.credential_path = None

    @property
    def endpoint(self):
        if not self.httpd:
            return None
        host = "127.0.0.1" if self.host == "localhost" else self.host
        return f"http://{host}:{self.httpd.server_port}"

    def start(self):
        if self.httpd:
            return self
        self.service = RuntimeService(self.root, display_name=self.display_name, realm_id=self.realm_id, support_root=self.support_root, reboot_executor=self.reboot_executor, reboot_allowlist=self.reboot_allowlist)
        self.token, self.credential_path = self.credentials.provision("owner", ["admin", "handshake", "projects:read", "projects:write", "objects:read", "objects:write", "tasks:read", "tasks:write", "worker:execute", "worker:register", "credentials:provision"])
        self.worker_token, _ = self.credentials.provision("fake-worker", ["handshake", "worker:execute", "tasks:read"])
        if self.bootstrap_token_file and self.bootstrap_token_file.exists():
            bootstrap_token = self.bootstrap_token_file.read_text(encoding="utf-8").strip()
            self.credentials.provision_static("bootstrap", bootstrap_token, ["admin", "credentials:provision"])
            self.bootstrap_token_file.unlink(missing_ok=True)
        self.httpd = RuntimeHTTPServer((self.host, self.port), RuntimeHandler)
        self.httpd.runtime = self.service
        self.httpd.credentials = self.credentials
        self.catalog.register(realm_id=self.service.realm["id"], display_name=self.service.realm["display_name"], data_root=str(self.root))
        birth_id = process_birth_identity()
        if self.owner_lock:
            atomic_json_write(self.owner_lock, {"pid": os.getpid(), "process_birth_id": birth_id, "runtime_instance_id": self.instance_id, "realm_id": self.service.realm["id"]})
        self.discovery.publish(version=1, endpoint=self.endpoint, pid=os.getpid(), process_birth_id=birth_id, runtime_instance_id=self.instance_id, active_realm=self.service.realm["id"], instance_id=self.instance_id, realm_id=self.service.realm["id"], protocol_version="workspace.v1", schema_version="workspace-schema-v1", coordinator_epoch=self.instance_id, credential_file=str(self.credential_path))
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="banodoco-runtime", daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        self.discovery.clear(self.instance_id)
        if self.service:
            self.service.close()
            self.service = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()
