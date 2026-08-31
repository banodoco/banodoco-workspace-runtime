"""Concrete local boundary for the neutral workspace runtime.

The bootstrap package deliberately does not import the runtime implementation.
This module is the small adapter that turns an editable source profile into a
real loopback daemon process and a generated-client-shaped connection.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Mapping

from .bootstrap import BootstrapError, SourceProfile


PROTOCOL_VERSION = "workspace.v1"
WIRE_PROTOCOL = PROTOCOL_VERSION
SCHEMA_VERSION = "workspace-schema-v1"
WAIT_SECONDS = 10.0


class RuntimeConnection:
    """Generated-client compatible connection plus bootstrap-only provisioning."""

    def __init__(self, endpoint: str, credential: str, bootstrap_credential: str | None = None):
        self.endpoint = endpoint.rstrip("/")
        self.credential = credential
        self.bootstrap_credential = bootstrap_credential
        self._client = None

    def _generated(self):
        if self._client is None:
            raise RuntimeError("generated client is unavailable")
        return self._client

    def __getattr__(self, name):
        return getattr(self._generated(), name)

    def _request(self, method: str, path: str, body: Mapping[str, Any], token: str):
        encoded = json.dumps(dict(body), separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.endpoint + path,
            data=encoded,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8"))
            except Exception:
                detail = {"message": str(exc)}
            raise BootstrapError(f"Runtime credential provisioning failed: {detail}") from exc

    def provision_actor(self, *, scope: str, actor_id: str, credential: str):
        # On reconnect the one-time bootstrap credential is gone. The actor
        # credential is already durable, so provisioning is intentionally a
        # no-op in that case.
        if self.bootstrap_credential:
            value = self._request(
                "POST",
                "/v1/credentials",
                {
                    "actor_id": actor_id,
                    "credential": credential,
                    "scope": scope,
                },
                self.bootstrap_credential,
            )
            if value.get("scope") != scope:
                raise BootstrapError("Runtime returned an unexpected credential scope.")
        return {"scope": scope, "actor_id": actor_id}

    def select_realm(self, *, actor_id: str, realm_id: str):
        # Realm selection is represented durably by the neutral catalog. The
        # runtime has one realm per process in Stage 1, so no extra API call is
        # needed here; retaining this method keeps the generated seam explicit.
        return {"actor_id": actor_id, "realm_id": realm_id}

    def handshake(self, **kwargs):
        # The generated client uses the canonical handshake signature while the
        # bootstrap protocol passes version keywords. Bridge both shapes.
        requested = [
            "projects:read", "projects:write", "objects:read", "objects:write",
            "tasks:read", "tasks:write",
        ]
        return self._generated().handshake("astrid-local", "0.1.0", requested)


class LocalRuntimeBoundary:
    """Launch and supervise a loopback daemon from an editable source profile."""

    def __init__(self, *, wait_seconds: float = WAIT_SECONDS):
        self.wait_seconds = wait_seconds
        self._process: subprocess.Popen[str] | None = None
        self._source: SourceProfile | None = None
        self._realm_root: Path | None = None
        self._support_root: Path | None = None
        self._realm_id: str | None = None
        self._display_name = "Astrid Workspace"
        self._bootstrap_credential: str | None = None
        self._detached_pid: int | None = None

    @staticmethod
    def _validate_checkout(source: SourceProfile) -> Path:
        checkout = Path(source.runtime_checkout).expanduser().resolve()
        if not checkout.is_dir() or not (checkout / "runtime_protocol").is_dir():
            raise BootstrapError(f"Runtime checkout is not an editable runtime source: {checkout}")
        source_checkout = Path(source.source_checkout).expanduser().resolve()
        if not source_checkout.exists():
            raise BootstrapError(f"Source checkout from the editable profile does not exist: {source_checkout}")
        return checkout

    def configure_source(self, source: SourceProfile) -> None:
        self._source = source

    @staticmethod
    def _token_file(support_root: Path, token: str) -> Path:
        support_root.mkdir(parents=True, exist_ok=True)
        support_root.chmod(0o700)
        fd, name = tempfile.mkstemp(prefix=".bootstrap-token-", dir=support_root)
        path = Path(name)
        path.chmod(0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(token)
            handle.flush()
            os.fsync(handle.fileno())
        return path

    def _argv(self, source: SourceProfile, *, realm_id: str, realm_root: Path, support_root: Path, display_name: str, owner_lock: Path, token_file: Path) -> list[str]:
        checkout = self._validate_checkout(source)
        if source.runtime_command:
            argv = list(source.runtime_command)
        else:
            python = sys.executable
            if source.runtime_environment:
                candidate = Path(source.runtime_environment).expanduser().resolve() / "bin" / "python"
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    python = str(candidate)
            argv = [python, "-m", "runtime_protocol", "start"]
        replacements = {
            "{realm_id}": realm_id,
            "{realm_root}": str(realm_root),
            "{support_root}": str(support_root),
            "{display_name}": display_name,
            "{owner_lock}": str(owner_lock),
            "{bootstrap_token_file}": str(token_file),
        }
        argv = [replacements.get(part, part) for part in argv]
        if not any("--root" == part for part in argv):
            argv += ["--root", str(realm_root)]
        if not any("--support-root" == part for part in argv):
            argv += ["--support-root", str(support_root)]
        if not any("--display-name" == part for part in argv):
            argv += ["--display-name", display_name]
        if not any("--realm-id" == part for part in argv):
            argv += ["--realm-id", realm_id]
        if not any("--owner-lock" == part for part in argv):
            argv += ["--owner-lock", str(owner_lock)]
        if not any("--bootstrap-token-file" == part for part in argv):
            argv += ["--bootstrap-token-file", str(token_file)]
        return argv

    def start(self, *, realm_id: str, realm_root: Path, owner_lock: Path, source_profile: SourceProfile) -> Mapping[str, Any]:
        if self._process and self._process.poll() is None:
            raise BootstrapError("runtime boundary already owns a live daemon")
        realm_root = Path(realm_root).expanduser().resolve()
        support_root = owner_lock.parent.expanduser().resolve()
        bootstrap_token = os.urandom(32).hex()
        token_file = self._token_file(support_root, bootstrap_token)
        argv = self._argv(source_profile, realm_id=realm_id, realm_root=realm_root, support_root=support_root, display_name=self._display_name, owner_lock=owner_lock, token_file=token_file)
        checkout = self._validate_checkout(source_profile)
        log_path = support_root / "runtime.log"
        log = log_path.open("ab")
        try:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(checkout) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
            self._process = subprocess.Popen(argv, cwd=str(checkout), env=env, stdout=subprocess.DEVNULL, stderr=log, text=True, start_new_session=True)
        except Exception:
            log.close()
            token_file.unlink(missing_ok=True)
            raise
        finally:
            log.close()
        self._source, self._realm_root, self._support_root, self._realm_id = source_profile, realm_root, support_root, realm_id
        self._bootstrap_credential = bootstrap_token
        endpoint = self._wait_endpoint(support_root, self._process)
        return {
            "endpoint": endpoint,
            "pid": self._process.pid,
            "runtime_instance_id": self._read_discovery(support_root).get("runtime_instance_id", ""),
            "coordinator_epoch": self._read_discovery(support_root).get("coordinator_epoch"),
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "capability_digest": source_profile.capability_digest,
        }

    def _read_discovery(self, support_root: Path) -> dict[str, Any]:
        try:
            value = json.loads((support_root / "discovery.json").read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _wait_endpoint(self, support_root: Path, process: subprocess.Popen[str]) -> str:
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise BootstrapError(f"Runtime daemon exited during startup (see {support_root / 'runtime.log'}).")
            discovery = self._read_discovery(support_root)
            endpoint = str(discovery.get("endpoint", ""))
            if endpoint and self._http_health(endpoint):
                return endpoint
            time.sleep(0.05)
        self._terminate(process)
        raise BootstrapError("Runtime daemon did not become healthy before the bounded startup deadline.")

    @staticmethod
    def _http_health(endpoint: str) -> bool:
        request = urllib.request.Request(endpoint.rstrip("/") + "/v1/health", headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=0.5) as response:
                value = json.loads(response.read().decode("utf-8"))
            return value.get("status") == "ok" and value.get("protocol") == WIRE_PROTOCOL
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def connect(self, *, endpoint: str, credential: str) -> RuntimeConnection:
        try:
            from banodoco_workspace_client import WorkspaceClient
        except ImportError:
            checkout = self._source and Path(self._source.runtime_checkout).expanduser().resolve()
            if checkout:
                client_root = checkout / "packages" / "python"
                if str(client_root) not in sys.path:
                    sys.path.insert(0, str(client_root))
            from banodoco_workspace_client import WorkspaceClient
        connection = RuntimeConnection(endpoint, credential, self._bootstrap_credential)
        connection._client = WorkspaceClient(endpoint, credential)
        return connection

    def health(self, *, endpoint: str, pid: int, instance_id: str) -> bool:
        return self.is_pid_alive(pid) and self._http_health(endpoint)

    def validate_owner(self, *, endpoint: str, pid: int, instance_id: str, owner_lock: Path) -> bool:
        if not self.is_pid_alive(pid):
            return False
        try:
            marker = json.loads(Path(owner_lock).read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return False
        if str(marker.get("pid")) != str(pid) or str(marker.get("runtime_instance_id")) != instance_id:
            return False
        return self._http_health(endpoint)

    @staticmethod
    def is_pid_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    @staticmethod
    def _terminate(process: subprocess.Popen[str]):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

    def stop(self, **_kwargs):
        if self._process:
            self._terminate(self._process)
            self._process = None
        self._bootstrap_credential = None

    def prepare_restart(self, *, source_profile: SourceProfile, realm_id: str, realm_root: Path, support_root: Path, pid: int) -> None:
        """Adopt a detached daemon for an operator restart.

        ``banodoco-local up`` intentionally leaves the daemon in its own
        process group, so a later CLI invocation has no ``Popen`` handle.  The
        support lock/discovery record is the only durable hand-off; adopting
        it here lets restart terminate exactly that owner and relaunch the
        same realm without opening its database in the launcher.
        """
        self._source = source_profile
        self._realm_id = str(realm_id)
        self._realm_root = Path(realm_root).expanduser().resolve()
        self._support_root = Path(support_root).expanduser().resolve()
        self._detached_pid = int(pid)

    def restart(self, **kwargs) -> Mapping[str, Any]:
        if not self._source or not self._realm_root or not self._support_root or not self._realm_id:
            raise BootstrapError("No runtime process is available to restart.")
        source, root, support, realm_id = self._source, self._realm_root, self._support_root, self._realm_id
        if not self._process and getattr(self, "_detached_pid", None):
            detached = int(self._detached_pid)
            try:
                os.killpg(detached, signal.SIGTERM)
            except OSError:
                pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and self.is_pid_alive(detached):
                time.sleep(0.05)
            if self.is_pid_alive(detached):
                try:
                    os.killpg(detached, signal.SIGKILL)
                except OSError:
                    pass
            self._detached_pid = None
        else:
            self.stop()
        return self.start(realm_id=realm_id, realm_root=root, owner_lock=support / "instance.lock", source_profile=source)
