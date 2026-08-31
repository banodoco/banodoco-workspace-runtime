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
    def _validate_source(source: SourceProfile) -> None:
        """Validate only the explicitly configured product source.

        The runtime and generated client are installed dependencies.  A
        checkout path is provenance for the editable source profile, never an
        import or launch fallback for the neutral runtime.
        """
        source_checkout = Path(source.source_checkout).expanduser().resolve()
        if not source_checkout.exists():
            raise BootstrapError(f"Source checkout from the editable profile does not exist: {source_checkout}")

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
        self._validate_source(source)
        if source.runtime_command:
            argv = list(source.runtime_command)
        else:
            python = sys.executable
            if source.runtime_environment:
                candidate = Path(source.runtime_environment).expanduser().resolve() / "bin" / "python"
                if not candidate.is_file() or not os.access(candidate, os.X_OK):
                    raise BootstrapError(
                        "Configured runtime environment is missing its installed Python: "
                        f"{candidate}"
                    )
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
        log_path = support_root / "runtime.log"
        log = log_path.open("ab")
        try:
            # Do not derive imports from either checkout.  The selected
            # runtime_environment is an installed environment and the child
            # inherits the host's already-configured environment unchanged.
            self._process = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=log, text=True, start_new_session=True)
        except Exception:
            log.close()
            token_file.unlink(missing_ok=True)
            raise
        finally:
            log.close()
        self._source, self._realm_root, self._support_root, self._realm_id = source_profile, realm_root, support_root, realm_id
        self._bootstrap_credential = bootstrap_token
        endpoint = self._wait_endpoint(support_root, self._process)
        discovery = self._read_discovery(support_root)
        return {
            "endpoint": endpoint,
            "pid": self._process.pid,
            "process_birth_id": discovery.get("process_birth_id") or self.process_birth_identity(self._process.pid),
            "runtime_instance_id": discovery.get("runtime_instance_id", ""),
            "coordinator_epoch": discovery.get("coordinator_epoch"),
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

    @staticmethod
    def process_birth_identity(pid: int) -> str | None:
        """Return a PID-reuse-resistant process start marker."""
        if int(pid) <= 0:
            return None
        stat_path = Path(f"/proc/{int(pid)}/stat")
        try:
            fields = stat_path.read_text(encoding="utf-8").rsplit(")", 1)[-1].split()
            if len(fields) >= 20:
                return f"proc-start-ticks:{fields[19]}"
        except (OSError, ValueError):
            pass
        try:
            result = subprocess.run(["ps", "-p", str(int(pid)), "-o", "lstart="], capture_output=True, text=True, check=False, timeout=1)
            rendered = result.stdout.strip()
            if result.returncode == 0 and rendered:
                return f"ps-lstart:{rendered}"
        except (OSError, subprocess.SubprocessError):
            pass
        return None

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
        except ImportError as exc:
            raise BootstrapError("The installed generated workspace client is unavailable; install banodoco-workspace-client.") from exc
        connection = RuntimeConnection(endpoint, credential, self._bootstrap_credential)
        connection._client = WorkspaceClient(endpoint, credential)
        return connection

    def health(self, *, endpoint: str, pid: int, instance_id: str) -> bool:
        return self.is_pid_alive(pid) and self._http_health(endpoint)

    def validate_owner(self, *, endpoint: str, pid: int, instance_id: str, owner_lock: Path, process_birth_id: str | None = None) -> bool:
        if not self.is_pid_alive(pid):
            return False
        try:
            marker = json.loads(Path(owner_lock).read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return False
        if str(marker.get("pid")) != str(pid) or str(marker.get("runtime_instance_id")) != instance_id:
            return False
        expected_birth = process_birth_id or marker.get("process_birth_id")
        if not expected_birth or expected_birth != self.process_birth_identity(pid):
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
        endpoint = str(kwargs.get("endpoint", ""))
        expected_pid = int(kwargs.get("pid", 0))
        expected_instance = str(kwargs.get("instance_id", ""))
        expected_birth = str(kwargs.get("process_birth_id", ""))
        expected_realm = str(kwargs.get("realm_id", realm_id))
        owner_lock = Path(kwargs.get("owner_lock", support / "instance.lock")).expanduser().resolve()
        discovery_path = Path(kwargs.get("discovery_path", support / "discovery.json")).expanduser().resolve()

        def validate_before_signal(*, require_health: bool = True) -> None:
            """Re-read every fence immediately before the first signal."""
            if expected_pid <= 0 or not endpoint or not expected_instance or not expected_birth:
                raise BootstrapError("Runtime restart refused: discovery identity is incomplete.")
            if expected_pid == os.getpid():
                raise BootstrapError("Runtime restart refused: owner PID is the current operator process.")
            try:
                discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
                marker = json.loads(owner_lock.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise BootstrapError("Runtime restart refused: owner discovery or lock is unavailable.") from exc
            checks = (
                str(discovery.get("pid")) == str(expected_pid),
                str(discovery.get("endpoint")) == endpoint,
                str(discovery.get("runtime_instance_id")) == expected_instance,
                str(discovery.get("process_birth_id")) == expected_birth,
                str(discovery.get("active_realm")) == expected_realm,
                str(marker.get("pid")) == str(expected_pid),
                str(marker.get("runtime_instance_id")) == expected_instance,
                str(marker.get("process_birth_id")) == expected_birth,
                str(marker.get("realm_id")) == expected_realm,
                self.is_pid_alive(expected_pid),
                self.process_birth_identity(expected_pid) == expected_birth,
                (self._http_health(endpoint) if require_health else True),
            )
            if not all(checks):
                raise BootstrapError("Runtime restart refused: owner identity changed or is stale.")
            # A group kill is only safe for the daemon's own session leader.
            try:
                if os.getpgid(expected_pid) != expected_pid:
                    raise BootstrapError("Runtime restart refused: owner is not its own process-group leader.")
            except OSError as exc:
                raise BootstrapError("Runtime restart refused: owner process disappeared.") from exc

        validate_before_signal()
        if not self._process and getattr(self, "_detached_pid", None):
            detached = int(self._detached_pid)
            if detached != expected_pid:
                raise BootstrapError("Runtime restart refused: adopted owner PID changed.")
            validate_before_signal()
            os.killpg(detached, signal.SIGTERM)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and self.is_pid_alive(detached):
                time.sleep(0.05)
            if self.is_pid_alive(detached):
                # Revalidate again before escalation; PID reuse or a changed
                # group must never receive a signal from this boundary.
                validate_before_signal(require_health=False)
                os.killpg(detached, signal.SIGKILL)
            self._detached_pid = None
        else:
            process = self._process
            if process is None or process.pid != expected_pid:
                raise BootstrapError("Runtime restart refused: owned process handle changed.")
            validate_before_signal()
            self._terminate(process)
            self._process = None
        return self.start(realm_id=realm_id, realm_root=root, owner_lock=support / "instance.lock", source_profile=source)
