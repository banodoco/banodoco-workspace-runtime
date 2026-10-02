"""Concrete local boundary for the neutral workspace runtime.

The bootstrap package deliberately does not import the runtime implementation.
This module is the small adapter that turns an editable source profile into a
real loopback daemon process and a generated-client-shaped connection.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import fcntl
from pathlib import Path
import secrets
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .bootstrap import BootstrapError, SourceProfile
from .compatibility import canonical_value
from .io import atomic_write_json
from .custody_broker import (
    ACTIVE_CAPABILITY_NAME,
    CustodyError,
    RoleBoundCustodyBroker,
    custody_wrapper_argv,
    publish_active_capability,
    signal_sealed_capability,
)


PROTOCOL_VERSION = "workspace.v1"
WIRE_PROTOCOL = PROTOCOL_VERSION
SCHEMA_VERSION = "workspace-schema-v1"
WAIT_SECONDS = 10.0
ADMISSION_TIMEOUT_ENV = "ASTRID_RUNTIME_ADMISSION_TIMEOUT_SECONDS"
DEFAULT_ADMISSION_TIMEOUT_SECONDS = 120.0
STARTUP_WAIT_MARGIN_SECONDS = 5.0
DARWIN_UNIX_SOCKET_PATH_MAX_BYTES = 103
DARWIN_HANDOFF_SOCKET_PARENT = Path("/private/tmp")


def _create_compact_handoff_root() -> Path:
    """Create an owner-only restart rendezvous below Darwin's short temp alias."""

    parent = DARWIN_HANDOFF_SOCKET_PARENT
    try:
        parent_stat = os.lstat(parent)
    except OSError as exc:
        raise BootstrapError("Orderly handoff socket parent is unavailable.") from exc
    if (
        not parent.is_absolute()
        or stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or (
            parent_stat.st_mode & stat.S_IWOTH
            and not parent_stat.st_mode & stat.S_ISVTX
        )
    ):
        raise BootstrapError("Orderly handoff socket parent is unsafe.")
    root = Path(
        tempfile.mkdtemp(
            prefix=f"astrid-handoff-{os.getuid()}-",
            dir=parent,
        )
    )
    os.chmod(root, 0o700)
    root_stat = os.lstat(root)
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        try:
            root.rmdir()
        finally:
            raise BootstrapError("Orderly handoff socket root identity is unsafe.")
    if len(os.fsencode(str(root / "coordinator.sock"))) > DARWIN_UNIX_SOCKET_PATH_MAX_BYTES:
        try:
            root.rmdir()
        finally:
            raise BootstrapError("Orderly handoff socket path exceeds Darwin AF_UNIX limit.")
    return root


class RuntimeCustodyLaunchUncertain(BootstrapError):
    """A Runtime child exists but durable sealed custody publication failed."""

    def __init__(
        self,
        message: str,
        *,
        process: subprocess.Popen[str],
        broker: RoleBoundCustodyBroker,
    ) -> None:
        super().__init__(message)
        self.process = process
        self.broker = broker


def _is_authenticated_active_work_refusal(
    frame: object, *, transfer_version: str, handoff_id: str
) -> bool:
    """Recognize only the exact owner-A refusal frame after peer authentication."""

    return frame == {
        "version": transfer_version,
        "command": "refused_active_work",
        "handoff_id": handoff_id,
    }


def _validate_owner_a_export_offer(
    frame: object,
    *,
    transfer_version: str,
    handoff_id: str,
    sealed_record_digest: str,
) -> Mapping[str, Any]:
    """Map exact active-work refusal and reject every malformed export frame."""

    if _is_authenticated_active_work_refusal(
        frame,
        transfer_version=transfer_version,
        handoff_id=handoff_id,
    ):
        raise BootstrapError(
            "Runtime lifecycle refused while work is active or unreconciled."
        )
    if (
        not isinstance(frame, Mapping)
        or set(frame) != {
            "version", "command", "handoff_id", "sealed_record_digest", "export",
        }
        or frame.get("version") != transfer_version
        or frame.get("command") != "seal_export"
        or frame.get("handoff_id") != handoff_id
        or frame.get("sealed_record_digest") != sealed_record_digest
        or not isinstance(frame.get("export"), Mapping)
    ):
        raise BootstrapError("Owner A export-seal request is invalid.")
    return frame


def _admission_timeout_from_environment() -> float:
    """Read the bounded startup integrity budget from the install environment."""
    raw = canonical_value(ADMISSION_TIMEOUT_ENV)
    if raw in (None, ""):
        return DEFAULT_ADMISSION_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise BootstrapError(f"{ADMISSION_TIMEOUT_ENV} must be a finite positive number.") from exc
    if not (value > 0 and value != float("inf") and value == value):
        raise BootstrapError(f"{ADMISSION_TIMEOUT_ENV} must be a finite positive number.")
    return value


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

    # Health is a loopback request, but the daemon may be briefly busy while
    # finishing startup or serving another control-plane request.  Keep this
    # bounded without making a normal, healthy runtime look stale.
    HEALTH_TIMEOUT_SECONDS = 5.0

    def __init__(self, *, wait_seconds: float | None = None):
        self.admission_timeout_seconds = _admission_timeout_from_environment()
        requested_wait = WAIT_SECONDS if wait_seconds is None else float(wait_seconds)
        if requested_wait <= 0 or requested_wait != requested_wait or requested_wait == float("inf"):
            raise BootstrapError("wait_seconds must be a finite positive number.")
        self.wait_seconds = max(requested_wait, self.admission_timeout_seconds + STARTUP_WAIT_MARGIN_SECONDS)
        self._process: subprocess.Popen[str] | None = None
        self._source: SourceProfile | None = None
        self._realm_root: Path | None = None
        self._support_root: Path | None = None
        self._realm_id: str | None = None
        self._display_name = "Astrid Workspace"
        self._bootstrap_credential: str | None = None
        self._detached_pid: int | None = None

    @classmethod
    def _custody_identity(cls, pid: int) -> Mapping[str, object] | None:
        birth_id = cls.process_birth_identity(pid)
        if birth_id is None:
            return None
        try:
            uid_result = subprocess.run(
                ["/bin/ps", "-ww", "-o", "uid=", "-p", str(pid)],
                capture_output=True, text=True, check=False, timeout=1,
            )
            rendered_uid = uid_result.stdout.strip()
            if uid_result.returncode or not rendered_uid.isdigit():
                return None
        except (OSError, subprocess.SubprocessError):
            return None
        return {"pid": pid, "birth_id": birth_id, "uid": int(rendered_uid)}

    def _spawn_custodied_runtime(
        self,
        argv: list[str],
        *,
        support_root: Path,
        stdout,
        pass_fds: tuple[int, ...] = (),
    ) -> tuple[subprocess.Popen[str], RoleBoundCustodyBroker]:
        """Spawn one Runtime owner and publish its sealed audit-token sidecar."""

        custody_parent = support_root / "runtime-custody"
        custody_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        custody_parent.chmod(0o700)
        ledger_root = custody_parent / uuid.uuid4().hex
        process: subprocess.Popen[str] | None = None
        try:
            broker = RoleBoundCustodyBroker(
                role="runtime_owner",
                identity_provider=self._custody_identity,
                ledger_root=ledger_root,
                timeout=min(10.0, self.admission_timeout_seconds),
            )
            child_environment = dict(os.environ)
            child_environment.update(
                broker.child_environment(argv, start_new_session=True)
            )
            process = subprocess.Popen(
                custody_wrapper_argv(argv[0]),
                stdout=stdout,
                stderr=subprocess.STDOUT,
                text=True,
                env=child_environment,
                start_new_session=False,
                close_fds=True,
                pass_fds=pass_fds,
            )
            # This boundary created the unreaped direct child and is its sole
            # waiter.  Keep that authority explicit so handle-based cleanup
            # cannot later be applied to an adopted or detached owner.
            process._runtime_boundary_owner = self  # type: ignore[attr-defined]
            process._runtime_boundary_sole_reaper = True  # type: ignore[attr-defined]
            process._runtime_custody_broker = broker  # type: ignore[attr-defined]
            broker.wait_until_sealed()
            return process, broker
        except (CustodyError, OSError) as exc:
            if process is not None:
                process._runtime_custody_broker = broker  # type: ignore[attr-defined]
                raise RuntimeCustodyLaunchUncertain(
                    "Runtime child exists but sealed custody publication failed; cleanup is uncertain.",
                    process=process,
                    broker=broker,
                ) from exc
            raise BootstrapError(
                "Runtime audit-token custody admission failed; cleanup is uncertain."
            ) from exc

    @staticmethod
    def _validate_source(source: SourceProfile) -> None:
        """Validate only the explicitly configured product source.

        The runtime and generated client are installed dependencies.  A
        checkout path is provenance for the editable source profile, never an
        import or launch fallback for the neutral runtime.
        """
        if source.mode == "installed":
            if source.runtime_module != "runtime_protocol":
                raise BootstrapError("Installed source profile runtime module must be runtime_protocol.")
            spec = importlib.util.find_spec(source.runtime_module)
            if spec is None or not spec.origin:
                raise BootstrapError("Installed Runtime module is unavailable.")
            actual = Path(spec.origin).resolve(strict=True)
            expected = Path(source.runtime_module_origin).expanduser()
            LocalRuntimeBoundary._validate_path(expected, "installed Runtime module origin")
            if expected.is_symlink() or not expected.is_file() or expected.resolve(strict=True) != actual:
                raise BootstrapError("Installed Runtime module origin changed.")
            digest = "sha256:" + hashlib.sha256(actual.read_bytes()).hexdigest()
            if digest != source.runtime_artifact_sha256:
                raise BootstrapError("Installed Runtime artifact digest changed.")
            if source.runtime_environment:
                raise BootstrapError("Installed source profile cannot redirect to another runtime environment.")
            if source.worker_profile:
                worker_profile = Path(source.worker_profile).expanduser()
                LocalRuntimeBoundary._validate_path(worker_profile, "worker profile")
                if worker_profile.is_symlink() or not worker_profile.is_file():
                    raise BootstrapError(f"Configured worker profile is unavailable: {worker_profile}")
            return
        if source.mode != "editable":
            raise BootstrapError("Source profile mode is unsupported.")
        runtime_checkout = Path(source.runtime_checkout).expanduser()
        if not runtime_checkout.is_absolute():
            raise BootstrapError("Source profile must provide an absolute pinned runtime_checkout.")
        LocalRuntimeBoundary._validate_path(runtime_checkout, "runtime checkout")
        source_checkout = Path(source.source_checkout).expanduser()
        LocalRuntimeBoundary._validate_path(source_checkout, "source checkout")
        if source_checkout.is_symlink():
            raise BootstrapError("Source checkout from the editable profile must not be a symlink.")
        source_checkout = source_checkout.resolve()
        if not source_checkout.exists():
            raise BootstrapError(f"Source checkout from the editable profile does not exist: {source_checkout}")
        if source.worker_profile:
            worker_profile = Path(source.worker_profile).expanduser()
            LocalRuntimeBoundary._validate_path(worker_profile, "worker profile")
            if worker_profile.is_symlink() or not worker_profile.is_file():
                raise BootstrapError(f"Configured worker profile is unavailable: {worker_profile}")
        if source.runtime_environment:
            environment = Path(source.runtime_environment).expanduser()
            LocalRuntimeBoundary._validate_path(environment, "runtime environment")
            if not environment.is_dir():
                raise BootstrapError(f"Configured runtime environment does not exist: {environment}")

    @staticmethod
    def _validate_path(path: Path, label: str) -> Path:
        """Reject operator-controlled path aliases before resolving them."""
        target = Path(path).expanduser()
        if not target.is_absolute():
            raise BootstrapError(f"{label} must be absolute")
        current = Path(target.anchor)
        for component in target.parts[1:]:
            current /= component
            # /var and /tmp are protected macOS compatibility aliases; all
            # support-relative components below them are still checked.
            if current.is_symlink() and current not in {Path("/var"), Path("/tmp")}:
                raise BootstrapError(f"{label} must not traverse a symlink")
        return target

    def configure_source(self, source: SourceProfile) -> None:
        self._source = source

    @staticmethod
    def _token_file(support_root: Path, token: str) -> Path:
        LocalRuntimeBoundary._validate_path(support_root, "runtime support root")
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
        if not any("--admission-timeout" == part for part in argv):
            argv += ["--admission-timeout", str(self.admission_timeout_seconds)]
        if source.worker_profile and "--worker-profile" not in argv:
            argv += ["--worker-profile", str(Path(source.worker_profile).expanduser().resolve())]
        return argv

    def create(self, *, realm_id: str, realm_root: Path, display_name: str, source_profile: SourceProfile) -> Mapping[str, Any]:
        """Explicitly provision one fresh realm before launching its daemon.

        Ordinary ``start`` remains an open/admission operation and therefore
        refuses a missing or invalid realm.  This separate subprocess invokes
        the Runtime's canonical creation command, keeping schema, identity,
        and ownership inside Runtime rather than recreating them in the
        neutral launcher.
        """
        realm_root = self._validate_path(Path(realm_root), "realm root").resolve()
        if realm_root.exists() or realm_root.is_symlink():
            raise BootstrapError("fresh realm creation requires a new root")
        self._validate_source(source_profile)
        if source_profile.runtime_command:
            raise BootstrapError("explicit realm creation requires the pinned runtime environment")
        python = sys.executable
        if source_profile.runtime_environment:
            candidate = Path(source_profile.runtime_environment).expanduser().resolve() / "bin" / "python"
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                raise BootstrapError(
                    "Configured runtime environment is missing its installed Python: "
                    f"{candidate}"
                )
            python = str(candidate)
        argv = [
            python, "-m", "runtime_protocol", "create",
            "--root", str(realm_root),
            "--display-name", display_name,
            "--realm-id", realm_id,
        ]
        try:
            result = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise BootstrapError("Runtime realm creation could not start.") from exc
        output = result.stdout.strip()
        if result.returncode != 0:
            raise BootstrapError(
                "Runtime realm creation failed: " + (output or "no diagnostic")
            )
        try:
            created = json.loads(output)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BootstrapError("Runtime realm creation returned invalid metadata.") from exc
        if not isinstance(created, Mapping):
            raise BootstrapError("Runtime realm creation returned invalid metadata.")
        return created

    def inspect(self, *, realm_root: Path) -> Mapping[str, Any]:
        """Run Runtime's bounded doctor without opening or starting authority."""
        root = self._validate_path(Path(realm_root), "realm root")
        if root.is_symlink() or not root.is_dir():
            raise BootstrapError(f"realm root is unavailable: {root}")
        result = subprocess.run(
            [sys.executable, "-m", "runtime_protocol", "doctor", "--root", str(root), "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        try:
            report = json.loads(result.stdout.strip())
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BootstrapError("Runtime realm inspection returned invalid metadata.") from exc
        if not isinstance(report, Mapping):
            raise BootstrapError("Runtime realm inspection returned invalid metadata.")
        return report

    def start(self, *, realm_id: str, realm_root: Path, owner_lock: Path, source_profile: SourceProfile) -> Mapping[str, Any]:
        if self._process and self._process.poll() is None:
            raise BootstrapError("runtime boundary already owns a live daemon")
        realm_root = self._validate_path(Path(realm_root), "realm root")
        owner_lock = self._validate_path(Path(owner_lock), "owner lock")
        support_root = self._validate_path(owner_lock.parent, "runtime support root")
        self._validate_source(source_profile)
        # Resolve only after the lexical fence.  No source profile field can
        # replace these neutral authority paths.
        realm_root = realm_root.resolve()
        support_root = support_root.resolve()
        owner_lock = owner_lock.resolve()
        bootstrap_token = os.urandom(32).hex()
        token_file = self._token_file(support_root, bootstrap_token)
        argv = self._argv(source_profile, realm_id=realm_id, realm_root=realm_root, support_root=support_root, display_name=self._display_name, owner_lock=owner_lock, token_file=token_file)
        log_path = support_root / "runtime.log"
        log = log_path.open("ab")
        try:
            # Do not derive imports from either checkout.  The selected
            # runtime_environment is an installed environment and the child
            # inherits the host's already-configured environment unchanged.
            # Preserve the daemon's structured startup failure on the existing
            # operator log boundary; successful stdout is only its one-line
            # launch record.
            self._process, _broker = self._spawn_custodied_runtime(
                argv, support_root=support_root, stdout=log,
            )
        except RuntimeCustodyLaunchUncertain as exc:
            self._process = exc.process
            raise
        except Exception:
            log.close()
            token_file.unlink(missing_ok=True)
            raise
        finally:
            log.close()
        self._source, self._realm_root, self._support_root, self._realm_id = source_profile, realm_root, support_root, realm_id
        self._bootstrap_credential = bootstrap_token
        try:
            endpoint = self._wait_endpoint(support_root, self._process)
            discovery = self._read_discovery(support_root)
            ready_identity = self._custody_identity(self._process.pid)
            if ready_identity is None:
                raise BootstrapError("Runtime ready owner identity is unavailable.")
            _broker.bind_ready_token(
                expected_pid=self._process.pid,
                expected_identity=ready_identity,
            )
            publish_active_capability(
                support_root / ACTIVE_CAPABILITY_NAME,
                _broker,
            )
        except Exception:
            self._terminate(self._process)
            token_file.unlink(missing_ok=True)
            self._bootstrap_credential = None
            raise
        return {
            "endpoint": endpoint,
            "pid": self._process.pid,
            "process_birth_id": discovery.get("process_birth_id") or self.process_birth_identity(self._process.pid),
            "runtime_instance_id": discovery.get("runtime_instance_id", ""),
            "coordinator_epoch": discovery.get("coordinator_epoch"),
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "capability_digest": source_profile.capability_digest,
            # These are paths and public metadata only; the scoped worker
            # secret remains in the runtime-owned 0600 file.
            "worker_credential_file": discovery.get("worker_credential_file"),
            "worker_credential_pending": bool(discovery.get("worker_credential_pending")),
            "worker_actor": discovery.get("worker_actor"),
            "worker_scopes": discovery.get("worker_scopes", ()),
        }

    def _read_discovery(self, support_root: Path) -> dict[str, Any]:
        return self._read_discovery_file(self._validate_path(Path(support_root) / "discovery.json", "runtime discovery"))

    @classmethod
    def _read_discovery_file(cls, path: Path) -> dict[str, Any]:
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return {}
                chunks = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                value = json.loads(b"".join(chunks).decode("utf-8"))
            finally:
                os.close(fd)
            return value if isinstance(value, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError):
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
            # A support root may still advertise a healthy incumbent while a
            # replacement candidate is starting.  Never adopt that endpoint:
            # doing so lets the candidate's rollback clear the incumbent's
            # discovery and owner marker.  The daemon publishes its own PID
            # atomically only after realm admission succeeds.
            try:
                advertised_pid = int(discovery.get("pid", 0))
            except (TypeError, ValueError):
                advertised_pid = 0
            if advertised_pid and advertised_pid != process.pid:
                time.sleep(0.05)
                continue
            endpoint = str(discovery.get("endpoint", ""))
            if endpoint and self._http_health(endpoint):
                return endpoint
            time.sleep(0.05)
        self._terminate(process)
        raise BootstrapError("Runtime daemon did not become healthy before the bounded startup deadline.")

    @staticmethod
    def _http_status(endpoint: str) -> str | None:
        value = LocalRuntimeBoundary._http_health_payload(endpoint)
        return value.get("status") if value else None

    @staticmethod
    def _http_health_payload(endpoint: str) -> dict[str, Any] | None:
        try:
            parsed = urlsplit(str(endpoint))
            if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ("", "/")
                    or parsed.port is None or not (1 <= parsed.port <= 65535)):
                return None
        except ValueError:
            return None
        request = urllib.request.Request(str(endpoint).rstrip("/") + "/v1/health", headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=LocalRuntimeBoundary.HEALTH_TIMEOUT_SECONDS) as response:
                value = json.loads(response.read().decode("utf-8"))
            if isinstance(value, dict) and value.get("protocol") == WIRE_PROTOCOL:
                status = value.get("status")
                if status in ("ok", "degraded"):
                    return value
            return None
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _http_health(endpoint: str) -> bool:
        return LocalRuntimeBoundary._http_status(endpoint) == "ok"

    @staticmethod
    def _http_claim_admission(endpoint: str, bootstrap_credential: str) -> bool:
        """Prove B's authenticated claim gate opened, not only its health route."""

        request = urllib.request.Request(
            str(endpoint).rstrip("/") + "/v1/doctor",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {bootstrap_credential}",
            },
        )
        try:
            with urllib.request.urlopen(
                request, timeout=LocalRuntimeBoundary.HEALTH_TIMEOUT_SECONDS
            ) as response:
                value = json.loads(response.read().decode("utf-8"))
            return response.status == 200 and isinstance(value, dict)
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def connect(self, *, endpoint: str, credential: str) -> RuntimeConnection:
        try:
            parsed = urlsplit(str(endpoint))
            if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ("", "/")
                    or parsed.port is None or not (1 <= parsed.port <= 65535)):
                raise ValueError
        except ValueError as exc:
            raise BootstrapError("runtime endpoint must be an HTTP loopback authority") from exc
        try:
            from banodoco_workspace_client import WorkspaceClient
        except ImportError as exc:
            raise BootstrapError("The installed generated workspace client is unavailable; install banodoco-workspace-client.") from exc
        connection = RuntimeConnection(endpoint, credential, self._bootstrap_credential)
        connection._client = WorkspaceClient(endpoint, credential)
        return connection

    def health(self, *, endpoint: str, pid: int, instance_id: str) -> bool:
        health = self._http_health_payload(endpoint)
        return bool(
            self.is_pid_alive(pid)
            and health
            and health.get("status") == "ok"
            and health.get("runtime_instance_id") == instance_id
        )

    def endpoint_metadata(self, *, endpoint: str, credential_file: Path) -> Mapping[str, Any]:
        """Read endpoint instance and authenticated realm identity without mutation."""
        health = self._http_health_payload(endpoint)
        if not health:
            return {}
        try:
            credential_path = self._validate_path(Path(credential_file), "runtime credential")
            fd = os.open(credential_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return {}
                raw = bytearray()
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    raw.extend(chunk)
            finally:
                os.close(fd)
            token = bytes(raw).decode("utf-8").strip()
            if not token:
                return {}
            request = urllib.request.Request(
                str(endpoint).rstrip("/") + "/v1/realm",
                headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(request, timeout=self.HEALTH_TIMEOUT_SECONDS) as response:
                realm = json.loads(response.read().decode("utf-8"))
            if not isinstance(realm, Mapping) or not realm.get("realm_id"):
                return {}
            return {**health, "realm_id": str(realm["realm_id"])}
        except (BootstrapError, OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return {}

    def validate_owner(
        self, *, endpoint: str, pid: int, instance_id: str, owner_lock: Path,
        process_birth_id: str | None = None, expected_realm_id: str | None = None,
        expected_realm_root: Path | None = None,
    ) -> bool:
        if not self.is_pid_alive(pid):
            return False
        try:
            path = self._validate_path(Path(owner_lock), "owner lock")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return False
                chunks = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                marker = json.loads(b"".join(chunks).decode("utf-8"))
            finally:
                os.close(fd)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError):
            return False
        if not isinstance(marker, dict):
            return False
        if str(marker.get("pid")) != str(pid) or str(marker.get("runtime_instance_id")) != instance_id:
            return False
        if expected_realm_id is not None and str(marker.get("realm_id")) != str(expected_realm_id):
            return False
        if expected_realm_root is not None:
            try:
                expected_root = self._validate_path(Path(expected_realm_root), "expected realm root").resolve()
                marker_root = self._validate_path(Path(str(marker.get("realm_root") or "")), "owner realm root").resolve()
            except (BootstrapError, OSError):
                return False
            if marker_root != expected_root:
                return False
        expected_birth = process_birth_id or marker.get("process_birth_id")
        if not expected_birth:
            return False
        actual_birth = self.process_birth_identity(pid)
        health = self._http_health_payload(endpoint)
        if not health or health.get("runtime_instance_id") != instance_id:
            return False
        if actual_birth is None:
            # Restricted clients may be able to prove that a PID exists but
            # not inspect its birth marker. Require the daemon itself to
            # attest the durable runtime instance over its loopback health
            # endpoint; health alone is never an identity proof.
            pass
        elif expected_birth != actual_birth:
            return False
        # A degraded runtime can still be the correct owner. Keep health
        # admission separate so database failures are not called PID conflicts.
        return True

    @staticmethod
    def is_pid_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            result = subprocess.run(
                ["/bin/ps", "-ww", "-o", "pid=", "-p", str(int(pid))],
                capture_output=True, text=True, check=False, timeout=1,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0 and result.stdout.strip() == str(int(pid))

    @staticmethod
    def _process_parent_pid(pid: int) -> int | None:
        try:
            result = subprocess.run(
                ["/bin/ps", "-ww", "-o", "ppid=", "-p", str(int(pid))],
                capture_output=True, text=True, check=False, timeout=1,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        rendered = result.stdout.strip()
        return int(rendered) if result.returncode == 0 and rendered.isdigit() else None

    def _assert_direct_child_termination_authority(
        self, process: subprocess.Popen[str],
    ) -> None:
        if (
            getattr(process, "_runtime_boundary_owner", None) is not self
            or getattr(process, "_runtime_boundary_sole_reaper", False) is not True
        ):
            raise BootstrapError(
                "Runtime direct-child cleanup refused: sole-reaper authority is absent."
            )
        observed_parent = self._process_parent_pid(process.pid)
        if observed_parent != os.getpid():
            if process.poll() is not None:
                return
            raise BootstrapError(
                "Runtime direct-child cleanup refused: process is no longer a direct child."
            )

    def _terminate(self, process: subprocess.Popen[str]):
        if process.poll() is not None:
            return
        self._assert_direct_child_termination_authority(process)
        try:
            process.terminate()
            process.wait(timeout=5)
        except ProcessLookupError:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._assert_direct_child_termination_authority(process)
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired as exc:
                raise BootstrapError(
                    "Runtime direct-child cleanup is uncertain after kill."
                ) from exc

    def _signal_registered_owner(
        self,
        *,
        support: Path,
        expected_pid: int,
        expected_birth: str,
        signum: int,
    ) -> Mapping[str, object]:
        """Signal one detached owner only through its sealed audit token."""

        identity = self._custody_identity(expected_pid)
        if identity is None or identity.get("birth_id") != expected_birth:
            raise BootstrapError(
                "Runtime sealed custody refused: selected owner identity changed."
            )
        try:
            return signal_sealed_capability(
                support / ACTIVE_CAPABILITY_NAME,
                expected_identity=identity,
                signum=signum,
                identity_provider=self._custody_identity,
            )
        except CustodyError as exc:
            raise BootstrapError(
                "Runtime sealed custody is unavailable for the selected detached owner."
            ) from exc

    def _terminate_detached_owner(
        self,
        *,
        support: Path,
        expected_pid: int,
        expected_birth: str,
        event_callback: Callable[[str], None] | None = None,
    ) -> bool:
        """Stop an adopted owner without any PID or process-group signal."""

        if event_callback is not None:
            event_callback("sealed_term_requested")
        self._signal_registered_owner(
            support=support,
            expected_pid=expected_pid,
            expected_birth=expected_birth,
            signum=signal.SIGTERM,
        )
        if event_callback is not None:
            event_callback("sealed_term_completed")
        deadline = time.monotonic() + 5
        while (
            time.monotonic() < deadline
            and self.process_birth_identity(expected_pid) == expected_birth
        ):
            time.sleep(0.05)
        if self.process_birth_identity(expected_pid) == expected_birth:
            if event_callback is not None:
                event_callback("sealed_kill_requested")
            self._signal_registered_owner(
                support=support,
                expected_pid=expected_pid,
                expected_birth=expected_birth,
                signum=signal.SIGKILL,
            )
            if event_callback is not None:
                event_callback("sealed_kill_completed")
        return True

    def _terminate_direct_child_owner_with_sealed_custody(
        self,
        process: subprocess.Popen[str],
        *,
        support: Path,
        expected_pid: int,
        expected_birth: str,
        event_callback: Callable[[str], None] | None = None,
    ) -> bool:
        """Signal an owned child through sealed custody, then reap its handle."""

        if process.pid != expected_pid:
            raise BootstrapError("Runtime restart refused: owned process handle changed.")
        if process.poll() is not None:
            process.wait(timeout=2)
            if event_callback is not None:
                event_callback("reaped_without_signal")
            return False
        self._assert_direct_child_termination_authority(process)
        if event_callback is not None:
            event_callback("sealed_term_requested")
        self._signal_registered_owner(
            support=support,
            expected_pid=expected_pid,
            expected_birth=expected_birth,
            signum=signal.SIGTERM,
        )
        if event_callback is not None:
            event_callback("sealed_term_completed")
        try:
            process.wait(timeout=5)
        except ProcessLookupError:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._assert_direct_child_termination_authority(process)
            if event_callback is not None:
                event_callback("sealed_kill_requested")
            self._signal_registered_owner(
                support=support,
                expected_pid=expected_pid,
                expected_birth=expected_birth,
                signum=signal.SIGKILL,
            )
            if event_callback is not None:
                event_callback("sealed_kill_completed")
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired as exc:
                raise BootstrapError(
                    "Runtime sealed direct-child cleanup is uncertain after kill."
                ) from exc
        return True

    def _cleanup_failed_handoff_process(
        self,
        process: subprocess.Popen[str] | None,
        *,
        authenticated_admission_confirmed: bool,
    ) -> None:
        """Stop an unconfirmed adopter but preserve an admitted healthy B."""

        if process is None or process.poll() is not None or authenticated_admission_confirmed:
            return
        broker = getattr(process, "_runtime_custody_broker", None)
        if not isinstance(broker, RoleBoundCustodyBroker):
            raise BootstrapError(
                "Runtime adopter cleanup is uncertain: sealed audit-token custody is unavailable."
            )
        try:
            identity = self._custody_identity(process.pid)
            if identity is None:
                raise CustodyError("failed Runtime adopter identity is unavailable")
            if broker.state == "sealed":
                broker.bind_ready_token(
                    expected_pid=process.pid,
                    expected_identity=identity,
                )
            broker.signal(signal.SIGTERM, expected_pid=process.pid)
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            broker.signal(signal.SIGKILL, expected_pid=process.pid)
            process.wait(timeout=2)
        except CustodyError as exc:
            raise BootstrapError(
                "Runtime adopter cleanup is uncertain: sealed audit-token signal failed."
            ) from exc

    @staticmethod
    def _build_authenticated_handoff_result(
        *, process, accepted, discovery, source, current
    ) -> Mapping[str, Any]:
        return {
            "endpoint": discovery["endpoint"],
            "pid": process.pid,
            "process_birth_id": accepted["runtime_birth_id"],
            "runtime_instance_id": accepted["runtime_instance_id"],
            "coordinator_epoch": discovery.get("coordinator_epoch"),
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "capability_digest": source.capability_digest,
            "worker_credential_file": discovery.get("worker_credential_file"),
            "worker_credential_pending": False,
            "worker_actor": discovery.get("worker_actor"),
            "worker_scopes": discovery.get("worker_scopes", ()),
            "orderly_handoff": current.get("result"),
            "handoff_record": str(current["_record_path"]),
        }

    def _report_authenticated_handoff(self, **kwargs) -> Mapping[str, Any]:
        """Build the observational boundary result without revoking owner B."""

        process = kwargs["process"]
        try:
            return self._build_authenticated_handoff_result(**kwargs)
        except BaseException:
            self._cleanup_failed_handoff_process(
                process,
                authenticated_admission_confirmed=True,
            )
            raise

    def _retain_failed_adopter_gate(
        self,
        *,
        support: Path,
        record,
        handoff_id: str,
        process: subprocess.Popen[str] | None,
        owner_b_birth_id: str | None,
    ) -> bool:
        """Persist the B-loss gate while the caller still holds the mutex."""

        try:
            retained = record.read()
            if retained.get("state") not in {
                "COMMITTED_ORPHAN", "FINALIZING", "ADOPTED",
            }:
                return False
            marker = support / "orderly-handoff-cleanup-uncertain.json"
            if not marker.exists() and not marker.is_symlink():
                self._atomic_owner_json(marker, {
                    "version": 1,
                    "state": (
                        "operator_audit_required"
                        if retained.get("state") == "ADOPTED"
                        else "cleanup_unverified_after_owner_b_loss"
                    ),
                    "handoff_id": handoff_id,
                    "handoff_state": retained.get("state"),
                    "record_path": str(record.path),
                    "record_digest": retained.get("record_digest"),
                    "owner_b_pid": process.pid if process is not None else None,
                    "owner_b_birth_id": owner_b_birth_id,
                })
            return True
        except Exception:
            # The still-present request pointer is the independent startup
            # gate when marker creation or record inspection fails.
            return False

    def _publish_active_adopted_owner(
        self,
        *,
        support: Path,
        record,
        current: Mapping[str, Any],
        process: subprocess.Popen[str],
        accepted: Mapping[str, Any],
    ) -> None:
        """Publish the retained ADOPTED tombstone before transient gates clear."""

        if current.get("state") != "ADOPTED":
            raise BootstrapError("Runtime owner B is not durably ADOPTED.")
        from runtime_protocol.orderly_handoff import digest

        reference = {
                "version": 1,
                "state": "ADOPTED",
                "handoff_id": current["handoff_id"],
                "record_path": str(record.path),
                "record_digest": current["record_digest"],
                "pid": process.pid,
                "birth_id": accepted["runtime_birth_id"],
                "runtime_instance_id": accepted["runtime_instance_id"],
        }
        reference["reference_digest"] = digest(reference)
        self._atomic_owner_json(
            support / "orderly-handoff-adopted-owner.json", reference
        )

    @staticmethod
    def _predecessor_active_reference_digest(
        support: Path,
        *,
        expected_pid: int,
        expected_birth: str,
        expected_instance: str,
    ) -> str | None:
        from runtime_protocol.orderly_handoff import digest

        path = support / "orderly-handoff-adopted-owner.json"
        if not path.exists() and not path.is_symlink():
            return None
        try:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise BootstrapError("The active adopted-owner reference is invalid.")
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise BootstrapError("The active adopted-owner reference is not owner-only.")
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BootstrapError("The active adopted-owner reference is unavailable.") from exc
        if not isinstance(value, dict):
            raise BootstrapError("The active adopted-owner reference is invalid.")
        claimed = value.get("reference_digest")
        unsigned = {key: item for key, item in value.items() if key != "reference_digest"}
        if (
            claimed != digest(unsigned)
            or value.get("pid") != expected_pid
            or value.get("birth_id") != expected_birth
            or value.get("runtime_instance_id") != expected_instance
        ):
            raise BootstrapError("The active adopted-owner reference changed.")
        return str(claimed)

    def stop(self, **_kwargs):
        if self._process:
            self._terminate(self._process)
            self._process = None
        self._bootstrap_credential = None

    def stop_owner(self, **kwargs) -> Mapping[str, Any]:
        """Authenticate, fence, revalidate, and stop one adopted owner."""
        return self._restart_impl(kwargs, stop_with_fence=True)

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
        self._realm_root = self._validate_path(Path(realm_root), "realm root").resolve()
        self._support_root = self._validate_path(Path(support_root), "runtime support root").resolve()
        self._detached_pid = int(pid)

    def restart(self, **kwargs) -> Mapping[str, Any]:
        return self._restart_impl(kwargs, stop_with_fence=False)

    def _restart_impl(
        self,
        kwargs: Mapping[str, Any],
        *,
        stop_with_fence: bool,
    ) -> Mapping[str, Any]:
        if not self._source or not self._realm_root or not self._support_root or not self._realm_id:
            raise BootstrapError("No runtime process is available to restart.")
        source, root, support, realm_id = self._source, self._realm_root, self._support_root, self._realm_id
        start_after_stop = False if stop_with_fence else bool(kwargs.get("start_after_stop", True))
        require_health = bool(kwargs.get("require_health", True))
        endpoint = str(kwargs.get("endpoint", ""))
        expected_pid = int(kwargs.get("pid", 0))
        expected_instance = str(kwargs.get("instance_id", ""))
        expected_birth = str(kwargs.get("process_birth_id", ""))
        expected_realm = str(kwargs.get("realm_id", realm_id))
        preserve_worker = bool(kwargs.get("preserve_worker", False))
        owner_lock = self._validate_path(Path(kwargs.get("owner_lock", support / "instance.lock")), "owner lock").resolve()
        discovery_path = self._validate_path(Path(kwargs.get("discovery_path", support / "discovery.json")), "runtime discovery").resolve()

        def validate_before_signal(
            *,
            require_health: bool = True,
            authenticate_endpoint: bool = True,
        ) -> dict[str, Any]:
            """Re-read every fence immediately before the first signal."""
            if expected_pid <= 0 or not endpoint or not expected_instance or not expected_birth:
                raise BootstrapError("Runtime restart refused: discovery identity is incomplete.")
            if expected_pid == os.getpid():
                raise BootstrapError("Runtime restart refused: owner PID is the current operator process.")
            try:
                discovery = self._read_discovery_file(discovery_path)
                fd = os.open(owner_lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise OSError("owner lock is not a regular file")
                    marker = json.loads(os.read(fd, 1024 * 1024).decode("utf-8"))
                finally:
                    os.close(fd)
            except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise BootstrapError("Runtime restart refused: owner discovery or lock is unavailable.") from exc
            try:
                expected_root = self._validate_path(root, "expected realm root").resolve()
                discovery_root = self._validate_path(
                    Path(str(discovery.get("realm_root") or "")), "discovery realm root"
                ).resolve()
                marker_root = self._validate_path(
                    Path(str(marker.get("realm_root") or "")), "owner realm root"
                ).resolve()
            except (BootstrapError, OSError) as exc:
                raise BootstrapError("Runtime restart refused: realm-root identity is invalid.") from exc
            observed_birth = self.process_birth_identity(expected_pid)
            checks = {
                "discovery_pid": str(discovery.get("pid")) == str(expected_pid),
                "discovery_endpoint": str(discovery.get("endpoint")) == endpoint,
                "discovery_instance": str(discovery.get("runtime_instance_id")) == expected_instance,
                "discovery_birth": str(discovery.get("process_birth_id")) == expected_birth,
                "discovery_realm": str(discovery.get("active_realm")) == expected_realm,
                "discovery_root": discovery_root == expected_root,
                "owner_lock_pid": str(marker.get("pid")) == str(expected_pid),
                "owner_lock_instance": str(marker.get("runtime_instance_id")) == expected_instance,
                "owner_lock_birth": str(marker.get("process_birth_id")) == expected_birth,
                "owner_lock_realm": str(marker.get("realm_id")) == expected_realm,
                "owner_lock_root": marker_root == expected_root,
                "pid_alive": self.is_pid_alive(expected_pid),
                "process_birth": observed_birth == expected_birth,
            }
            observed = {
                "discovery_pid": discovery.get("pid"),
                "discovery_endpoint": discovery.get("endpoint"),
                "discovery_instance": discovery.get("runtime_instance_id"),
                "discovery_birth": discovery.get("process_birth_id"),
                "discovery_realm": discovery.get("active_realm"),
                "discovery_root": str(discovery_root),
                "owner_lock_pid": marker.get("pid"),
                "owner_lock_instance": marker.get("runtime_instance_id"),
                "owner_lock_birth": marker.get("process_birth_id"),
                "owner_lock_realm": marker.get("realm_id"),
                "owner_lock_root": str(marker_root),
                "process_birth": observed_birth,
            }
            if authenticate_endpoint:
                health = self._http_health_payload(endpoint)
                endpoint_identity = self.endpoint_metadata(
                    endpoint=endpoint,
                    credential_file=support / "credentials" / "owner.token",
                )
                checks.update({
                    "health_instance": bool(health and health.get("runtime_instance_id") == expected_instance),
                    "authenticated_instance": bool(endpoint_identity and endpoint_identity.get("runtime_instance_id") == expected_instance),
                    "authenticated_realm": bool(endpoint_identity and endpoint_identity.get("realm_id") == expected_realm),
                    "required_health": (bool(health and health.get("status") == "ok") if require_health else True),
                })
                observed.update({
                    "health_status": health.get("status") if health else None,
                    "health_instance": health.get("runtime_instance_id") if health else None,
                    "authenticated_instance": endpoint_identity.get("runtime_instance_id") if endpoint_identity else None,
                    "authenticated_realm": endpoint_identity.get("realm_id") if endpoint_identity else None,
                })
            try:
                observed_group = os.getpgid(expected_pid)
            except OSError as exc:
                observed_group = None
                checks["process_group_leader"] = False
                observed["process_group"] = None
                observed["process_group_error"] = type(exc).__name__
            else:
                checks["process_group_leader"] = observed_group == expected_pid
                observed["process_group"] = observed_group
            result = {"checks": checks, "observed": observed, "passed": all(checks.values())}
            return result

        def require_validation(**options: Any) -> dict[str, Any]:
            result = validate_before_signal(**options)
            if not result["passed"]:
                raise BootstrapError("Runtime restart refused: owner identity changed or is stale.")
            return result

        if stop_with_fence:
            if preserve_worker:
                raise BootstrapError("Worker preservation uses the separate restart handoff path.")
            # Authenticate the live endpoint before taking the realm write
            # fence. HTTP handlers need the Runtime store mutex and cannot
            # respond while a mutation is queued behind that fence holding
            # the mutex. The same stop invocation then holds the fence while
            # it repeats every local identity check and uses sealed custody.
            validation_path = support / "runtime-stop-validation.json"
            phase_events: list[dict[str, Any]] = []
            receipt: dict[str, Any] = {
                "version": 1,
                "operation": "normal-down",
                "state": "validating",
                "expected": {
                    "pid": expected_pid,
                    "process_birth_id": expected_birth,
                    "runtime_instance_id": expected_instance,
                    "realm_id": expected_realm,
                    "realm_root": str(root),
                    "endpoint": endpoint,
                    "owner_lock": str(owner_lock),
                    "discovery_path": str(discovery_path),
                },
                "phases": {},
                "events": phase_events,
                "effects": {
                    "signal_attempted": False,
                    "signal_completed": False,
                    "sealed_term_requested": False,
                    "sealed_term_completed": False,
                    "sealed_kill_requested": False,
                    "sealed_kill_completed": False,
                    "reaped_without_signal": False,
                },
            }
            sealed_custody_signal = False

            def persist(state: str, *, failure: BaseException | None = None) -> None:
                receipt["state"] = state
                receipt["updated_at"] = time.time()
                if failure is not None:
                    receipt["failure"] = {
                        "class": type(failure).__name__,
                        "message": str(failure),
                    }
                atomic_write_json(validation_path, receipt)

            def record_signal_effect(event: str) -> None:
                if event not in {
                    "sealed_term_requested",
                    "sealed_term_completed",
                    "sealed_kill_requested",
                    "sealed_kill_completed",
                    "reaped_without_signal",
                }:
                    raise BootstrapError("Runtime stop reported an invalid signal effect.")
                receipt["effects"][event] = True
                if event.endswith("_requested"):
                    receipt["effects"]["signal_attempted"] = True
                if event.endswith("_completed"):
                    receipt["effects"]["signal_completed"] = True
                persist("signal_in_progress")

            try:
                authenticated = validate_before_signal(
                    require_health=False, authenticate_endpoint=True
                )
            except Exception as exc:
                receipt["phases"]["authenticated_preflight"] = {
                    "passed": False,
                    "checks": {"identity_observation_completed": False},
                    "observed": {"failure_class": type(exc).__name__},
                }
                phase_events.append({"phase": "authenticated_preflight", "result": "failed", "at": time.monotonic()})
                persist("refused_before_fence", failure=exc)
                raise
            receipt["phases"]["authenticated_preflight"] = authenticated
            if not authenticated["passed"]:
                refusal = BootstrapError("Runtime restart refused: owner identity changed or is stale.")
                phase_events.append({"phase": "authenticated_preflight", "result": "failed", "at": time.monotonic()})
                persist("refused_before_fence", failure=refusal)
                raise refusal
            phase_events.append({"phase": "authenticated_preflight", "result": "passed", "at": time.monotonic()})
            persist("authenticated_before_fence")
            from runtime_protocol.lifecycle import interruption_fence
            timeout_seconds = float(kwargs.get("interruption_timeout_seconds", 5.0))
            try:
                with interruption_fence(root, timeout_seconds=timeout_seconds) as fenced_idle:
                    phase_events.append({"phase": "interruption_fence", "result": "acquired", "at": time.monotonic()})
                    receipt["phases"]["interruption_fence"] = dict(fenced_idle)
                    try:
                        local_validation = validate_before_signal(
                            require_health=False, authenticate_endpoint=False
                        )
                    except Exception as exc:
                        receipt["phases"]["local_identity_revalidation"] = {
                            "passed": False,
                            "checks": {"identity_observation_completed": False},
                            "observed": {"failure_class": type(exc).__name__},
                        }
                        phase_events.append({"phase": "local_identity_revalidation", "result": "failed", "at": time.monotonic()})
                        persist("refused_under_fence", failure=exc)
                        raise
                    receipt["phases"]["local_identity_revalidation"] = local_validation
                    if not local_validation["passed"]:
                        refusal = BootstrapError("Runtime restart refused: owner identity changed or is stale.")
                        phase_events.append({"phase": "local_identity_revalidation", "result": "failed", "at": time.monotonic()})
                        persist("refused_under_fence", failure=refusal)
                        raise refusal
                    phase_events.append({"phase": "local_identity_revalidation", "result": "passed", "at": time.monotonic()})
                    persist("validated_under_fence")
                    if not self._process and getattr(self, "_detached_pid", None):
                        detached = int(self._detached_pid)
                        if detached != expected_pid:
                            raise BootstrapError("Runtime restart refused: adopted owner PID changed.")
                        persist("signal_authorized")
                        sealed_custody_signal = self._terminate_detached_owner(
                            support=support,
                            expected_pid=detached,
                            expected_birth=expected_birth,
                            event_callback=record_signal_effect,
                        )
                        self._detached_pid = None
                    else:
                        process = self._process
                        if process is None or process.pid != expected_pid:
                            raise BootstrapError("Runtime restart refused: owned process handle changed.")
                        persist("signal_authorized")
                        sealed_custody_signal = self._terminate_direct_child_owner_with_sealed_custody(
                            process,
                            support=support,
                            expected_pid=expected_pid,
                            expected_birth=expected_birth,
                            event_callback=record_signal_effect,
                        )
                        self._process = None
                    phase_events.append({
                        "phase": (
                            "sealed_signal"
                            if sealed_custody_signal
                            else "reaped_without_signal"
                        ),
                        "result": "completed",
                        "at": time.monotonic(),
                    })
                    persist("owner_stopped_under_fence")
            except Exception as exc:
                if receipt.get("state") not in {"refused_under_fence", "refused_before_fence"}:
                    persist("stop_failed", failure=exc)
                raise
            self._bootstrap_credential = None
            persist("completed")
            return {
                "status": "stopped",
                "realm_id": realm_id,
                "pid": expected_pid,
                "interruption_audit": dict(fenced_idle),
                "identity_validation": {
                    "authenticated_before_fence": True,
                    "local_fences_revalidated_under_fence": True,
                    "http_probe_under_fence": False,
                    "sealed_custody_signal": sealed_custody_signal,
                    "receipt_path": str(validation_path),
                },
            }

        # Restart and Worker-preserving handoff retain their existing live
        # endpoint checks and do not enter the normal-down fence above.
        require_validation(require_health=require_health)
        if preserve_worker:
            if not start_after_stop:
                raise BootstrapError("Worker preservation requires a replacement Runtime owner.")
            return self._restart_preserving_worker(
                source=source,
                root=root,
                support=support,
                realm_id=realm_id,
                owner_lock=owner_lock,
                endpoint=endpoint,
                expected_pid=expected_pid,
                expected_birth=expected_birth,
                expected_instance=expected_instance,
            )
        if not self._process and getattr(self, "_detached_pid", None):
            detached = int(self._detached_pid)
            if detached != expected_pid:
                raise BootstrapError("Runtime restart refused: adopted owner PID changed.")
            require_validation(require_health=require_health)
            self._terminate_detached_owner(
                support=support,
                expected_pid=detached,
                expected_birth=expected_birth,
            )
            self._detached_pid = None
        else:
            process = self._process
            if process is None or process.pid != expected_pid:
                raise BootstrapError("Runtime restart refused: owned process handle changed.")
            require_validation(require_health=require_health)
            self._terminate(process)
            self._process = None
        if not start_after_stop:
            self._bootstrap_credential = None
            return {"status": "stopped", "realm_id": realm_id, "pid": expected_pid}
        return self.start(realm_id=realm_id, realm_root=root, owner_lock=support / "instance.lock", source_profile=source)

    @staticmethod
    def _atomic_owner_json(path: Path, value: Mapping[str, Any]) -> None:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(dict(value), handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            path.chmod(0o600)
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _create_owner_json_no_clobber(path: Path, value: Mapping[str, Any]) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise BootstrapError(
                "An unresolved orderly handoff request already exists."
            ) from exc
        try:
            os.fchmod(descriptor, 0o600)
            payload = json.dumps(
                dict(value), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _observe_realm_flock_release(root: Path, deadline: float):
        lock_path = root / "owner.lock"
        handle = lock_path.open("a+")
        try:
            while time.monotonic() < deadline:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return handle
                except BlockingIOError:
                    time.sleep(0.02)
            raise BootstrapError("Owner A did not release the realm flock before the handoff deadline.")
        except BaseException:
            handle.close()
            raise

    def _restart_preserving_worker(
        self,
        *,
        source: SourceProfile,
        root: Path,
        support: Path,
        realm_id: str,
        owner_lock: Path,
        endpoint: str,
        expected_pid: int,
        expected_birth: str,
        expected_instance: str,
    ) -> Mapping[str, Any]:
        """Coordinate one fail-closed A-to-B descriptor handoff."""

        if not hasattr(signal, "SIGUSR1") or not hasattr(socket, "SCM_RIGHTS"):
            raise BootstrapError("Orderly Worker preservation is unsupported on this platform.")
        from runtime_protocol.catalog import process_birth_identity
        from runtime_protocol.local_worker_handoff import (
            TRANSFER_VERSION,
            peer_pid,
            peer_uid,
            receive_authority_transfer,
            receive_frame,
            send_frame,
        )
        from runtime_protocol.orderly_handoff import HandoffRecord, RECORD_VERSION, digest

        deadline = time.monotonic() + min(self.wait_seconds, 30.0)
        deadline_unix_ms = int((time.time() + max(0.1, deadline - time.monotonic())) * 1000)
        health = self._http_health_payload(endpoint)
        if not health:
            raise BootstrapError("Orderly Worker handoff requires a healthy owner A.")
        old_runtime = {
            "endpoint": endpoint,
            "protocol": health.get("protocol"),
            "schema_digest": health.get("schema_digest"),
            "runtime_epoch": health.get("runtime_epoch"),
            "runtime_instance_id": expected_instance,
            "runtime_session_id": health.get("runtime_session_id"),
        }
        handoff_id = uuid.uuid4().hex
        predecessor_active_ref_digest = self._predecessor_active_reference_digest(
            support,
            expected_pid=expected_pid,
            expected_birth=expected_birth,
            expected_instance=expected_instance,
        )
        mutex_path = support / "orderly-handoff-coordinator.lock"
        mutex_fd = os.open(
            mutex_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        rendezvous = None
        pointer_path = support / "orderly-handoff-request.json"
        listener = None
        channel = None
        transfer = None
        capability_parent = None
        process = None
        token_file = None
        record = None
        realm_custody = None
        handoff_completed = False
        try:
            os.fchmod(mutex_fd, 0o600)
            try:
                fcntl.flock(mutex_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BootstrapError("Another orderly Runtime restart coordinator is active.") from exc
            rendezvous = _create_compact_handoff_root()
            socket_path = rendezvous / "coordinator.sock"
            # Keep the exact authority record under the support root. The
            # rendezvous socket is temporary, but a coordinator crash or hard
            # B loss must leave a durable record that ordinary startup sees.
            record = HandoffRecord(
                support / f"orderly-handoff-record-{handoff_id}.json"
            )
            created = record.create({
                "version": RECORD_VERSION,
                "state": "OWNED",
                "handoff_id": handoff_id,
                "realm_id": realm_id,
                "realm_root": str(root),
                "support_root": str(support),
                "deadline_monotonic": deadline,
                "deadline_unix_ms": deadline_unix_ms,
                "nonce_digest": None,
                "sealed_record_digest": None,
                "old_owner": {
                    "pid": expected_pid,
                    "birth_id": expected_birth,
                    "runtime_instance_id": expected_instance,
                    "runtime": old_runtime,
                },
                "export": None,
                "export_sealed_digest": None,
                "adopter": None,
                "predecessor_active_ref_digest": predecessor_active_ref_digest,
            })
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            socket_path.chmod(0o600)
            listener.listen(1)
            listener.settimeout(max(0.1, deadline - time.monotonic()))
            coordinator_birth = process_birth_identity()
            self._create_owner_json_no_clobber(pointer_path, {
                "version": TRANSFER_VERSION,
                "handoff_id": handoff_id,
                "record_path": str(record.path),
                "socket_path": str(socket_path),
                "coordinator_pid": os.getpid(),
                "coordinator_birth_id": coordinator_birth,
            })
            self._signal_registered_owner(
                support=support,
                expected_pid=expected_pid,
                expected_birth=expected_birth,
                signum=signal.SIGUSR1,
            )
            channel, _ = listener.accept()
            channel.settimeout(max(0.1, deadline - time.monotonic()))
            if peer_uid(channel) != os.getuid() or peer_pid(channel) != expected_pid:
                raise BootstrapError("Owner A rendezvous identity is invalid.")
            hello = receive_frame(channel)
            if hello != {
                "version": TRANSFER_VERSION,
                "command": "owner_hello",
                "handoff_id": handoff_id,
                "owner_pid": expected_pid,
                "owner_birth_id": expected_birth,
                "record_digest": created["record_digest"],
            }:
                raise BootstrapError("Owner A handoff hello is invalid.")
            send_frame(channel, {
                "version": TRANSFER_VERSION,
                "command": "seal_challenge",
                "handoff_id": handoff_id,
                "record_digest": created["record_digest"],
            })
            capability = receive_frame(channel)
            if set(capability) != {"version", "command", "handoff_id", "nonce_digest"} or capability.get("version") != TRANSFER_VERSION or capability.get("command") != "seal_capability" or capability.get("handoff_id") != handoff_id:
                raise BootstrapError("Owner A handoff capability frame is invalid.")
            sealed = record.seal(
                expected_record_digest=created["record_digest"],
                nonce_sha256=str(capability["nonce_digest"]),
            )
            send_frame(channel, {
                "version": TRANSFER_VERSION,
                "command": "sealed",
                "handoff_id": handoff_id,
                "nonce_digest": sealed["nonce_digest"],
                "sealed_record_digest": sealed["sealed_record_digest"],
            })
            export_offer = _validate_owner_a_export_offer(
                receive_frame(channel),
                transfer_version=TRANSFER_VERSION,
                handoff_id=handoff_id,
                sealed_record_digest=sealed["sealed_record_digest"],
            )
            export_bound = record.bind_export(
                handoff_id=handoff_id,
                sealed_record_digest=sealed["sealed_record_digest"],
                expected_record_digest=sealed["record_digest"],
                export=export_offer["export"],
            )
            send_frame(channel, {
                "version": TRANSFER_VERSION,
                "command": "export_sealed",
                "handoff_id": handoff_id,
                "export_sealed_digest": export_bound["export_sealed_digest"],
                "export_record_digest": export_bound["record_digest"],
            })
            parsed = urlsplit(endpoint)
            transfer = receive_authority_transfer(
                channel,
                expected_uid=os.getuid(),
                expected_listener=(str(parsed.hostname), int(parsed.port)),
            )
            frame = transfer.frame
            if (
                frame.get("handoff_id") != handoff_id
                or frame.get("nonce_digest") != sealed["nonce_digest"]
                or frame.get("sealed_record_digest") != sealed["sealed_record_digest"]
                or frame.get("old_runtime") != old_runtime
                or not isinstance(frame.get("nonce"), str)
                or not isinstance(frame.get("export"), Mapping)
            ):
                raise BootstrapError("Owner A authority transfer is invalid.")
            if (
                frame.get("export") != export_bound["export"]
                or
                frame.get("export_sealed_digest") != export_bound["export_sealed_digest"]
                or frame.get("export_record_digest") != export_bound["record_digest"]
            ):
                raise BootstrapError("Owner A export seal is invalid.")
            prepared_record = record.transition(
                expected_state="OWNED",
                new_state="PREPARED",
                handoff_id=handoff_id,
                sealed_record_digest=sealed["sealed_record_digest"],
                expected_record_digest=export_bound["record_digest"],
                updates={},
            )
            send_frame(channel, {
                "version": TRANSFER_VERSION,
                "command": "custody_accepted",
                "handoff_id": handoff_id,
                "sealed_record_digest": sealed["sealed_record_digest"],
            })
            released = receive_frame(channel)
            if released != {
                "version": TRANSFER_VERSION,
                "command": "owner_released",
                "handoff_id": handoff_id,
                "owner_pid": expected_pid,
            }:
                raise BootstrapError("Owner A release acknowledgement is invalid.")
            realm_custody = self._observe_realm_flock_release(root, deadline)
            committed = record.transition(
                expected_state="PREPARED",
                new_state="COMMITTED_ORPHAN",
                handoff_id=handoff_id,
                sealed_record_digest=sealed["sealed_record_digest"],
                expected_record_digest=prepared_record["record_digest"],
                updates={"owner_a_released": True},
            )
            # B must acquire the real realm flock itself.  The coordinator has
            # positively observed release; relinquish its observation handle
            # immediately before spawning while retaining the coordinator mutex.
            fcntl.flock(realm_custody.fileno(), fcntl.LOCK_UN)
            realm_custody.close()
            realm_custody = None

            bootstrap_token = secrets.token_hex(32)
            token_file = self._token_file(support, bootstrap_token)
            argv = self._argv(
                source,
                realm_id=realm_id,
                realm_root=root,
                support_root=support,
                display_name=self._display_name,
                owner_lock=owner_lock,
                token_file=token_file,
            )
            capability_parent, capability_child = socket.socketpair()
            fixed = (198, 199, 200)
            # Duplicate every source before touching a fixed target.  Without
            # this relocation, an unusually high inherited source descriptor
            # equal to a later target could be overwritten by an earlier
            # dup2 and silently transfer the wrong authority to B.
            relocated = [
                fcntl.fcntl(
                    source_fd,
                    getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD),
                    max(fixed) + 1,
                )
                for source_fd in (
                    transfer.worker_control_fd,
                    transfer.listener_fd,
                    capability_child.fileno(),
                )
            ]
            try:
                for source_fd, target_fd in zip(relocated, fixed):
                    os.dup2(source_fd, target_fd, inheritable=True)
            finally:
                for source_fd in relocated:
                    os.close(source_fd)
            argv += [
                "--handoff-record", str(record.path),
                "--handoff-worker-fd", str(fixed[0]),
                "--handoff-listener-fd", str(fixed[1]),
                "--handoff-capability-fd", str(fixed[2]),
            ]
            log = (support / "runtime.log").open("ab")
            try:
                try:
                    process, _broker = self._spawn_custodied_runtime(
                        argv, support_root=support, stdout=log, pass_fds=fixed,
                    )
                except RuntimeCustodyLaunchUncertain as exc:
                    process = exc.process
                    raise
            finally:
                log.close()
                capability_child.close()
                for descriptor in fixed:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            capability_parent.settimeout(max(0.1, deadline - time.monotonic()))
            send_frame(capability_parent, {
                **frame,
                "command": "adopt",
                "committed_record_digest": committed["record_digest"],
            })
            accepted = receive_frame(capability_parent)
            if (
                set(accepted) != {
                    "version", "command", "handoff_id", "runtime_pid",
                    "runtime_birth_id", "runtime_instance_id",
                }
                or accepted.get("version") != TRANSFER_VERSION
                or accepted.get("command") != "descriptors_accepted"
                or accepted.get("handoff_id") != handoff_id
                or int(accepted.get("runtime_pid", 0)) != process.pid
                or accepted.get("runtime_birth_id") != self.process_birth_identity(process.pid)
            ):
                raise BootstrapError("Owner B descriptor acknowledgement is invalid.")
            adopter = record.bind_adopter(
                handoff_id=handoff_id,
                sealed_record_digest=sealed["sealed_record_digest"],
                expected_record_digest=committed["record_digest"],
                adopter={
                    "pid": process.pid,
                    "birth_id": accepted["runtime_birth_id"],
                    "runtime_instance_id": accepted["runtime_instance_id"],
                },
            )
            send_frame(capability_parent, {
                "version": TRANSFER_VERSION,
                "command": "adopter_bound",
                "handoff_id": handoff_id,
                "adopter_record_digest": adopter["record_digest"],
                "adopter": adopter["adopter"],
            })
            capability_parent.close()
            capability_parent = None
            transfer.close()
            transfer = None
            self._process = process
            self._source, self._realm_root, self._support_root, self._realm_id = source, root, support, realm_id
            self._bootstrap_credential = bootstrap_token
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise BootstrapError(f"Runtime owner B exited during handoff (see {support / 'runtime.log'}).")
                current = record.read()
                if current.get("state") == "ADOPTED":
                    discovery = self._read_discovery(support)
                    if (
                        int(discovery.get("pid", 0)) == process.pid
                        and discovery.get("worker_credential_pending") is False
                        and self._http_health(str(discovery.get("endpoint") or ""))
                        and self._http_claim_admission(
                            str(discovery.get("endpoint") or ""), bootstrap_token
                        )
                    ):
                        ready_identity = self._custody_identity(process.pid)
                        if ready_identity is None:
                            raise BootstrapError("Runtime ready owner identity is unavailable.")
                        _broker.bind_ready_token(
                            expected_pid=process.pid,
                            expected_identity=ready_identity,
                        )
                        publish_active_capability(
                            support / ACTIVE_CAPABILITY_NAME,
                            _broker,
                        )
                        self._publish_active_adopted_owner(
                            support=support,
                            record=record,
                            current=current,
                            process=process,
                            accepted=accepted,
                        )
                        # Authority is complete before result construction.
                        # A later formatting/reporting exception is
                        # observational and must not roll back healthy B.
                        handoff_completed = True
                        return self._report_authenticated_handoff(
                            process=process,
                            accepted=accepted,
                            discovery=discovery,
                            source=source,
                            current={**current, "_record_path": record.path},
                        )
                if current.get("state") == "ABORTED":
                    raise BootstrapError("Runtime owner B aborted the orderly Worker handoff.")
                time.sleep(0.02)
            raise BootstrapError("Runtime owner B did not adopt before the handoff deadline.")
        except BaseException:
            if transfer is not None:
                transfer.close()
            if record is not None and not handoff_completed:
                self._retain_failed_adopter_gate(
                    support=support,
                    record=record,
                    handoff_id=handoff_id,
                    process=process,
                    owner_b_birth_id=(
                        accepted.get("runtime_birth_id")
                        if isinstance(locals().get("accepted"), Mapping)
                        else None
                    ),
                )
            self._cleanup_failed_handoff_process(
                process,
                authenticated_admission_confirmed=handoff_completed,
            )
            # The coordinator can prove owner B exited, but it cannot by that
            # fact alone prove every adopted Worker/host/engine/listener group
            # disappeared.  B writes ABORTED only after RuntimeDaemon.stop()
            # completes its receipt-bound graph cleanup.  Otherwise retain the
            # custody state; it is deliberately fail-closed for operator audit.
            raise
        finally:
            clear_pointer = handoff_completed
            if not clear_pointer and record is not None:
                try:
                    retained = record.read()
                    clear_pointer = retained.get("state") == "ABORTED"
                    if (
                        clear_pointer
                        and retained.get("predecessor_active_ref_digest") is not None
                    ):
                        resolution_path = (
                            support
                            / f"orderly-handoff-predecessor-resolution-{handoff_id}.json"
                        )
                        try:
                            resolution = json.loads(
                                resolution_path.read_text(encoding="utf-8")
                            )
                            clear_pointer = bool(
                                isinstance(resolution, dict)
                                and resolution.get("state") == "COMPLETE"
                                and resolution.get("handoff_id") == handoff_id
                                and resolution.get("aborted_record_digest")
                                == retained.get("record_digest")
                                and resolution.get("predecessor_active_ref_digest")
                                == retained.get("predecessor_active_ref_digest")
                                and resolution.get("resolution_digest") == digest({
                                    key: item for key, item in resolution.items()
                                    if key != "resolution_digest"
                                })
                            )
                        except Exception:
                            clear_pointer = False
                    if (
                        not clear_pointer
                        and process is None
                        and retained.get("state") == "OWNED"
                        and self.process_birth_identity(expected_pid) == expected_birth
                        and self._http_health(endpoint)
                    ):
                        # A refused before custody transfer and remains the
                        # positively identified healthy owner. This is the one
                        # safe pre-export case where a retry gate may clear.
                        clear_pointer = True
                except Exception:
                    clear_pointer = False
            if clear_pointer:
                pointer_path.unlink(missing_ok=True)
            if realm_custody is not None:
                try:
                    fcntl.flock(realm_custody.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
                realm_custody.close()
            if capability_parent is not None:
                capability_parent.close()
            if channel is not None:
                channel.close()
            if listener is not None:
                listener.close()
            if rendezvous is not None:
                (rendezvous / "coordinator.sock").unlink(missing_ok=True)
                rendezvous.rmdir()
            if token_file is not None and process is None:
                token_file.unlink(missing_ok=True)
            try:
                fcntl.flock(mutex_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(mutex_fd)
