"""T2 neutral one-realm launch/reconnect lifecycle.

The boundary protocol is intentionally tiny.  A real generated workspace
client can implement it; tests use a fake.  Runtime ownership stays behind
that boundary; the activation verifier only performs read-only artifact
checks before a legacy-root collision may be waived.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import secrets
import stat
import time
from contextlib import contextmanager
from typing import Any, Mapping, Protocol, Sequence
import uuid

from .io import atomic_write_json, owner_only, read_json, remove_file
from .paths import RuntimePaths


PROTOCOL_VERSION = "workspace.v1"
SCHEMA_VERSION = "workspace-schema-v1"
RUNTIME_VERSION = PROTOCOL_VERSION
IMPORTER_VERSION = "t5"
CATALOG_VERSION = 1
DISCOVERY_VERSION = 1
LEGACY_NEXT_ACTION = (
    "Run the offline migrator before launching: "
    "banodoco-local migrate --profile astrid --source {legacy_root}"
)
RECONFIGURE_NEXT_ACTION = (
    "Restart the runtime with a compatible source profile: "
    "banodoco-local restart --profile astrid"
)
MULTI_REALM_NEXT_ACTION = (
    "Stage 1 supports one realm only; use the Stage 2 multi-realm workflow."
)


class BootstrapError(RuntimeError):
    """A deterministic, user-actionable bootstrap failure."""


class LegacyRootCollisionError(BootstrapError):
    pass


class DuplicateOwnerError(BootstrapError):
    pass


class CompatibilityError(BootstrapError):
    pass


class UnsupportedRealmError(BootstrapError):
    pass


class RuntimeBoundary(Protocol):
    """Generated-client/runtime seam used by bootstrap.

    Implementations may launch or connect to a daemon, but must keep database
    and object-store ownership inside that daemon.
    """

    def start(self, *, realm_id: str, realm_root: Path, owner_lock: Path,
              source_profile: "SourceProfile") -> Mapping[str, Any]: ...

    def connect(self, *, endpoint: str, credential: str) -> Any: ...

    def health(self, *, endpoint: str, pid: int, instance_id: str) -> bool: ...

    def validate_owner(self, *, endpoint: str, pid: int, instance_id: str,
                       owner_lock: Path, process_birth_id: str | None = None) -> bool: ...

    def is_pid_alive(self, pid: int) -> bool: ...


@dataclass(frozen=True)
class SourceProfile:
    profile: str
    runtime_checkout: str
    source_checkout: str
    runtime_environment: str | None = None
    runtime_command: tuple[str, ...] = ()
    protocol_version: str = PROTOCOL_VERSION
    schema_version: str = SCHEMA_VERSION
    capability_digest: str = ""
    source_digest: str = ""
    lock_digest: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, expected_profile: str = "astrid") -> "SourceProfile":
        profile = str(value.get("profile", ""))
        if profile != expected_profile:
            raise BootstrapError(f"Source profile must be {expected_profile!r}, got {profile!r}.")
        runtime_checkout = str(value.get("runtime_checkout", ""))
        source_checkout = str(value.get("source_checkout", ""))
        if not runtime_checkout or not source_checkout:
            raise BootstrapError(
                "Source profile is incomplete; configure runtime_checkout and source_checkout "
                "in the editable source manifest."
            )
        command = value.get("runtime_command", ())
        if isinstance(command, str):
            command = (command,)
        if not isinstance(command, Sequence):
            raise BootstrapError("Source profile runtime_command must be an argv array.")
        return cls(
            profile=profile,
            runtime_checkout=runtime_checkout,
            source_checkout=source_checkout,
            runtime_environment=(str(value["runtime_environment"]) if value.get("runtime_environment") else None),
            runtime_command=tuple(str(part) for part in command),
            protocol_version=str(value.get("protocol_version", PROTOCOL_VERSION)),
            schema_version=str(value.get("schema_version", SCHEMA_VERSION)),
            capability_digest=str(value.get("capability_digest", "")),
            source_digest=str(value.get("source_digest", "")),
            lock_digest=str(value.get("lock_digest", "")),
        )

    @classmethod
    def load(cls, path: Path | str, *, expected_profile: str = "astrid") -> "SourceProfile":
        raw = read_json(Path(path))
        if raw is None:
            raise BootstrapError(f"Source profile manifest is missing or invalid: {path}")
        return cls.from_mapping(raw, expected_profile=expected_profile)

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "runtime_checkout": self.runtime_checkout,
            "source_checkout": self.source_checkout,
            "runtime_environment": self.runtime_environment,
            "runtime_command": list(self.runtime_command),
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "capability_digest": self.capability_digest,
            "source_digest": self.source_digest,
            "lock_digest": self.lock_digest,
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(self.as_dict(), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class BootstrapConfig:
    profile: str = "astrid"
    display_name: str = "Astrid Workspace"
    source_profile: SourceProfile | None = None
    source_manifest: Path | None = None
    protocol_version: str = PROTOCOL_VERSION
    schema_version: str = SCHEMA_VERSION
    capability_digest: str = ""
    legacy_roots: tuple[Path, ...] = ()

    def resolve_source_profile(self, paths: RuntimePaths) -> SourceProfile:
        if self.source_profile is not None:
            return self.source_profile
        manifest = self.source_manifest or (paths.source_profiles_dir / f"{self.profile}.json")
        return SourceProfile.load(manifest, expected_profile=self.profile)


@dataclass(frozen=True)
class BootstrapResult:
    status: str
    realm_id: str
    display_name: str
    endpoint: str
    actor_id: str
    source_profile: str
    diagnostics: tuple[str, ...] = ()
    discovery_path: Path | None = field(default=None, compare=False)

    @property
    def ready(self) -> bool:
        return self.status in {"started", "reconnected", "restarted"}


def _default_legacy_roots(paths: RuntimePaths) -> tuple[Path, ...]:
    # These are collision signals only; no directory is scanned and no legacy
    # state is read.  Callers can provide the exact historical root explicitly.
    return (
        paths.home / ".astrid",
        paths.home / "Astrid" / "projects",
        paths.home / "Documents" / "Astrid" / "projects",
    )


def _legacy_collision(paths: RuntimePaths, configured: tuple[Path, ...]) -> Path | None:
    for root in (*configured, *_default_legacy_roots(paths)):
        root = Path(root).expanduser()
        # lexists is intentional: a dangling legacy symlink is still a
        # collision and must not be bypassed by a stale/empty catalog.
        if os.path.lexists(str(root)) and (root.is_dir() or root.is_file() or root.is_symlink()):
            if root == paths.home / ".astrid" and _verified_activation_manifest(paths):
                continue
            return root
    return None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _durable_activation_trust_key(paths: RuntimePaths, *, provision: bool = False) -> bytes | None:
    """Read or provision the owner-only activation trust anchor.

    This file lives in runtime support, outside the migration archive,
    destination realm, and activation registry.  A migration may create it
    once, but neither bootstrap nor migration ever derive it from artifacts.
    """
    path = paths.activation_trust_path
    try:
        # Read through a retained parent descriptor and ``openat`` with
        # ``O_NOFOLLOW``.  The previous lexical ``is_file``/``stat`` checks
        # followed by ``read_json(path)`` let a concurrent replacement swap
        # the anchor for a symlink between validation and use, turning the
        # trust source into a path-resolution race.
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_fd = os.open(path.parent, directory_flags)
        try:
            file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path.name, file_flags, dir_fd=parent_fd)
            try:
                metadata = os.fstat(fd)
                owner_uid = getattr(os, "getuid", lambda: metadata.st_uid)()
                if (not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != owner_uid
                        or stat.S_IMODE(metadata.st_mode) != 0o600):
                    return None
                data = bytearray()
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    data.extend(chunk)
                value = json.loads(bytes(data).decode("utf-8"))
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        value = None
    if isinstance(value, Mapping) and value.get("version") == 1:
        encoded = value.get("key_hex")
        if isinstance(encoded, str):
            try:
                key = bytes.fromhex(encoded)
            except ValueError:
                key = None
            if key is not None and len(key) >= 32:
                return key
    if not provision:
        # An absent support key is an unverified activation. Only the durable
        # owner-only anchor can authorize a legacy-root waiver.
        return None
    key = secrets.token_bytes(32)
    atomic_write_json(path, {"version": 1, "key_hex": key.hex()})
    return key


def _sha256_regular(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(fd)


def _read_json_regular(path: Path) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        data = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        return json.loads(bytes(data).decode("utf-8"))
    finally:
        os.close(fd)


def _stat_digest(path: Path) -> dict[str, int]:
    value = path.stat(follow_symlinks=False)
    return {"st_dev": int(value.st_dev), "st_ino": int(value.st_ino), "st_mode": int(value.st_mode)}


def _has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def _cas_inventory(root: Path) -> list[dict[str, Any]]:
    result = []
    cas = root / "cas"
    if not cas.is_dir() or cas.is_symlink():
        raise OSError("CAS root is unavailable")
    for path in sorted(cas.rglob("*")):
        if path.is_symlink():
            raise OSError("CAS contains a symlink")
        if path.is_file():
            result.append({"path": str(path.relative_to(root)), "size": path.stat().st_size, "sha256": _sha256_regular(path)})
    return result


def _cas_digest(root: Path) -> str:
    return hashlib.sha256(_canonical_json(_cas_inventory(root))).hexdigest()


def _source_tree_digest(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise OSError("archive source tree is unavailable")
    result = []
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            resolved = path.resolve(strict=False)
            try:
                resolved.relative_to(root.resolve())
                inside = True
            except ValueError:
                inside = False
            result.append({"path": relative, "kind": "symlink", "target": os.readlink(path), "resolved_inside_root": inside})
        elif path.is_file():
            result.append({"path": relative, "kind": "file", "size": path.stat().st_size, "sha256": _sha256_regular(path)})
    return hashlib.sha256(_canonical_json(result)).hexdigest()


def _verified_activation_manifest(paths: RuntimePaths) -> bool:
    """Verify a complete activation registry against every referenced byte."""
    trust_key = _durable_activation_trust_key(paths)
    if trust_key is None:
        return False
    if paths.activations_dir.is_symlink() or not paths.activations_dir.is_dir():
        return False
    try:
        manifests = tuple(paths.activations_dir.glob("*.json"))
    except OSError:
        return False
    for path in manifests:
        try:
            if path.is_symlink() or not path.is_file() or path.name.startswith("."):
                continue
            value = _read_json_regular(path)
            if not isinstance(value, Mapping) or value.get("registry_version") != 1 or value.get("state") != "activated":
                continue
            registry_hash = value.get("registry_sha256")
            unsigned = {key: item for key, item in value.items() if key != "registry_sha256"}
            if not isinstance(registry_hash, str) or registry_hash != hashlib.sha256(_canonical_json(unsigned)).hexdigest():
                continue
            required = ("realm_id", "source_archive", "source_archive_sha256", "source_archive_identity", "source_manifest_sha256",
                        "source_archive_tree_sha256", "destination_root", "destination_identity",
                        "destination_database_sha256", "cas_inventory_sha256", "cas_inventory",
                        "migration_report", "migration_report_sha256", "activation_manifest",
                        "activation_manifest_sha256", "runtime_version", "schema_version",
                        "protocol_version", "importer_version", "source_version", "reconciliation",
                        "activation_signature")
            if any(not isinstance(value.get(key), (str, dict, list)) or value[key] in ("", None) for key in required):
                continue
            if (value["protocol_version"] != PROTOCOL_VERSION
                    or value["schema_version"] != SCHEMA_VERSION
                    or value["runtime_version"] != RUNTIME_VERSION
                    or value["importer_version"] != IMPORTER_VERSION):
                continue
            hex_fields = ("source_archive_sha256", "source_manifest_sha256", "source_archive_tree_sha256",
                          "destination_database_sha256", "cas_inventory_sha256", "migration_report_sha256",
                          "activation_manifest_sha256")
            if any(not isinstance(value.get(key), str) or len(value[key]) != 64 or any(c not in "0123456789abcdef" for c in value[key]) for key in hex_fields):
                continue
            destination = Path(str(value["destination_root"]))
            archive = Path(str(value["source_archive"]))
            report = Path(str(value["migration_report"]))
            activation = Path(str(value["activation_manifest"]))
            if any(not item.is_absolute() or _has_symlink_component(item) or item.is_symlink() for item in (destination, archive, report, activation)):
                continue
            if destination != Path(os.path.realpath(destination)) or not destination.is_dir():
                continue
            if value["activation_manifest"] != str(destination / "activation-manifest.json") or activation != destination / "activation-manifest.json":
                continue
            if value["realm_id"] != path.stem:
                continue
            if _stat_digest(destination) != value["destination_identity"] or _stat_digest(archive) != value["source_archive_identity"]:
                continue
            if _sha256_regular(activation) != value["activation_manifest_sha256"] or _sha256_regular(destination / "realm.sqlite3") != value["destination_database_sha256"]:
                continue
            if _cas_digest(destination) != value["cas_inventory_sha256"] or _cas_inventory(destination) != value["cas_inventory"]:
                continue
            if not archive.is_dir() or _sha256_regular(archive / "manifest.json") != value["source_archive_sha256"]:
                continue
            archive_manifest = _read_json_regular(archive / "manifest.json")
            if not isinstance(archive_manifest, Mapping):
                continue
            if (archive_manifest.get("source_version") != value["source_version"]
                    or archive_manifest.get("source_manifest_sha256") != value["source_manifest_sha256"]
                    or archive_manifest.get("archive_source_tree_sha256") != value["source_archive_tree_sha256"]
                    or archive_manifest.get("files_sha256") != value["source_archive_tree_sha256"]
                    or _source_tree_digest(archive / "source") != value["source_archive_tree_sha256"]):
                continue
            report_value = _read_json_regular(report)
            if not isinstance(report_value, Mapping):
                continue
            if hashlib.sha256(_canonical_json(report_value)).hexdigest() != value["migration_report_sha256"]:
                continue
            activation_value = _read_json_regular(activation)
            if not isinstance(activation_value, Mapping):
                continue
            activation_expected = {key: item for key, item in value.items() if key not in {"registry_version", "registry_sha256", "activation_manifest", "activation_manifest_sha256"}}
            if activation_value != activation_expected:
                continue
            signature = activation_value.get("activation_signature")
            unsigned_activation = {key: item for key, item in activation_value.items() if key != "activation_signature"}
            expected_signature = hmac.new(trust_key, _canonical_json(unsigned_activation), hashlib.sha256).hexdigest()
            if (not isinstance(signature, str)
                    or not hmac.compare_digest(signature, expected_signature)):
                continue
            reconciliation = activation_value.get("reconciliation")
            if (activation_value.get("state") != "activated"
                    or not isinstance(reconciliation, Mapping)
                    or reconciliation.get("ok") is not True):
                continue
            with sqlite3.connect((destination / "realm.sqlite3").as_uri() + "?mode=ro", uri=True) as db:
                realm = db.execute("SELECT id FROM realm LIMIT 1").fetchone()
            if not realm or str(realm[0]) != str(value["realm_id"]):
                continue
            catalog = _read_catalog(paths)
            rows = [row for row in catalog.get("realms", []) if isinstance(row, Mapping) and str(row.get("realm_id")) == str(value["realm_id"])]
            if catalog.get("selected_realm_id") != value["realm_id"] or len(rows) != 1:
                continue
            catalog_root = Path(str(rows[0].get("data_root", "")))
            if (not catalog_root.is_absolute() or _has_symlink_component(catalog_root)
                    or catalog_root != destination or os.path.realpath(str(catalog_root)) != str(destination)):
                continue
            return True
        except (OSError, ValueError, TypeError, sqlite3.Error, BootstrapError):
            continue
    return False


def _new_realm_id() -> str:
    return uuid.uuid4().hex


def _read_catalog(paths: RuntimePaths) -> dict[str, Any]:
    catalog = read_json(paths.catalog_path)
    if catalog is None:
        return {"version": CATALOG_VERSION, "selected_realm_id": None, "realms": [], "source_profiles": {}}
    catalog.setdefault("version", CATALOG_VERSION)
    catalog.setdefault("realms", [])
    catalog.setdefault("source_profiles", {})
    if not isinstance(catalog["realms"], list):
        raise BootstrapError("Neutral realm catalog is invalid; recover or remove catalog.json.")
    return catalog


def _selected_realm(catalog: dict[str, Any]) -> dict[str, Any] | None:
    realms = catalog.get("realms", [])
    if len(realms) > 1:
        raise UnsupportedRealmError(MULTI_REALM_NEXT_ACTION)
    if not realms:
        return None
    selected = catalog.get("selected_realm_id")
    realm = realms[0]
    if selected and selected != realm.get("realm_id"):
        raise BootstrapError("Catalog selected realm is inconsistent; run banodoco-local doctor.")
    return realm


def _credential(paths: RuntimePaths) -> tuple[str, str]:
    paths.credentials_dir.mkdir(parents=True, exist_ok=True)
    owner_only(paths.credentials_dir, directory=True)
    path = paths.credentials_dir / "astrid.json"
    current = read_json(path)
    if current and current.get("scope") == "astrid" and isinstance(current.get("token"), str):
        token = current["token"]
        if len(token) == 64:
            return str(current.get("actor_id") or _actor_id(token)), token
    token = secrets.token_hex(32)
    actor_id = _actor_id(token)
    atomic_write_json(path, {"version": 1, "scope": "astrid", "actor_id": actor_id, "token": token})
    return actor_id, token


def _actor_id(token: str) -> str:
    return "astrid-" + hashlib.sha256(token.encode()).hexdigest()[:24]


def _compatible(discovery: Mapping[str, Any], config: BootstrapConfig, source: SourceProfile) -> None:
    if discovery.get("protocol_version") != config.protocol_version or discovery.get("schema_version") != config.schema_version:
        raise CompatibilityError(
            "Runtime protocol/schema is incompatible. " + RECONFIGURE_NEXT_ACTION
        )
    if config.capability_digest and discovery.get("capability_digest") not in {None, "", config.capability_digest}:
        raise CompatibilityError("Runtime capability digest is incompatible. " + RECONFIGURE_NEXT_ACTION)
    if source.protocol_version != config.protocol_version or source.schema_version != config.schema_version:
        raise CompatibilityError("Source profile protocol/schema is incompatible. " + RECONFIGURE_NEXT_ACTION)


def _pid_alive(boundary: RuntimeBoundary | None, pid: Any) -> bool:
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return False
    try:
        if boundary is not None:
            return bool(boundary.is_pid_alive(pid_int))
    except Exception:
        pass
    try:
        if pid_int <= 0:
            return False
        try:
            os.kill(pid_int, 0)
            return True
        except OSError:
            return False
    except OSError:
        return False


def _lock_matches(paths: RuntimePaths, pid: int, instance_id: str, realm_id: str, process_birth_id: str | None = None) -> bool:
    marker = read_json(paths.instance_lock_path)
    return bool(
        marker
        and str(marker.get("pid")) == str(pid)
        and str(marker.get("runtime_instance_id")) == instance_id
        and str(marker.get("realm_id")) == realm_id
        and (process_birth_id is None or str(marker.get("process_birth_id")) == process_birth_id)
    )


@contextmanager
def _bootstrap_mutex(paths: RuntimePaths):
    """Serialize launchers so two clean launches cannot both start a daemon."""
    paths.runtime_support.mkdir(parents=True, exist_ok=True)
    owner_only(paths.runtime_support, directory=True)
    handle = paths.bootstrap_lock_path.open("a+")
    owner_only(paths.bootstrap_lock_path)
    try:
        try:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            # The daemon's instance lock remains the authoritative fallback on
            # platforms without advisory flock support.
            pass
        yield
    finally:
        try:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (ImportError, OSError):
            pass
        handle.close()


def _provision_connection(connection: Any, actor_id: str, token: str, realm_id: str) -> None:
    """Call only generated-client-shaped methods; never inspect runtime state."""
    provision = getattr(connection, "provision_actor", None)
    if provision is not None:
        result = provision(scope="astrid", actor_id=actor_id, credential=token)
        if isinstance(result, Mapping) and result.get("scope") not in (None, "astrid"):
            raise BootstrapError("Runtime refused the Astrid-scoped credential.")
    select = getattr(connection, "select_realm", None)
    if select is not None:
        select(actor_id=actor_id, realm_id=realm_id)
    handshake = getattr(connection, "handshake", None)
    if handshake is not None:
        handshake(protocol_version=PROTOCOL_VERSION, schema_version=SCHEMA_VERSION)


def bootstrap(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    config: BootstrapConfig | None = None,
) -> BootstrapResult:
    """Perform ``banodoco-local up`` for the one current-Mac realm."""
    config = config or BootstrapConfig()
    # Collision detection is deliberately before the mutex/support directory:
    # a legacy checkout must never cause even neutral launch state to be
    # created, and the user must be directed to the offline migrator first.
    if config.profile != "astrid":
        raise BootstrapError("Stage 1 supports only the astrid profile.")
    collision = _legacy_collision(paths, config.legacy_roots)
    if collision is not None:
        raise LegacyRootCollisionError(LEGACY_NEXT_ACTION.format(legacy_root=collision))
    config.resolve_source_profile(paths)
    with _bootstrap_mutex(paths):
        return _bootstrap_locked(paths, boundary, config)


def _bootstrap_locked(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig) -> BootstrapResult:
    if config.profile != "astrid":
        raise BootstrapError("Stage 1 supports only the astrid profile.")
    source = config.resolve_source_profile(paths)
    configure = getattr(boundary, "configure_source", None)
    if configure is not None:
        configure(source)
    collision = _legacy_collision(paths, config.legacy_roots)
    if collision is not None:
        raise LegacyRootCollisionError(LEGACY_NEXT_ACTION.format(legacy_root=collision))

    paths.ensure_support_dirs()
    _durable_activation_trust_key(paths, provision=True)
    catalog = _read_catalog(paths)
    realm = _selected_realm(catalog)
    diagnostics: list[str] = []

    discovery = read_json(paths.discovery_path)
    if discovery is not None and discovery.get("active_realm"):
        _compatible(discovery, config, source)
        pid = discovery.get("pid")
        endpoint = str(discovery.get("endpoint", ""))
        instance_id = str(discovery.get("runtime_instance_id", ""))
        if _pid_alive(boundary, pid):
            if not endpoint or not instance_id:
                raise DuplicateOwnerError(
                    "A runtime owner is active but its discovery record is incomplete; "
                    "stop that owner, then run banodoco-local restart --profile astrid."
                )
            valid_owner = boundary.validate_owner(
                endpoint=endpoint, pid=int(pid), instance_id=instance_id, owner_lock=paths.instance_lock_path,
                process_birth_id=str(discovery.get("process_birth_id") or "")
            )
            if not valid_owner or not discovery.get("process_birth_id") or not _lock_matches(paths, int(pid), instance_id, str(discovery["active_realm"]), str(discovery.get("process_birth_id"))):
                raise DuplicateOwnerError(
                    "A different runtime owner is active for the selected realm; "
                    "stop it before retrying banodoco-local up --profile astrid."
                )
            if not boundary.health(endpoint=endpoint, pid=int(pid), instance_id=instance_id):
                raise BootstrapError("The selected runtime owner is unhealthy; next action: " + RECONFIGURE_NEXT_ACTION)
            if realm is None or str(realm.get("realm_id")) != str(discovery["active_realm"]):
                raise BootstrapError("Discovery does not match the selected catalog realm; run banodoco-local doctor.")
            actor_id, token = _credential(paths)
            connection = boundary.connect(endpoint=endpoint, credential=token)
            realm_id = str(discovery["active_realm"])
            _provision_connection(connection, actor_id, token, realm_id)
            diagnostics.append("runtime checkout differences are provenance only")
            return BootstrapResult("reconnected", realm_id, str(realm.get("display_name", "Astrid Workspace")) if realm else "Astrid Workspace", endpoint, actor_id, source.profile, tuple(diagnostics), paths.discovery_path)
        # A dead advertisement is ephemeral support state.  Remove it before
        # starting so a crash cannot be mistaken for a live owner.
        remove_file(paths.discovery_path)

    # A daemon may have advertised successfully but crashed before its
    # ephemeral discovery write (or discovery may have been manually removed).
    # Never start a second owner while the durable instance lock still points
    # at a live process.
    marker = read_json(paths.instance_lock_path)
    if marker and _pid_alive(boundary, marker.get("pid")):
        raise DuplicateOwnerError(
            "A different runtime owner is active for the selected realm; "
            "stop it before retrying banodoco-local up --profile astrid."
        )

    if realm is None:
        realm = {
            "realm_id": _new_realm_id(),
            "display_name": config.display_name,
            "data_root": str(paths.realms_dir / _new_realm_id()),
        }
        # Use one opaque id for both catalog identity and root name.
        realm["data_root"] = str(paths.realms_dir / realm["realm_id"])
        catalog["realms"] = [realm]
        catalog["selected_realm_id"] = realm["realm_id"]
    elif catalog.get("selected_realm_id") is None:
        catalog["selected_realm_id"] = realm["realm_id"]

    realm_id = str(realm["realm_id"])
    handle = boundary.start(
        realm_id=realm_id,
        realm_root=Path(str(realm["data_root"])),
        owner_lock=paths.instance_lock_path,
        source_profile=source,
    )
    try:
        endpoint = str(handle["endpoint"])
        pid = int(handle["pid"])
        instance_id = str(handle["runtime_instance_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("Runtime start returned incomplete owner metadata.") from exc
    process_birth_id = str(handle.get("process_birth_id") or handle.get("birth_id") or "")
    if not process_birth_id:
        birth_fn = getattr(boundary, "process_birth_identity", None)
        if birth_fn is not None:
            process_birth_id = str(birth_fn(pid) or "")
    # Test/fake boundaries may not expose an OS process marker.  Keep a
    # synthetic marker in their hand-off while real boundaries always use the
    # kernel/ps birth identity above.
    if not process_birth_id:
        process_birth_id = f"synthetic:{instance_id}:{pid}"
    if not boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id):
        raise BootstrapError("Runtime started but failed health check; next action: " + RECONFIGURE_NEXT_ACTION)
    # The marker contains ownership metadata only and never a credential.
    atomic_write_json(paths.instance_lock_path, {"pid": pid, "process_birth_id": process_birth_id, "runtime_instance_id": instance_id, "realm_id": realm_id})
    actor_id, token = _credential(paths)
    connection = boundary.connect(endpoint=endpoint, credential=token)
    _provision_connection(connection, actor_id, token, realm_id)
    realm["source_profile"] = source.profile
    catalog["source_profiles"][source.profile] = source.as_dict()
    atomic_write_json(paths.catalog_path, catalog)
    # Keep the editable source profile at the neutral support boundary after a
    # successful launch.  ``up`` may have received a one-shot manifest from a
    # product launcher, and later operator reconnect/restart commands must be
    # able to resolve the same composition without requiring that temporary
    # path or a second manual setup step.  This is composition metadata only;
    # it is not a runtime/database authority and is written only after the
    # daemon, credential handoff, activation, and catalog commit succeeded.
    atomic_write_json(
        paths.source_profiles_dir / f"{source.profile}.json",
        source.as_dict(),
    )
    discovery_value = {
        "version": DISCOVERY_VERSION,
        "endpoint": endpoint,
        "pid": pid,
        "process_birth_id": process_birth_id,
        "runtime_instance_id": instance_id,
        "active_realm": realm_id,
        "coordinator_epoch": handle.get("coordinator_epoch"),
        "protocol_version": handle.get("protocol_version", source.protocol_version),
        "schema_version": handle.get("schema_version", source.schema_version),
        "capability_digest": handle.get("capability_digest", source.capability_digest),
        "credential_file": str(paths.credentials_dir / "astrid.json"),
        "advertised_at": time.time(),
    }
    atomic_write_json(paths.discovery_path, discovery_value)
    return BootstrapResult("started", realm_id, str(realm["display_name"]), endpoint, actor_id, source.profile, tuple(diagnostics), paths.discovery_path)


def connect(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig | None = None) -> BootstrapResult:
    """Connect without creating a realm or starting authority."""
    config = config or BootstrapConfig()
    catalog = _read_catalog(paths)
    realm = _selected_realm(catalog)
    discovery = read_json(paths.discovery_path)
    if realm is None or not discovery:
        raise BootstrapError("No healthy selected runtime. Next action: banodoco-local up --profile astrid")
    source = config.resolve_source_profile(paths)
    _compatible(discovery, config, source)
    try:
        pid = int(discovery["pid"])
        endpoint = str(discovery["endpoint"])
        instance_id = str(discovery["runtime_instance_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("Runtime discovery is incomplete; run banodoco-local restart --profile astrid.") from exc
    if not _pid_alive(boundary, pid) or not boundary.validate_owner(endpoint=endpoint, pid=pid, instance_id=instance_id, owner_lock=paths.instance_lock_path):
        raise BootstrapError("Runtime discovery is stale or owned by another process; run banodoco-local up --profile astrid.")
    if not boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id):
        raise BootstrapError("The selected runtime is unhealthy; run banodoco-local restart --profile astrid.")
    if str(realm.get("realm_id")) != str(discovery.get("active_realm")):
        raise BootstrapError("Discovery does not match the selected catalog realm; run banodoco-local doctor.")
    actor_id, token = _credential(paths)
    connection = boundary.connect(endpoint=endpoint, credential=token)
    _provision_connection(connection, actor_id, token, str(realm["realm_id"]))
    return BootstrapResult("reconnected", str(realm["realm_id"]), str(realm.get("display_name", "Astrid Workspace")), endpoint, actor_id, source.profile, (), paths.discovery_path)


def restart(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig | None = None) -> BootstrapResult:
    """Restart the selected owner through the client/boundary seam."""
    config = config or BootstrapConfig()
    discovery = read_json(paths.discovery_path)
    if not discovery:
        raise BootstrapError("No runtime to restart. Next action: banodoco-local up --profile astrid")
    try:
        pid = int(discovery["pid"])
        endpoint = str(discovery["endpoint"])
        instance_id = str(discovery["runtime_instance_id"])
        realm_id = str(discovery["active_realm"])
        process_birth_id = str(discovery["process_birth_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("Runtime restart refused: discovery identity is incomplete; run banodoco-local up.") from exc
    # Real boundaries must prove liveness.  Tiny in-memory test boundaries do
    # not have an OS identity provider and are allowed to model the hand-off
    # without a kernel PID.
    modeled_boundary = getattr(boundary, "process_birth_identity", None) is None
    if not endpoint or not instance_id or not realm_id or not process_birth_id or (not _pid_alive(boundary, pid) and not modeled_boundary):
        raise BootstrapError("Runtime restart refused: owner is stale or discovery identity is incomplete.")
    if not _lock_matches(paths, pid, instance_id, realm_id, process_birth_id):
        raise BootstrapError("Runtime restart refused: owner lock does not match discovery.")
    validate = getattr(boundary, "validate_owner", None)
    if validate is None or not validate(endpoint=endpoint, pid=pid, instance_id=instance_id, owner_lock=paths.instance_lock_path, process_birth_id=process_birth_id):
        raise BootstrapError("Runtime restart refused: owner endpoint or process identity failed validation.")
    restart_fn = getattr(boundary, "restart", None)
    if restart_fn is None:
        remove_file(paths.discovery_path)
        result = bootstrap(paths, boundary, config)
        return BootstrapResult("restarted", result.realm_id, result.display_name, result.endpoint, result.actor_id, result.source_profile, result.diagnostics, result.discovery_path)
    handle = restart_fn(endpoint=endpoint, pid=pid, instance_id=instance_id, process_birth_id=process_birth_id, realm_id=realm_id, owner_lock=paths.instance_lock_path, discovery_path=paths.discovery_path)
    # The boundary restart returns the same metadata shape as start.  Publish
    # its fresh advertisement, then let normal bootstrap validation reconnect;
    # this avoids a second start and keeps all credential/client calls unified.
    refreshed = dict(discovery)
    refreshed.update({
        "endpoint": str(handle["endpoint"]),
        "pid": int(handle["pid"]),
        "process_birth_id": str(handle.get("process_birth_id") or handle.get("birth_id") or f"synthetic:{handle.get('runtime_instance_id')}:{handle.get('pid')}"),
        "runtime_instance_id": str(handle["runtime_instance_id"]),
        "coordinator_epoch": handle.get("coordinator_epoch", discovery.get("coordinator_epoch")),
        "protocol_version": handle.get("protocol_version", discovery.get("protocol_version")),
        "schema_version": handle.get("schema_version", discovery.get("schema_version")),
        "capability_digest": handle.get("capability_digest", discovery.get("capability_digest")),
        "advertised_at": time.time(),
    })
    atomic_write_json(paths.instance_lock_path, {
        "pid": int(handle["pid"]),
        "process_birth_id": refreshed["process_birth_id"],
        "runtime_instance_id": str(handle["runtime_instance_id"]),
        "realm_id": str(discovery["active_realm"]),
    })
    atomic_write_json(paths.discovery_path, refreshed)
    result = bootstrap(paths, boundary, config)
    return BootstrapResult("restarted", result.realm_id, result.display_name, result.endpoint, result.actor_id, result.source_profile, result.diagnostics, result.discovery_path)


def doctor(paths: RuntimePaths, boundary: RuntimeBoundary | None = None) -> dict[str, Any]:
    """Read-only support-state diagnostics.  This function creates no files."""
    catalog = read_json(paths.catalog_path)
    discovery = read_json(paths.discovery_path)
    report: dict[str, Any] = {
        "healthy": True,
        "catalog_path": str(paths.catalog_path),
        "discovery_path": str(paths.discovery_path),
        "catalog_present": catalog is not None,
        "discovery_present": discovery is not None,
        "issues": [],
    }
    if catalog is None:
        report["healthy"] = False
        report["issues"].append("catalog_missing")
    else:
        try:
            realm = _selected_realm(catalog)
            report["realm_id"] = realm.get("realm_id") if realm else None
            if realm and not Path(str(realm.get("data_root", ""))).exists():
                report["healthy"] = False
                report["issues"].append("realm_root_missing")
        except BootstrapError as exc:
            report["healthy"] = False
            report["issues"].append(str(exc))
    if discovery is not None:
        report["pid_alive"] = bool(_pid_alive(boundary, discovery.get("pid")))
        if not report["pid_alive"]:
            report["healthy"] = False
            report["issues"].append("stale_discovery")
        elif boundary:
            try:
                owner_ok = bool(boundary.validate_owner(endpoint=str(discovery.get("endpoint", "")), pid=int(discovery["pid"]), instance_id=str(discovery.get("runtime_instance_id", "")), owner_lock=paths.instance_lock_path, process_birth_id=str(discovery.get("process_birth_id") or "")))
            except Exception:
                owner_ok = False
            if not owner_ok:
                report["healthy"] = False
                report["issues"].append("discovery_identity")
            elif not boundary.health(endpoint=str(discovery.get("endpoint", "")), pid=int(discovery["pid"]), instance_id=str(discovery.get("runtime_instance_id", ""))):
                report["healthy"] = False
                report["issues"].append("runtime_unhealthy")
    return report
