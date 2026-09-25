from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import tempfile
import threading
import uuid
from pathlib import Path

from .errors import AuthorizationError, ValidationError


class CredentialStore:
    """Owner-only bearer credentials with explicit actor scopes."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self._lock = threading.RLock()
        self._disabled_actors: set[str] = set()

    @staticmethod
    def _actor(actor: str) -> str:
        if not actor or "/" in actor or ".." in actor:
            raise ValidationError("invalid actor")
        return actor

    def path_for(self, actor: str) -> Path:
        return self.root / f"{self._actor(actor)}.token"

    @staticmethod
    def _canonical(value) -> str:
        try:
            return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValidationError("credential metadata must be JSON-compatible") from exc

    @staticmethod
    def _sha256(value: bytes) -> str:
        return "sha256:" + hashlib.sha256(value).hexdigest()

    def _paths(self, actor: str) -> tuple[Path, Path, Path]:
        token = self.path_for(actor)
        return token, token.with_suffix(".json"), token.with_suffix(".commit")

    @staticmethod
    def _safe_file(path: Path, label: str) -> None:
        try:
            value = path.lstat()
        except OSError as exc:
            raise ValidationError(f"{label} is unavailable") from exc
        if path.is_symlink() or not stat.S_ISREG(value.st_mode):
            raise ValidationError(f"{label} must be a regular non-symlink file")
        if value.st_uid != getattr(os, "getuid", lambda: value.st_uid)():
            raise ValidationError(f"{label} owner does not match the runtime")
        if stat.S_IMODE(value.st_mode) != 0o600:
            raise ValidationError(f"{label} must be owner-only")

    def _atomic_replace(self, path: Path, value: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=self.root)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)

    def _commit_value(self, token_bytes: bytes, metadata_bytes: bytes) -> bytes:
        return self._canonical({
            "generation": uuid.uuid4().hex,
            "token_sha256": self._sha256(token_bytes),
            "metadata_sha256": self._sha256(metadata_bytes),
        }).encode("utf-8")

    def _read_actor(self, actor: str) -> tuple[str, dict]:
        token_path, metadata_path, commit_path = self._paths(actor)
        for path, label in ((token_path, "credential token"), (metadata_path, "credential metadata"), (commit_path, "credential commit")):
            self._safe_file(path, label)
        try:
            token_bytes = token_path.read_bytes()
            metadata_bytes = metadata_path.read_bytes()
            commit = json.loads(commit_path.read_text(encoding="utf-8"))
            metadata = json.loads(metadata_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("credential generation is unreadable") from exc
        token = token_bytes.decode("utf-8").strip()
        if (not token or not isinstance(metadata, dict) or not isinstance(commit, dict)
                or commit.get("token_sha256") != self._sha256(token_bytes)
                or commit.get("metadata_sha256") != self._sha256(metadata_bytes)):
            raise ValidationError("credential generation is inconsistent")
        return token, metadata

    def _publish(self, actor: str, token: str, value: dict) -> Path:
        token_path, metadata_path, commit_path = self._paths(actor)
        if token_path.is_symlink() or metadata_path.is_symlink() or commit_path.is_symlink():
            raise ValidationError("credential path must not be a symlink")
        token_bytes = token.encode("utf-8")
        metadata_bytes = json.dumps(value).encode("utf-8")
        # The commit marker is replaced last. A crash after either data-file
        # replacement leaves hashes that cannot authenticate as one generation.
        self._atomic_replace(token_path, token_bytes)
        self._atomic_replace(metadata_path, metadata_bytes)
        self._atomic_replace(commit_path, self._commit_value(token_bytes, metadata_bytes))
        return token_path

    def _legacy_pair(self, actor: str) -> tuple[str, dict] | None:
        """Read the pre-marker format once so exact credentials can be upgraded."""
        token_path, metadata_path, commit_path = self._paths(actor)
        if commit_path.exists() or not token_path.exists() or not metadata_path.exists():
            return None
        self._safe_file(token_path, "credential token")
        self._safe_file(metadata_path, "credential metadata")
        try:
            token = token_path.read_text(encoding="utf-8").strip()
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        return (token, metadata) if token and isinstance(metadata, dict) else None

    def has_legacy_generation(self, actor: str) -> bool:
        """Return whether actor storage is the pre-commit credential format."""
        actor = self._actor(actor)
        with self._lock:
            return self._legacy_pair(actor) is not None

    def provision(self, actor: str, scopes: list[str], *, metadata: dict | None = None, rotate: bool = False, enabled: bool = True) -> tuple[str, Path]:
        actor = self._actor(actor)
        if metadata is not None and not isinstance(metadata, dict):
            raise ValidationError("credential metadata must be an object")
        if metadata is not None and set(metadata) & {"actor", "scopes"}:
            raise ValidationError("credential metadata cannot override actor or scopes")
        expected_scopes = sorted(set(str(scope) for scope in scopes))
        expected_metadata = dict(metadata or {})
        self._canonical(expected_metadata)
        expected = {"actor": actor, "scopes": expected_scopes, **expected_metadata}
        token_path, metadata_path, commit_path = self._paths(actor)
        with self._lock:
            current = None
            if not rotate:
                try:
                    current = self._read_actor(actor)
                except ValidationError:
                    current = self._legacy_pair(actor)
            if current is not None and current[1] == expected:
                token = current[0]
                if not commit_path.exists():
                    token_bytes = token_path.read_bytes()
                    metadata_bytes = metadata_path.read_bytes()
                    self._atomic_replace(commit_path, self._commit_value(token_bytes, metadata_bytes))
                if enabled:
                    self._disabled_actors.discard(actor)
                else:
                    self._disabled_actors.add(actor)
                return token, token_path
            if token_path.is_symlink() or metadata_path.is_symlink() or commit_path.is_symlink():
                raise ValidationError("credential path must not be a symlink")
            token = secrets.token_urlsafe(32)
            path = self._publish(actor, token, expected)
            if enabled:
                self._disabled_actors.discard(actor)
            else:
                self._disabled_actors.add(actor)
            return token, path

    def provision_static(self, actor: str, token: str, scopes: list[str]) -> Path:
        """Install a caller-created token after an authenticated handoff."""
        if not token:
            raise ValidationError("credential cannot be empty")
        actor = self._actor(actor)
        with self._lock:
            path = self._publish(actor, token, {"actor": actor, "scopes": sorted(set(scopes))})
            self._disabled_actors.discard(actor)
            return path

    def actor_metadata(self, actor: str) -> dict | None:
        actor = self._actor(actor)
        with self._lock:
            try:
                return self._read_actor(actor)[1]
            except ValidationError:
                return None

    def disable_actor(self, actor: str) -> None:
        with self._lock:
            self._disabled_actors.add(self._actor(actor))

    def enable_actor(self, actor: str) -> None:
        actor = self._actor(actor)
        with self._lock:
            self._read_actor(actor)
            self._disabled_actors.discard(actor)

    def revoke(self, actor: str) -> None:
        actor = self._actor(actor)
        with self._lock:
            self._disabled_actors.add(actor)
            token_path, metadata_path, commit_path = self._paths(actor)
            commit_path.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            token_path.unlink(missing_ok=True)

    def load(self, token: str):
        if not token:
            raise AuthorizationError("bearer credential required")
        with self._lock:
            for token_path in self.root.glob("*.token"):
                actor = token_path.stem
                if actor in self._disabled_actors:
                    continue
                try:
                    expected, metadata = self._read_actor(actor)
                except ValidationError:
                    continue
                if secrets.compare_digest(expected, token):
                    return metadata
        raise AuthorizationError("invalid bearer credential")

    def require(self, token: str, scope: str):
        identity = self.load(token)
        if scope not in identity.get("scopes", []) and "admin" not in identity.get("scopes", []):
            raise AuthorizationError("credential lacks required scope", details={"scope": scope})
        return identity
