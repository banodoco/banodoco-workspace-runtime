from __future__ import annotations

import secrets
from pathlib import Path

from .errors import AuthorizationError, ValidationError


class CredentialStore:
    """Owner-only bearer credentials with explicit actor scopes."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)

    def provision(self, actor: str, scopes: list[str], *, metadata: dict | None = None) -> tuple[str, Path]:
        if not actor or "/" in actor or ".." in actor:
            raise ValidationError("invalid actor")
        token = secrets.token_urlsafe(32)
        path = self.root / f"{actor}.token"
        path.write_text(token, encoding="utf-8")
        path.chmod(0o600)
        value = {"actor": actor, "scopes": sorted(set(scopes))}
        if metadata:
            value.update(metadata)
        (self.root / f"{actor}.json").write_text(__import__("json").dumps(value), encoding="utf-8")
        (self.root / f"{actor}.json").chmod(0o600)
        return token, path

    def provision_static(self, actor: str, token: str, scopes: list[str]) -> Path:
        """Install a caller-created token after an authenticated handoff."""
        if not token:
            raise ValidationError("credential cannot be empty")
        if not actor or "/" in actor or ".." in actor:
            raise ValidationError("invalid actor")
        path = self.root / f"{actor}.token"
        path.write_text(token, encoding="utf-8")
        path.chmod(0o600)
        metadata = self.root / f"{actor}.json"
        metadata.write_text(__import__("json").dumps({"actor": actor, "scopes": sorted(set(scopes))}), encoding="utf-8")
        metadata.chmod(0o600)
        return path

    def load(self, token: str):
        if not token:
            raise AuthorizationError("bearer credential required")
        for token_path in self.root.glob("*.token"):
            try:
                expected = token_path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if secrets.compare_digest(expected, token):
                import json
                metadata_path = token_path.with_suffix(".json")
                metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {"actor": token_path.stem, "scopes": []}
                return metadata
        raise AuthorizationError("invalid bearer credential")

    def require(self, token: str, scope: str):
        identity = self.load(token)
        if scope not in identity.get("scopes", []) and "admin" not in identity.get("scopes", []):
            raise AuthorizationError("credential lacks required scope", details={"scope": scope})
        return identity
