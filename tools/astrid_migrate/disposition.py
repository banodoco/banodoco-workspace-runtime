"""Authenticated B10.2 source dispositions.

The migration driver deliberately does not infer ownership.  This module is
the small boundary between an owner-attested source decision and migration:
the decision is bound to the frozen source manifest and scope, authenticated
with the retained operator HMAC key, and consumed exactly once.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any, Mapping, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - the supported POSIX runtimes use fcntl
    fcntl = None

from .boundary import AuthorizationError, ConflictError, ValidationError, atomic_json_write, canonical_json, now

from .migrator import MigrationConfig, MigrationError, Migrator

SCHEMA_VERSION = "trusted-disposition-v1"
DEFAULT_FACT_SCOPE = ("media", "owner-data")
DEFAULT_FIELD_SCOPE = ("all",)
DEFAULT_SOURCE_PAIR_SCOPE = ("legacy-clone -> neutral-runtime",)
EPOCH_KEYS = frozenset(("source_epoch", "migration_epoch"))
DECISIONS = frozenset(("preserve", "exclude"))
FIELDS = (
    "schema_version", "disposition_id", "owner_identity", "source_owner_binding",
    "trust_root_or_verifier_sha256", "attestation_method", "source_manifest_sha256",
    "fact_scope", "field_scope", "source_pair_scope", "decision",
    "basis_artifact_sha256", "issued_at", "expires_at", "nonce", "revoked_at",
    "epochs", "signature_or_attestation_sha256",
)


def _key_id(key: bytes) -> str:
    return hashlib.sha256(bytes(key)).hexdigest()


def _payload(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in FIELDS if key != "signature_or_attestation_sha256"}


def _signature(value: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(bytes(key), canonical_json(_payload(value)).encode("utf-8"), hashlib.sha256).hexdigest()


def _timestamp(value: Any, label: str, *, allow_none: bool = False) -> None:
    if allow_none and value == "NONE":
        return
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be an ISO-8601 timestamp or NONE")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{label} must include a timezone")


def _scope(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value) or value != sorted(set(value)):
        raise ValidationError(f"trusted disposition {label} must be a sorted unique string list")
    return value


def _epochs(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != EPOCH_KEYS or any(not isinstance(item, str) or not item for item in value.values()):
        raise ValidationError("trusted disposition epochs must contain exactly source_epoch and migration_epoch strings")
    return dict(value)


def issue_trusted_disposition(
    *, owner_identity: str, source_manifest_sha256: str,
    fact_scope: Sequence[str], field_scope: Sequence[str], source_pair_scope: Sequence[str],
    decision: str, basis_artifact_sha256: str, epochs: Mapping[str, Any],
    signing_key: bytes, issuer_identity: str, disposition_id: str | None = None,
    expires_at: str = "NONE", nonce: str | None = None,
) -> dict[str, Any]:
    """Create an owner-bound HMAC attestation.

    The issuer is intentionally separate from the source owner.  A caller
    trying to self-issue is rejected before any artifact can be sealed.
    """
    if not owner_identity or not issuer_identity or issuer_identity == owner_identity:
        raise AuthorizationError("trusted disposition requires an independent verifier issuer")
    if len(bytes(signing_key)) < 32:
        raise AuthorizationError("trusted disposition signing key is too short")
    for value, label in ((source_manifest_sha256, "source manifest"), (basis_artifact_sha256, "basis artifact")):
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValidationError(f"{label} digest must be a SHA-256 hex digest")
    if decision not in DECISIONS:
        raise ValidationError("trusted disposition decision must be preserve or exclude")
    validated_epochs = _epochs(epochs)
    disposition = {
        "schema_version": SCHEMA_VERSION,
        "disposition_id": disposition_id or f"DISPOSITION-B10:{secrets.token_hex(12)}",
        "owner_identity": owner_identity,
        "source_owner_binding": {"source_owner_id": owner_identity, "source_manifest_sha256": source_manifest_sha256},
        "trust_root_or_verifier_sha256": _key_id(signing_key),
        "attestation_method": "hmac-sha256",
        "source_manifest_sha256": source_manifest_sha256,
        "fact_scope": sorted(set(str(item) for item in fact_scope)),
        "field_scope": sorted(set(str(item) for item in field_scope)),
        "source_pair_scope": sorted(set(str(item) for item in source_pair_scope)),
        "decision": decision,
        "basis_artifact_sha256": basis_artifact_sha256,
        "issued_at": now(),
        "expires_at": expires_at,
        "nonce": nonce or secrets.token_urlsafe(32),
        "revoked_at": "NONE",
        "epochs": validated_epochs,
        "signature_or_attestation_sha256": "",
    }
    disposition["signature_or_attestation_sha256"] = _signature(disposition, signing_key)
    return disposition


def verify_trusted_disposition(
    disposition: Mapping[str, Any], *, verification_key: bytes,
    expected_owner_identity: str, expected_source_manifest_sha256: str,
    expected_fact_scope: Sequence[str] = DEFAULT_FACT_SCOPE,
    expected_field_scope: Sequence[str] = DEFAULT_FIELD_SCOPE,
    expected_source_pair_scope: Sequence[str] = DEFAULT_SOURCE_PAIR_SCOPE,
    now_value: datetime | None = None,
) -> dict[str, Any]:
    """Verify schema, source/owner/scope binding, freshness, and HMAC."""
    if set(disposition) != set(FIELDS):
        raise ValidationError("trusted disposition schema fields are not exact")
    value = dict(disposition)
    if value["schema_version"] != SCHEMA_VERSION or value["attestation_method"] != "hmac-sha256":
        raise ValidationError("unsupported trusted disposition schema or attestation method")
    if not isinstance(value["owner_identity"], str) or value["owner_identity"] != expected_owner_identity:
        raise AuthorizationError("trusted disposition owner identity does not match SOURCE-OWNER-ID")
    binding = value["source_owner_binding"]
    if (
        not isinstance(binding, Mapping)
        or set(binding) != {"source_owner_id", "source_manifest_sha256"}
        or not isinstance(binding.get("source_owner_id"), str)
        or not isinstance(binding.get("source_manifest_sha256"), str)
        or binding.get("source_owner_id") != value["owner_identity"]
        or binding.get("source_manifest_sha256") != value["source_manifest_sha256"]
    ):
        raise AuthorizationError("trusted disposition SOURCE-OWNER-ID binding is invalid")
    if value["source_manifest_sha256"] != expected_source_manifest_sha256:
        raise ConflictError("trusted disposition source manifest does not match frozen source")
    if value["trust_root_or_verifier_sha256"] != _key_id(verification_key):
        raise AuthorizationError("trusted disposition verifier trust root is unknown")
    if not hmac.compare_digest(str(value["signature_or_attestation_sha256"]), _signature(value, verification_key)):
        raise ConflictError("trusted disposition attestation is invalid or tampered")
    if not isinstance(value["nonce"], str) or not value["nonce"]:
        raise ValidationError("trusted disposition nonce is required")
    _timestamp(value["issued_at"], "issued_at")
    _timestamp(value["expires_at"], "expires_at", allow_none=True)
    _timestamp(value["revoked_at"], "revoked_at", allow_none=True)
    if value["revoked_at"] != "NONE":
        raise AuthorizationError("trusted disposition has been revoked")
    clock = now_value or datetime.now(timezone.utc)
    issued = datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00"))
    if issued > clock:
        raise ConflictError("trusted disposition is not yet valid")
    if value["expires_at"] != "NONE" and datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")) <= clock:
        raise AuthorizationError("trusted disposition has expired")
    for key in ("fact_scope", "field_scope", "source_pair_scope"):
        _scope(value[key], key)
    if value["decision"] not in DECISIONS:
        raise ValidationError("trusted disposition decision must be preserve or exclude")
    _epochs(value["epochs"])
    for key, expected in (("fact_scope", expected_fact_scope), ("field_scope", expected_field_scope), ("source_pair_scope", expected_source_pair_scope)):
        if value[key] != sorted(set(str(item) for item in expected)):
            raise ConflictError(f"trusted disposition {key} does not match requested scope")
    return value


class DispositionNonceLedger:
    """Small durable replay ledger for one-shot disposition attestations."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": 1, "consumed": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConflictError("trusted disposition nonce ledger is unreadable") from exc
        if value.get("schema_version") != 1 or not isinstance(value.get("consumed"), dict):
            raise ConflictError("trusted disposition nonce ledger schema is invalid")
        return value

    @contextmanager
    def _exclusive_lock(self):
        """Serialize the read/check/write transaction across processes."""
        if fcntl is None:
            raise ConflictError("trusted disposition nonce ledger requires a file-locking runtime")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        with lock_path.open("a+") as stream:
            try:
                os.fchmod(stream.fileno(), 0o600)
            except OSError:
                pass
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def consume(self, disposition: Mapping[str, Any]) -> None:
        with self._exclusive_lock():
            value = self._read()
            nonce = str(disposition["nonce"])
            prior = value["consumed"].get(nonce)
            binding = {"disposition_id": disposition["disposition_id"], "signature": disposition["signature_or_attestation_sha256"]}
            if prior is not None:
                if prior != binding:
                    raise ConflictError("trusted disposition nonce replay conflicts with a different attestation")
                raise ConflictError("trusted disposition nonce has already been consumed")
            value["consumed"][nonce] = binding
            atomic_json_write(self.path, value)


def resolve_trusted_dispositions(
    dispositions: Sequence[Mapping[str, Any]], *, verification_key: bytes,
    expected_owner_identity: str, expected_source_manifest_sha256: str,
    expected_fact_scope: Sequence[str] = DEFAULT_FACT_SCOPE,
    expected_field_scope: Sequence[str] = DEFAULT_FIELD_SCOPE,
    expected_source_pair_scope: Sequence[str] = DEFAULT_SOURCE_PAIR_SCOPE,
    nonce_ledger: DispositionNonceLedger | None = None,
) -> dict[str, Any]:
    """Verify and resolve a set; contradictory decisions stop migration."""
    if not dispositions:
        raise ValidationError("at least one trusted disposition is required")
    verified = [verify_trusted_disposition(item, verification_key=verification_key, expected_owner_identity=expected_owner_identity, expected_source_manifest_sha256=expected_source_manifest_sha256, expected_fact_scope=expected_fact_scope, expected_field_scope=expected_field_scope, expected_source_pair_scope=expected_source_pair_scope) for item in dispositions]
    keys = {(tuple(item["fact_scope"]), tuple(item["field_scope"]), tuple(item["source_pair_scope"])) for item in verified}
    decisions = {item["decision"] for item in verified}
    if len(keys) != 1 or len(decisions) != 1:
        raise ConflictError("conflicting trusted dispositions preserve both sides and stop migration")
    if nonce_ledger is not None:
        for item in verified:
            nonce_ledger.consume(item)
    return {"decision": verified[0]["decision"], "disposition_ids": [item["disposition_id"] for item in verified], "trusted_disposition_sha256": hashlib.sha256(canonical_json(verified).encode("utf-8")).hexdigest()}


def seal_trusted_disposition(path: str | Path, disposition: Mapping[str, Any], *, verification_key: bytes, expected_owner_identity: str, expected_source_manifest_sha256: str) -> str:
    value = verify_trusted_disposition(disposition, verification_key=verification_key, expected_owner_identity=expected_owner_identity, expected_source_manifest_sha256=expected_source_manifest_sha256)
    atomic_json_write(Path(path).expanduser().resolve(), value)
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def migrate_with_trusted_disposition(config: MigrationConfig, client: Any, *, dispositions: Sequence[Mapping[str, Any]], verification_key: bytes, source_owner_id: str, nonce_ledger: DispositionNonceLedger) -> dict[str, Any]:
    """Authorize a migration from a frozen inventory, then run the driver."""
    inventory = Migrator(config, client).inventory()
    resolved = resolve_trusted_dispositions(dispositions, verification_key=verification_key, expected_owner_identity=source_owner_id, expected_source_manifest_sha256=inventory["source_manifest_sha256"], nonce_ledger=nonce_ledger)
    migration_config = config.__class__(**{**config.__dict__, "expected_source_manifest_sha256": inventory["source_manifest_sha256"], "expected_source_facts_sha256": inventory["source_facts_sha256"], "include_owner_data": resolved["decision"] == "preserve"})
    report = Migrator(migration_config, client).migrate()
    report["trusted_disposition"] = resolved
    return report
