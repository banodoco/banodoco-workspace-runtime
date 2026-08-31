"""Neutral-runtime half of the local Stage 1 release identity boundary.

The runtime may observe a component checkout and produce/retrieve identity
receipts, but it is intentionally not a publisher.  This module mirrors the
small API used by the Astrid product checkout while keeping the neutral
runtime independent of Astrid imports and storage.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import unicodedata
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "release-identity-v1"
NONE = "NONE"


class ReleaseIdentityError(ValueError):
    pass


def _norm(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_norm(item) for item in value]
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", str(k)): _norm(v) for k, v in value.items()}
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(_norm(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def framed_hash(label: str, value: Any) -> str:
    left = unicodedata.normalize("NFC", label).encode()
    right = canonical_bytes(value)
    return hashlib.sha256(len(left).to_bytes(8, "big") + left + len(right).to_bytes(8, "big") + right).hexdigest()


def _git(root: Path, *args: str, optional: bool = False) -> str:
    try:
        result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True, timeout=30)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        if optional:
            return ""
        raise ReleaseIdentityError(f"git observation failed: {' '.join(args)}") from exc
    return result.stdout.rstrip("\n")


def _names(root: Path) -> list[str]:
    result = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "--name-only", "-z", "HEAD"], capture_output=True, check=True, timeout=30)
    return [item.decode() for item in result.stdout.split(b"\0") if item]


def _digest_inventory(root: Path, paths: Sequence[str]) -> str:
    rows = []
    for path in sorted(set(paths)):
        oid = _git(root, "rev-parse", f"HEAD:{path}", optional=True)
        if oid:
            rows.append({"path": path, "oid": oid})
    return framed_hash("banodoco.release-inventory.v1", rows)


def resolve_component(component_id: str, path: str | os.PathLike[str], *, source_ref: str | None = None, epochs: Mapping[str, Any] | None = None) -> dict[str, Any]:
    root = Path(path).expanduser().resolve()
    if not component_id or not root.is_dir() or not (root / ".git").exists():
        raise ReleaseIdentityError(f"invalid Git component: {component_id or root}")
    names = _names(root)
    head = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    contract = [p for p in names if any(x in p.lower() for x in ("contract/", "schema", "openapi", "conformance/"))]
    generated = [p for p in names if any(x in p.lower() for x in ("generated", "/client", "client/"))]
    capability = [p for p in names if any(x in p.lower() for x in ("capabil", "manifest", "pack/"))]
    dependency = [p for p in names if any(x in p.lower() for x in ("lock", "requirements", "pyproject.toml", "package.json"))]
    epoch_values = {"contract_epoch": NONE, "runtime_epoch": NONE, "source_epoch": head, "migration_epoch": NONE, "activation_epoch": NONE, "release_epoch": NONE}
    epoch_values.update(_norm(dict(epochs or {})))
    return {
        "component_id": component_id,
        "repository_identity": _git(root, "config", "--get", "remote.origin.url", optional=True) or root.name,
        "source_ref": source_ref or _git(root, "symbolic-ref", "--short", "-q", "HEAD", optional=True) or head,
        "base_oid": head, "base_tree_oid": tree, "integrated_oid": head, "integrated_tree_oid": tree,
        "subtree_sha256": framed_hash("banodoco.component-subtree.v1", [{"path": p, "oid": _git(root, "rev-parse", f"HEAD:{p}")} for p in names]),
        "contract_sha256": _digest_inventory(root, contract),
        "generator_ids": generated,
        "dependency_lock_digests": [{"path": p, "sha256": hashlib.sha256(_git(root, "show", f"HEAD:{p}").encode()).hexdigest()} for p in dependency],
        "fixture_digests": [], "tool_ids": ["TOOL-GIT"],
        "generator_observation_rows": [{"path": p, "sha256": _git(root, "rev-parse", f"HEAD:{p}")} for p in generated],
        "provenance_input_bindings": [], "producer_id": "CMD-IDENTITY:pre-live-root", "epoch_profile_id": "EP-CRSM", "freshness_policy_id": "CURRENT-CLEAN-HEAD",
        "tree_sha256": tree, "schema_sha256": _digest_inventory(root, contract), "capability_ledger_sha256": _digest_inventory(root, capability),
        "dirty": bool(status), "dirty_paths": [line[3:] for line in status.splitlines() if line], "epochs": epoch_values, "checkout": str(root),
    }


def _clean(rows: Sequence[Mapping[str, Any]]) -> None:
    bad = [(row.get("component_id"), row.get("dirty_paths", [])) for row in rows if row.get("dirty")]
    if bad:
        raise ReleaseIdentityError(f"candidate component has uncommitted changes: {bad}")


def _receipt_hash(receipt: Mapping[str, Any]) -> str:
    return framed_hash("banodoco.release-receipt.v1", {k: v for k, v in receipt.items() if k not in {"receipt_sha256", "identity"}})


def create_pre_live_identity(components: Mapping[str, str | os.PathLike[str]], *, metadata: Mapping[str, Any] | None = None, output: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    rows = sorted((resolve_component(k, v) for k, v in components.items()), key=lambda row: row["component_id"])
    _clean(rows)
    evidence = [{"path": f"components/{row['component_id']}", "sha256": row["subtree_sha256"], "producer_id": "CMD-IDENTITY:pre-live-root", "token_ids": [row["component_id"]], "epochs": row["epochs"], "media_type": "application/json"} for row in rows]
    identity = framed_hash("banodoco.pre-live-evidence-root.v1", evidence)
    receipt = {"schema_version": SCHEMA_VERSION, "kind": "pre-live-root", "operation_id": "CMD-IDENTITY:pre-live-root", "identity": identity, "epochs": dict((metadata or {}).get("epochs", {})), "seed_ids": ["EXECUTION-COMPONENTS", "CONTRACT-ID", "RUNTIME-BUILD-ID", "SOURCE-MANIFEST-ID", "MIGRATION-MANIFEST-ID", "SELECTED-REALM-ID", "TRUSTED-DISPOSITION-SHA256"], "evidence_rows": evidence, "component_rows": rows, "metadata": _norm(dict(metadata or {}))}
    receipt["receipt_sha256"] = _receipt_hash(receipt)
    _write(receipt, output)
    return receipt


def create_candidate_core_identity(pre_live: Mapping[str, Any] | str | os.PathLike[str], components: Mapping[str, str | os.PathLike[str]], *, metadata: Mapping[str, Any] | None = None, output: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    prior = load_receipt(pre_live) if isinstance(pre_live, (str, os.PathLike)) else dict(pre_live)
    verify_receipt(prior)
    if prior.get("kind") != "pre-live-root":
        raise ReleaseIdentityError("candidate core requires a pre-live-root receipt")
    rows = sorted((resolve_component(k, v) for k, v in components.items()), key=lambda row: row["component_id"])
    _clean(rows)
    previous = {row["component_id"]: row for row in prior.get("component_rows", [])}
    for row in rows:
        if row["component_id"] not in previous or previous[row["component_id"]].get("integrated_oid") != row["integrated_oid"] or previous[row["component_id"]].get("integrated_tree_oid") != row["integrated_tree_oid"]:
            raise ReleaseIdentityError(f"candidate component changed after pre-live capture: {row['component_id']}")
    meta = dict(metadata or {})
    core = {"schema_version": 1, "governance_binding": meta.get("governance_binding", "LOCAL-STAGE1-RELEASE"), "component_manifest_sha256": framed_hash("banodoco.component-manifest.v1", rows), "contract_id": meta.get("contract_id", framed_hash("banodoco.contract.v1", [r["contract_sha256"] for r in rows])), "runtime_build_id": meta.get("runtime_build_id", framed_hash("banodoco.runtime-build.v1", [r["integrated_oid"] for r in rows])), "source_manifest_id": meta.get("source_manifest_id", framed_hash("banodoco.source-manifest.v1", [r["subtree_sha256"] for r in rows])), "migration_manifest_id": meta.get("migration_manifest_id", NONE), "selected_realm_id": meta.get("selected_realm_id", NONE), "trusted_disposition_sha256": meta.get("trusted_disposition_sha256", NONE), "pre_live_evidence_root": prior["identity"], "contract_epoch": meta.get("contract_epoch", NONE), "runtime_epoch": meta.get("runtime_epoch", NONE), "source_epoch": meta.get("source_epoch", NONE), "migration_epoch": meta.get("migration_epoch", NONE), "activation_epoch": meta.get("activation_epoch", NONE), "release_epoch": NONE, "component_rows": rows}
    receipt = {"schema_version": SCHEMA_VERSION, "kind": "candidate-core", "operation_id": "CMD-IDENTITY:candidate-core", "identity": framed_hash("banodoco.candidate-core.v1", core), "candidate_core": core, "pre_live_root": prior["identity"], "metadata": _norm(meta)}
    receipt["receipt_sha256"] = _receipt_hash(receipt)
    _write(receipt, output)
    return receipt


def _write(receipt: Mapping[str, Any], output: str | os.PathLike[str] | None) -> None:
    if output:
        target = Path(output).expanduser().resolve(); target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(canonical_bytes(receipt) + b"\n")


def verify_receipt(receipt: Mapping[str, Any]) -> str:
    if receipt.get("schema_version") != SCHEMA_VERSION or receipt.get("receipt_sha256") != _receipt_hash(receipt):
        raise ReleaseIdentityError("release receipt digest or schema mismatch")
    if receipt.get("kind") == "pre-live-root":
        expected = framed_hash("banodoco.pre-live-evidence-root.v1", receipt.get("evidence_rows"))
    elif receipt.get("kind") == "candidate-core":
        expected = framed_hash("banodoco.candidate-core.v1", receipt.get("candidate_core"))
    else:
        raise ReleaseIdentityError("unknown release receipt kind")
    if expected != receipt.get("identity"):
        raise ReleaseIdentityError("release identity mismatch")
    return expected


def load_receipt(path: str | os.PathLike[str]) -> dict[str, Any]:
    try:
        receipt = json.loads(Path(path).expanduser().resolve().read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseIdentityError("cannot retrieve release receipt") from exc
    if not isinstance(receipt, dict):
        raise ReleaseIdentityError("release receipt must be an object")
    verify_receipt(receipt); return receipt


def bind_remote_targets(receipt: Mapping[str, Any], targets: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    verify_receipt(receipt)
    result = copy.deepcopy(dict(receipt)); seen = set(); rows = []
    for target in targets:
        item = dict(target); target_id = item.get("remote_target_id")
        if not isinstance(target_id, str) or not target_id or target_id in seen: raise ReleaseIdentityError("remote target ids must be unique")
        seen.add(target_id); rows.append(_norm(item))
    result["remote_targets"] = sorted(rows, key=lambda row: row["remote_target_id"]); result["remote_target_registry_sha256"] = framed_hash("banodoco.remote-target-registry.v1", result["remote_targets"]); result["receipt_sha256"] = _receipt_hash(result); return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="banodoco-runtime-identity"); sub = parser.add_subparsers(dest="op", required=True)
    pre = sub.add_parser("pre-live"); pre.add_argument("--component", action="append", default=[]); pre.add_argument("--output")
    core = sub.add_parser("candidate-core"); core.add_argument("--pre-live", required=True); core.add_argument("--component", action="append", default=[]); core.add_argument("--output")
    check = sub.add_parser("verify"); check.add_argument("receipt")
    args = parser.parse_args(argv)
    try:
        components = {}
        for value in getattr(args, "component", []):
            if "=" not in value: raise ReleaseIdentityError("--component must use COMPONENT_ID=CHECKOUT")
            key, path = value.split("=", 1); components[key] = path
        if args.op == "pre-live": result = create_pre_live_identity(components, output=args.output)
        elif args.op == "candidate-core": result = create_candidate_core_identity(args.pre_live, components, output=args.output)
        else: result = {"ok": True, "identity": load_receipt(args.receipt)["identity"]}
        print(json.dumps(result, sort_keys=True, indent=2)); return 0
    except ReleaseIdentityError as exc:
        print(json.dumps({"ok": False, "error": str(exc)})); return 1


if __name__ == "__main__":
    raise SystemExit(main())
