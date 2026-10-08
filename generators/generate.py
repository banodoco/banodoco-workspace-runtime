#!/usr/bin/env python3
"""Render checked-in contract metadata and the Python client from canonical inputs.

The release/conformance client generators consume the same component manifest;
this small repository-local command keeps the package artifacts bound to that
manifest as well.  The Python client is rendered from the tracked template;
``--check`` remains a read-only stale-artifact check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contract" / "manifest.json"
COMPONENT_MANIFEST = ROOT / "contract" / "component-manifest.json"
PYTHON_CLIENT_TEMPLATE = ROOT / "generators" / "python_client_template.py"
PYTHON_CLIENT_OUTPUT = ROOT / "packages" / "python" / "banodoco_workspace_client" / "generated.py"
TYPESCRIPT_CLIENT_OUTPUT = ROOT / "packages" / "typescript" / "src" / "generated.ts"


def _regular(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"{label} must be a regular file")
    return path.read_bytes()


def _component(path: Path = COMPONENT_MANIFEST) -> tuple[bytes, Mapping[str, Any]]:
    raw = _regular(path, "component manifest")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("component manifest must be UTF-8 JSON") from exc
    canonical = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if raw != canonical:
        raise SystemExit("component manifest must use canonical JSON bytes")
    if value.get("schema_version") != 1 or value.get("manifest_id") != "GENERATOR-CONFORMANCE-ID":
        raise SystemExit("component manifest identity is invalid")
    return raw, value


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def contract_digest(manifest_path: Path = MANIFEST) -> str:
    manifest = json.loads(_regular(manifest_path, "schema manifest"))
    paths = [ROOT / "contract" / manifest["openapi"], *(ROOT / "contract" / p for p in manifest["schemas"])]
    h = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix().encode()
        data = _regular(path, "contract input")
        h.update(len(relative).to_bytes(4, "big")); h.update(relative)
        h.update(len(data).to_bytes(8, "big")); h.update(data)
    return "sha256:" + h.hexdigest()


def operation_index(manifest_path: Path = MANIFEST) -> list[str]:
    manifest = json.loads(_regular(manifest_path, "schema manifest"))
    text = (ROOT / "contract" / manifest["openapi"]).read_text(encoding="utf-8")
    return [line.split(":", 1)[1].strip() for line in text.splitlines() if re.match(r"^\s+operationId:", line)]


def render_python_client(manifest_path: Path = MANIFEST) -> str:
    """Render the checked-in Python client from its tracked template.

    The template is deliberately separate from the output: ``--check`` must
    detect a mutated generated client rather than merely re-reading it.  The
    contract digest and operation projection are embedded so the artifact is
    also bound to the canonical OpenAPI/schema inputs.
    """
    template = _regular(PYTHON_CLIENT_TEMPLATE, "Python client template").decode("utf-8")
    if "__SCHEMA_DIGEST__" not in template or "__OPERATIONS__" not in template:
        raise SystemExit("Python client template is missing generator placeholders")
    operations = operation_index(manifest_path)
    if not operations or len(operations) != len(set(operations)):
        raise SystemExit("contract operation projection must be non-empty and unique")
    rendered = template.replace("Authoritative Python client template; rendered by generators/generate.py.", "Generated from contract/openapi/workspace-v1.yaml; do not edit by hand.")
    rendered = rendered.replace("__SCHEMA_DIGEST__", contract_digest(manifest_path))
    rendered = rendered.replace("__OPERATIONS__", repr(tuple(operations)))
    return rendered


def render_typescript_client() -> str:
    """Render the source-frame thumbnail operations into the typed TS client."""
    source = _regular(TYPESCRIPT_CLIENT_OUTPUT, "TypeScript client").decode("utf-8")
    child_authority_types = (
        'export interface ChildAuthorityChild { child_id: string; capability_id: string; capability_digest: string }\n'
        'export interface DerivedInputDescriptor { name: string; output_port: string; filename: string; object_id: string; size: number; media_type: string }\n'
        'export interface ChildAuthorityRequest { lease_id: string; fence: number; runtime_epoch: number; child?: ChildAuthorityChild; derived_inputs?: DerivedInputDescriptor[] }'
    )
    if "export interface ChildAuthorityRequest " not in source:
        anchor = "export interface ObjectLocation"
        if anchor not in source:
            raise SystemExit("TypeScript client is missing the child-authority type insertion point")
        source = source.replace(anchor, child_authority_types + "\n" + anchor, 1)
    old_child_authority_method = '  async issueChildAuthority(attemptId: string, body: { lease_id: string; fence: number; runtime_epoch: number }): Promise<Record<string, unknown>>'
    new_child_authority_method = '  async issueChildAuthority(attemptId: string, body: ChildAuthorityRequest): Promise<Record<string, unknown>>'
    if new_child_authority_method not in source:
        if old_child_authority_method not in source:
            raise SystemExit("TypeScript child-authority client projection is partially present")
        source = source.replace(old_child_authority_method, new_child_authority_method, 1)
    snapshot_type = 'export interface RecoverableSnapshotRequest { lease_id: string; fence: number; runtime_epoch: number; revision: number; output: DerivedInputDescriptor }'
    if "export interface RecoverableSnapshotRequest " not in source:
        source = source.replace("export interface ObjectLocation", snapshot_type + "\nexport interface ObjectLocation", 1)
    snapshot_method = '  async publishRecoverableSnapshot(attemptId: string, body: RecoverableSnapshotRequest, idempotencyKey: string): Promise<MutationResult<ManagedOutput>> { return this.mutation<ManagedOutput>((await this.request("POST", `/v1/attempts/${encodeURIComponent(attemptId)}/recoverable-snapshots`, new TextEncoder().encode(JSON.stringify(body)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey })).body) }'
    if "  async publishRecoverableSnapshot(" not in source:
        source = source.replace("  async issueChildAuthority(", snapshot_method + "\n  async issueChildAuthority(", 1)
    source = source.replace(
        'export interface GenerationVariant { variant_id: string; generation_id: string; object_id?: string | null; variant_type: string; metadata: Record<string, unknown>; thumbnail?: { object_id: string; source_object_id: string; recipe_version: number } | null; viewed_at?: string | null; created_at: string }',
        'export interface ThumbnailDescriptor { object_id: string; source_object_id: string; recipe_version: number; selection?: { kind: "variant" | "source_frame"; source_time_seconds?: number } }\nexport interface GenerationVariant { variant_id: string; generation_id: string; object_id?: string | null; variant_type: string; metadata: Record<string, unknown>; thumbnail?: ThumbnailDescriptor | null; viewed_at?: string | null; created_at: string }',
        1,
    )
    get_method = '  async getSourceFrameThumbnail(projectId: string, sourceObjectId: string, sourceTimeSeconds: number, recipeVersion = 1): Promise<Record<string, unknown> | null> { const query = `source_object_id=${encodeURIComponent(sourceObjectId)}&source_time_seconds=${sourceTimeSeconds.toFixed(6)}&recipe_version=${recipeVersion}`; return this.json<{ thumbnail: Record<string, unknown> | null }>((await this.request("GET", `/v1/projects/${encodeURIComponent(projectId)}/thumbnails/source-frame?${query}`)).body).thumbnail }'
    ensure_method = '  async ensureSourceFrameThumbnail(projectId: string, thumbnail: Record<string, unknown>, idempotencyKey: string): Promise<MutationResult<Record<string, unknown>>> { return this.mutation<Record<string, unknown>>((await this.request("POST", `/v1/projects/${encodeURIComponent(projectId)}/thumbnails/source-frame`, new TextEncoder().encode(JSON.stringify(thumbnail)), { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey }, [200, 201])).body) }'
    markers = ("  async getSourceFrameThumbnail(", "  async ensureSourceFrameThumbnail(")
    present = tuple(marker in source for marker in markers)
    if all(present):
        return source
    if any(present):
        raise SystemExit("TypeScript source-frame thumbnail client projection is partially present")
    anchor = next((line for line in source.splitlines() if line.startswith("  async listMediaRelations(")), None)
    if anchor is None:
        raise SystemExit("TypeScript client is missing the listMediaRelations insertion point")
    return source.replace(anchor, anchor + "\n" + get_method + "\n" + ensure_method, 1)


def validate_typescript_client(manifest_path: Path = MANIFEST) -> None:
    """Fail closed when the typed product projection drifts from OpenAPI.

    The TypeScript client remains a typed repository source rather than a
    Python-template copy.  This check still binds every public method to the
    canonical operation projection and asserts the execution binding fields
    whose types cannot be inferred by the small metadata renderer.
    """
    source = _regular(TYPESCRIPT_CLIENT_OUTPUT, "TypeScript client").decode("utf-8")
    methods = set(re.findall(r"^  async (\w+)\(", source, re.MULTILINE))
    expected = set(operation_index(manifest_path)) | {"updateTimelineDocument"}
    if methods != expected:
        missing = sorted(expected - methods)
        extra = sorted(methods - expected)
        raise SystemExit(
            "TypeScript client operation projection drifted"
            + (f"; missing={missing}" if missing else "")
            + (f"; extra={extra}" if extra else "")
        )
    required_fragments = (
        "actual_target?: ExecutionTarget",
        "verification?: ExecutionBindingVerification",
        "executor_incarnation?: string",
        "run_id: string; project_id: string | null; lease_id: string",
        "lease_expires_at: string; runtime_epoch: number",
        "provider_state_unknown",
    )
    missing_fragments = [value for value in required_fragments if value not in source]
    if missing_fragments:
        raise SystemExit(
            "TypeScript execution contract projection is stale: "
            + ", ".join(missing_fragments)
        )


def render(manifest_path: Path = MANIFEST, component_path: Path = COMPONENT_MANIFEST) -> dict[str, str]:
    component_bytes, component = _component(component_path)
    digest = contract_digest(manifest_path)
    operations = operation_index(manifest_path)
    component_digest = _digest(component_bytes)
    py = ('"""Generated contract metadata; do not edit by hand."""\n\n'
          'PROTOCOL = "workspace.v1"\nCOMPONENT_MANIFEST_SHA256 = ' + repr(component_digest) +
          '\nSCHEMA_DIGEST = ' + repr(digest) + "\nOPERATIONS = " + repr(tuple(operations)) + "\n")
    ts = ('/** Generated contract metadata; do not edit by hand. */\n\n'
          'export const PROTOCOL = "workspace.v1" as const;\nexport const COMPONENT_MANIFEST_SHA256 = ' + json.dumps(component_digest) +
          ';\nexport const SCHEMA_DIGEST = ' + json.dumps(digest) + ";\nexport const OPERATIONS = " + json.dumps(operations) + " as const;\n")
    runtime = ('"""Generated contract metadata; do not edit by hand."""\n\n'
               'PROTOCOL = "workspace.v1"\nCOMPONENT_MANIFEST_SHA256 = ' + repr(component_digest) +
               '\nSCHEMA_DIGEST = ' + repr(digest) + "\nOPERATIONS = " + repr(tuple(operations)) + "\n")
    # Keep the three package metadata modules bound to the same manifest.  The
    # standalone Python/TypeScript client artifacts and fixture bundle are
    # emitted by their language-specific conformance generators.
    _ = component
    return {"packages/python/banodoco_workspace_client/contract_metadata.py": py, "packages/typescript/src/contract-metadata.ts": ts, "runtime_protocol/contract_metadata.py": runtime}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated metadata differs")
    parser.add_argument("--component-manifest", default=str(COMPONENT_MANIFEST))
    parser.add_argument("--python-output", default=str(PYTHON_CLIENT_OUTPUT), help="Python client output path (for isolated checks)")
    args = parser.parse_args()
    generated = render(component_path=Path(args.component_manifest).expanduser())
    generated["packages/python/banodoco_workspace_client/generated.py"] = render_python_client()
    generated["packages/typescript/src/generated.ts"] = render_typescript_client()
    for relative, content in generated.items():
        path = Path(args.python_output).expanduser().resolve() if relative == "packages/python/banodoco_workspace_client/generated.py" else ROOT / relative
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                print(f"stale generated file: {relative}")
                return 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(relative)
    validate_typescript_client()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
