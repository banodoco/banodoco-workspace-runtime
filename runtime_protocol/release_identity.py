"""Neutral-runtime release identity implementation (portable and closed)."""
from __future__ import annotations
import argparse, copy, hashlib, json, os, re, subprocess, unicodedata
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

SCHEMA_VERSION="release-identity-v1"; NONE="NONE"; CANDIDATE_COMPONENT_SCHEMA="candidate-component-row-v1"; PRELIVE_MANIFEST_SCHEMA="pre-live-manifest-v1"
CANDIDATE_COMPONENT_FIELDS=("component_id","repository_identity","source_ref","base_oid","base_tree_oid","integrated_oid","integrated_tree_oid","subtree_sha256","contract_sha256","generator_ids","dependency_lock_digests","fixture_digests","tool_ids","generator_observation_rows","provenance_input_bindings","producer_id","epoch_profile_id","freshness_policy_id")
CANDIDATE_CORE_FIELDS=("schema_version","governance_binding","component_manifest_sha256","contract_id","runtime_build_id","source_manifest_id","migration_manifest_id","selected_realm_id","trusted_disposition_sha256","pre_live_evidence_root","contract_epoch","runtime_epoch","source_epoch","migration_epoch","activation_epoch","release_epoch","component_rows")
REMOTE_TARGET_FIELDS=("remote_target_id","target_kind","component_id","local_repository_identity","repository_identity","canonical_url","destination_ref_or_prefix","expected_old_oid","reviewed_source_oid","identity_transition_sha256","repository_provision_receipt_rows")
PRELIVE_EXCLUDED_IDS=("PRELIVE-MANIFEST","RCPT-PRELIVE-MANIFEST","PRELIVE-ROOT","RCPT-IDENTITY-PRELIVE","CANDIDATE-CORE","RCPT-IDENTITY-CANDIDATE-CORE")
PRELIVE_SEED_SOURCE="CURRENT-PLAN CURRENT-GOAL NORTH-STAR CUSTODY PHASE0-BASELINE GOVERNANCE-AMENDMENT THROUGHPUT-POLICY VALIDATOR-ID ROADMAP-OVERALL ROADMAP-ASTRID-BETA ROADMAP-REIGH ROADMAP-HARDENING ROADMAP-VISION ROADMAP-README CONVERGENCE BUNDLE-MANIFEST EXECUTION-PACKETS EXECUTION-REQUIREMENTS EXECUTION-COVERAGE EXECUTION-VALIDATION-MATRIX EXECUTION-COMMANDS EXECUTION-INTEGRATIONS EXECUTION-COMPONENTS EXECUTION-SCHEMAS-MANIFEST EXECUTION-VECTORS-MANIFEST BUNDLE-B0 RCPT-B0-MATERIALIZE P(B0.1) P(B0.2) P(B0.3) G(K-B0) CONTRACT-ID RUNTIME-BUILD-ID SOURCE-MANIFEST-ID MIGRATION-MANIFEST-ID SELECTED-REALM-ID TRUSTED-DISPOSITION-SHA256 RCPT-REV-C1 RCPT-REV-C2 RCPT-REV-C3 RCPT-REV-C4 G(K-B10) P(B11.1) P(B11.2) REVIEWED-COMPONENTS-B11 REMOTE-TARGET-LOCATORS REMOTE-TARGET-SET".split()
PRELIVE_SEEDS=tuple(sorted(set(PRELIVE_SEED_SOURCE)))

class ReleaseIdentityError(ValueError): pass
def _nfc(v:Any)->Any:
    if isinstance(v,str): return unicodedata.normalize("NFC",v)
    if isinstance(v,list): return [_nfc(x) for x in v]
    if isinstance(v,dict): return {unicodedata.normalize("NFC",str(k)):_nfc(x) for k,x in v.items()}
    return v
def canonical_bytes(v:Any)->bytes: return json.dumps(_nfc(v),ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
def framed_hash(label:str,v:Any)->str:
    a,b=unicodedata.normalize("NFC",label).encode(),canonical_bytes(v); return hashlib.sha256(len(a).to_bytes(8,"big")+a+len(b).to_bytes(8,"big")+b).hexdigest()
def _git(root:Path,*args:str,text:bool=True,optional:bool=False)->str|bytes:
    try: r=subprocess.run(["git","-C",str(root),*args],capture_output=True,text=text,check=True,timeout=30)
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        if optional:return "" if text else b""
        raise ReleaseIdentityError(f"git observation failed: {' '.join(args)}") from e
    return r.stdout
def _gt(root:Path,*args:str,optional:bool=False)->str:return str(_git(root,*args,optional=optional)).rstrip("\n")
def _gb(root:Path,*args:str)->bytes:return bytes(_git(root,*args,text=False))
def _names(root:Path)->list[str]:return [x.decode() for x in _gb(root,"ls-tree","-r","--name-only","-z","HEAD").split(b"\0") if x]
def _repo(root:Path)->str:
    remote=_gt(root,"config","--get","remote.origin.url",optional=True)
    if not remote:return root.name
    m=re.search(r"(?:github\.com[:/])([^/ :]+/[^/]+?)(?:\.git)?$",remote); return m.group(1) if m else remote.removesuffix(".git")
def git_identity(path:str|os.PathLike[str])->dict[str,Any]:
    root=Path(path).expanduser().resolve(); gd=_gt(root,"rev-parse","--git-dir"); common=_gt(root,"rev-parse","--git-common-dir"); ref=_gt(root,"symbolic-ref","-q","--short","HEAD",optional=True); subs=[]
    for line in _gt(root,"submodule","status","--recursive",optional=True).splitlines():
        m=re.match(r"^[ +-]?([0-9a-f]{40,64})\s+([^ (]+)",line)
        if m:subs.append({"path":m.group(2),"oid":m.group(1)})
    return {"repository_identity":_repo(root),"head_oid":_gt(root,"rev-parse","HEAD"),"head_ref":ref or NONE,"detached":not bool(ref),"git_dir_kind":"worktree" if (root/".git").is_file() else "directory","git_dir_relative":os.path.relpath(gd,common) if gd and common else NONE,"common_dir_relative":".","submodules":sorted(subs,key=lambda x:x["path"])}
def _dirty(root:Path,exclude:Any=None)->list[str]:
    ex=None
    if exclude:
        try:ex=Path(exclude).expanduser().resolve().relative_to(root.resolve()).as_posix()
        except ValueError:pass
    out=[]
    for line in _gt(root,"status","--porcelain=v1","--untracked-files=all","--ignored=matching").splitlines():
        if not line:continue
        p=line[3:] if len(line)>=3 else line
        if not ex or p!=ex:out.append(p)
    return sorted(set(out))
def _inv(root:Path,paths:Iterable[str])->str:
    rows=[]
    for p in sorted(set(paths)):
        oid=_gt(root,"rev-parse",f"HEAD:{p}",optional=True)
        if oid:rows.append({"path":p,"oid":oid})
    return framed_hash("banodoco.release-inventory.v1",rows)
def _scope(paths:Sequence[str],needles:Sequence[str])->list[str]:return [p for p in paths if any(n in p.lower() for n in needles)]
def _shape(row:Mapping[str,Any])->dict[str,Any]:
    if set(row)!=set(CANDIDATE_COMPONENT_FIELDS):raise ReleaseIdentityError("candidate-component-row-v1 has unexpected or missing fields")
    return {k:_nfc(row[k]) for k in CANDIDATE_COMPONENT_FIELDS}
def resolve_component(component_id:str,path:str|os.PathLike[str],*,source_ref:str|None=None,epochs:Mapping[str,Any]|None=None,scope_paths:Sequence[str]|None=None)->dict[str,Any]:
    root=Path(path).expanduser().resolve()
    if not component_id or not root.is_dir() or not (root/".git").exists():raise ReleaseIdentityError(f"invalid Git component: {component_id or root}")
    names=_names(root); scope=sorted(set(scope_paths or names)); head=_gt(root,"rev-parse","HEAD"); tree=_gt(root,"rev-parse","HEAD^{tree}"); contract=_scope(names,("contract/","schema","openapi","conformance/")); generated=_scope(names,("generated","/client","client/")); deps=_scope(names,("lock","requirements","pyproject.toml","package.json")); fixtures=_scope(names,("fixture","fixtures")); _=epochs
    return _shape({"component_id":component_id,"repository_identity":_repo(root),"source_ref":source_ref or _gt(root,"symbolic-ref","--short","-q","HEAD",optional=True) or head,"base_oid":head,"base_tree_oid":tree,"integrated_oid":head,"integrated_tree_oid":tree,"subtree_sha256":framed_hash("banodoco.component-subtree.v1", [{"path":p,"oid":_gt(root,"rev-parse",f"HEAD:{p}")} for p in scope]),"contract_sha256":_inv(root,contract),"generator_ids":generated,"dependency_lock_digests":[{"path":p,"sha256":hashlib.sha256(_gb(root,"show",f"HEAD:{p}")).hexdigest()} for p in deps],"fixture_digests":[{"path":p,"sha256":hashlib.sha256(_gb(root,"show",f"HEAD:{p}")).hexdigest()} for p in fixtures],"tool_ids":["TOOL-GIT"],"generator_observation_rows":[],"provenance_input_bindings":[],"producer_id":"PROD-CMD-PACKET:B11.1","epoch_profile_id":"EP-CRSM","freshness_policy_id":"CURRENT-CLEAN-HEAD"})
def resolve_reviewed_components(components:Mapping[str,str|os.PathLike[str]],**kwargs:Any)->list[dict[str,Any]]:return sorted((resolve_component(k,v,**kwargs) for k,v in components.items()),key=lambda x:x["component_id"])
def _clean(components:Mapping[str,str|os.PathLike[str]],output:Any=None)->None:
    bad=[(k,_dirty(Path(v).expanduser().resolve(),output)) for k,v in components.items() if _dirty(Path(v).expanduser().resolve(),output)]
    if bad:raise ReleaseIdentityError(f"candidate component has uncommitted changes: {bad}")
def _transition(cid:str,local:str,canonical:str,url:str,ref:str)->str:return framed_hash("banodoco.local-to-canonical-repository.v1",[cid,local,canonical,url,ref])
def plan_component_registry()->list[dict[str,Any]]:
    rows=[("NEUTRAL-RUNTIME","banodoco-workspace-runtime-oracle","banodoco/banodoco-workspace-runtime","https://github.com/banodoco/banodoco-workspace-runtime.git"),("ASTRID-CLIENT","peteromallet/Astrid","peteromallet/Astrid","https://github.com/peteromallet/Astrid.git")]
    return [{"remote_target_id":f"REMOTE-TARGET:COMPONENT:{c}","target_kind":"component","component_id":c,"local_repository_identity":l,"repository_identity":r,"canonical_url":u,"destination_ref_or_prefix":"refs/heads/main","expected_old_oid":NONE,"reviewed_source_oid":NONE,"identity_transition_sha256":_transition(c,l,r,u,"refs/heads/main"),"repository_provision_receipt_rows":NONE} for c,l,r,u in rows]
PLAN_COMPONENT_REGISTRY=tuple(plan_component_registry())
def plan_publication_row()->dict[str,Any]:return {"remote_target_id":"REMOTE-TARGET:PUBLICATION","target_kind":"publication","component_id":NONE,"local_repository_identity":NONE,"repository_identity":"banodoco/banodoco-workspace-runtime","canonical_url":"https://github.com/banodoco/banodoco-workspace-runtime.git","destination_ref_or_prefix":"refs/tags/astrid-stage1-evidence/","expected_old_oid":NONE,"reviewed_source_oid":NONE,"identity_transition_sha256":NONE,"repository_provision_receipt_rows":NONE}
def component_registry_sha256(rows:Sequence[Mapping[str,Any]]|None=None)->str:return hashlib.sha256(canonical_bytes(list(rows if rows is not None else plan_component_registry()))).hexdigest()
def component_registry_sha256(rows:Sequence[Mapping[str,Any]]|None=None)->str:return hashlib.sha256(canonical_bytes(list(rows if rows is not None else plan_component_registry()))).hexdigest()
def _url(u:str)->None:
    p=urlparse(u)
    if p.scheme!="https" or p.netloc!="github.com" or p.username or p.password or p.query or p.fragment or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git",p.path):raise ReleaseIdentityError("canonical URL must be an absolute credential-free HTTPS GitHub URL")
def join_plan_remote_targets(rows:Sequence[Mapping[str,Any]],*,strict:bool=True)->list[dict[str,Any]]:
    source={r["component_id"]:_shape(r) for r in rows}; registry=plan_component_registry()
    if strict and set(source)!={r["component_id"] for r in registry}:raise ReleaseIdentityError("plan-owned component registry join is not total")
    out=[]
    for t in registry:
        s=source.get(t["component_id"])
        if not s or s["repository_identity"]!=t["local_repository_identity"]:raise ReleaseIdentityError("local repository identity does not match plan registry")
        _url(t["canonical_url"]); item=copy.deepcopy(t); item["reviewed_source_oid"]=s["integrated_oid"]; out.append(item)
    out.append(plan_publication_row()); return out
def build_prelive_manifest(seed_outputs:Mapping[str,Any]|None=None,*,metadata:Mapping[str,Any]|None=None)->dict[str,Any]:
    outputs=seed_outputs or {}; seeds=sorted(set(PRELIVE_SEED_SOURCE)); epochs=dict((metadata or {}).get("epochs",{"contract_epoch":NONE,"runtime_epoch":NONE,"source_epoch":NONE,"migration_epoch":NONE,"activation_epoch":NONE,"release_epoch":NONE})); evidence=[]
    for s in seeds:
        v=outputs.get(s,{"seed_id":s}); data=bytes(v) if isinstance(v,(bytes,bytearray)) else canonical_bytes(v); d=hashlib.sha256(data).hexdigest(); evidence.append({"path":f"evidence/sha256/{d[:2]}/{d}","sha256":d,"producer_id":"CMD-PRELIVE-MANIFEST","token_ids":[s],"epochs":_nfc(epochs),"media_type":"application/json"})
    evidence.sort(key=lambda x:(x["path"],x["sha256"],x["producer_id"])); m={"schema_version":PRELIVE_MANIFEST_SCHEMA,"governance_binding":"LOCAL-STAGE1-RELEASE","seed_ids":seeds,"evidence_rows":evidence,"excluded_ids":list(PRELIVE_EXCLUDED_IDS),"epochs":_nfc(epochs)}; m["manifest_sha256"]=framed_hash("banodoco.pre-live-manifest.v1",m); return m
def _rd(r:Mapping[str,Any])->str:return framed_hash("banodoco.release-receipt.v1",{k:v for k,v in r.items() if k not in {"receipt_sha256","identity"}})
def create_pre_live_identity(components:Mapping[str,str|os.PathLike[str]],*,metadata:Mapping[str,Any]|None=None,output:Any=None,seed_outputs:Mapping[str,Any]|None=None)->dict[str,Any]:
    _clean(components,output); rows=resolve_reviewed_components(components); meta=dict(metadata or {}); manifest=build_prelive_manifest(seed_outputs,metadata=meta); evidence=[]
    for r in rows:
        b=canonical_bytes(r); d=hashlib.sha256(b).hexdigest(); evidence.append({"path":f"evidence/sha256/{d[:2]}/{d}","sha256":d,"producer_id":"CMD-IDENTITY:pre-live-root","token_ids":[r["component_id"]],"epochs":meta.get("epochs",{}),"media_type":"application/json"})
    evidence.sort(key=lambda x:(x["path"],x["sha256"],x["producer_id"])); identity=framed_hash("banodoco.pre-live-evidence-root.v1",{"component_rows":rows,"evidence_rows":evidence,"manifest_sha256":manifest["manifest_sha256"]}); strict=set(r["component_id"] for r in rows)=={"ASTRID-CLIENT","NEUTRAL-RUNTIME"} and all(r["repository_identity"] in {"peteromallet/Astrid","banodoco-workspace-runtime-oracle"} for r in rows); rec={"schema_version":SCHEMA_VERSION,"kind":"pre-live-root","operation_id":"CMD-IDENTITY:pre-live-root","identity":identity,"pre_live_manifest":manifest,"evidence_rows":evidence,"component_rows":rows,"remote_target_locators":join_plan_remote_targets(rows) if strict else [],"metadata":_nfc(meta)}; rec["receipt_sha256"]=_rd(rec); _write(rec,output); return rec
def _sets(rows:Sequence[Mapping[str,Any]])->dict[str,Mapping[str,Any]]:
    out={}
    for r in rows:
        _shape(r); c=r["component_id"]
        if not isinstance(c,str) or c in out:raise ReleaseIdentityError("candidate component IDs must be unique")
        out[c]=r
    return out
def create_candidate_core_identity(pre_live:Mapping[str,Any]|str|os.PathLike[str],components:Mapping[str,str|os.PathLike[str]],*,metadata:Mapping[str,Any]|None=None,output:Any=None)->dict[str,Any]:
    prior=load_receipt(pre_live) if isinstance(pre_live,(str,os.PathLike)) else dict(pre_live); verify_receipt(prior)
    if prior.get("kind")!="pre-live-root":raise ReleaseIdentityError("candidate core requires a pre-live-root receipt")
    _clean(components,output); rows=resolve_reviewed_components(components); old,new=_sets(prior.get("component_rows",[])),_sets(rows)
    if set(old)!=set(new):raise ReleaseIdentityError("candidate component set is not a total bijection")
    for c in old:
        if canonical_bytes(old[c])!=canonical_bytes(new[c]):raise ReleaseIdentityError(f"candidate component field mismatch after pre-live capture: {c}")
    meta=dict(metadata or {}); core={"schema_version":1,"governance_binding":meta.get("governance_binding","LOCAL-STAGE1-RELEASE"),"component_manifest_sha256":framed_hash("banodoco.component-manifest.v1",rows),"contract_id":meta.get("contract_id",framed_hash("banodoco.contract.v1",[r["contract_sha256"] for r in rows])),"runtime_build_id":meta.get("runtime_build_id",framed_hash("banodoco.runtime-build.v1",[r["integrated_oid"] for r in rows])),"source_manifest_id":meta.get("source_manifest_id",framed_hash("banodoco.source-manifest.v1",[r["subtree_sha256"] for r in rows])),"migration_manifest_id":meta.get("migration_manifest_id",NONE),"selected_realm_id":meta.get("selected_realm_id",NONE),"trusted_disposition_sha256":meta.get("trusted_disposition_sha256",NONE),"pre_live_evidence_root":prior["identity"],"contract_epoch":meta.get("contract_epoch",NONE),"runtime_epoch":meta.get("runtime_epoch",NONE),"source_epoch":meta.get("source_epoch",NONE),"migration_epoch":meta.get("migration_epoch",NONE),"activation_epoch":meta.get("activation_epoch",NONE),"release_epoch":NONE,"component_rows":rows}; rec={"schema_version":SCHEMA_VERSION,"kind":"candidate-core","operation_id":"CMD-IDENTITY:candidate-core","identity":framed_hash("banodoco.candidate-core.v1",core),"candidate_core":core,"pre_live_root":prior["identity"],"pre_live_manifest_sha256":prior["pre_live_manifest"]["manifest_sha256"],"metadata":_nfc(meta)}; rec["receipt_sha256"]=_rd(rec); _write(rec,output); return rec
def _safe(p:Any)->Path:
    raw=Path(p).expanduser()
    if ".." in raw.parts:raise ReleaseIdentityError("receipt path may not contain '..'")
    target=raw.absolute(); cur=Path(target.anchor)
    for part in target.parts[1:-1]:
        cur/=part
        if cur.exists() and cur.is_symlink() and cur != Path("/tmp"):raise ReleaseIdentityError("receipt path contains a symlink")
    if target.exists() and target.is_symlink():raise ReleaseIdentityError("receipt path is a symlink")
    return target
def _write(r:Mapping[str,Any],output:Any)->None:
    if output is None:return
    target=_safe(output); target.parent.mkdir(parents=True,exist_ok=True); data=canonical_bytes(r)+b"\n"; target.write_bytes(data)
    if target.read_bytes()!=data:raise ReleaseIdentityError("stored receipt bytes changed during write")
def verify_receipt(r:Mapping[str,Any])->str:
    if r.get("schema_version")!=SCHEMA_VERSION or r.get("receipt_sha256")!=_rd(r):raise ReleaseIdentityError("release receipt digest or schema mismatch")
    if r.get("kind")=="pre-live-root":
        m=r.get("pre_live_manifest")
        if not isinstance(m,Mapping) or m.get("manifest_sha256")!=framed_hash("banodoco.pre-live-manifest.v1",{k:m[k] for k in m if k!="manifest_sha256"}):raise ReleaseIdentityError("pre-live manifest digest mismatch")
        rows=_sets(r.get("component_rows",[])); expected=framed_hash("banodoco.pre-live-evidence-root.v1",{"component_rows":[rows[k] for k in sorted(rows)],"evidence_rows":r.get("evidence_rows"),"manifest_sha256":m["manifest_sha256"]})
    elif r.get("kind")=="candidate-core":
        core=r.get("candidate_core")
        if not isinstance(core,Mapping) or set(core)!=set(CANDIDATE_CORE_FIELDS):raise ReleaseIdentityError("candidate-core-object-v1 has unexpected or missing fields")
        expected=framed_hash("banodoco.candidate-core.v1",core)
    else:raise ReleaseIdentityError("unknown release receipt kind")
    if expected!=r.get("identity"):raise ReleaseIdentityError("release identity mismatch")
    return expected
def load_receipt(path:Any)->dict[str,Any]:
    target=_safe(path)
    try:
        raw=target.read_bytes(); value=json.loads(raw[:-1].decode()) if raw.endswith(b"\n") else (_ for _ in ()).throw(ReleaseIdentityError("receipt is not canonical stored bytes"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError) as e:raise ReleaseIdentityError("cannot retrieve release receipt") from e
    if not isinstance(value,dict) or canonical_bytes(value)+b"\n"!=raw:raise ReleaseIdentityError("receipt bytes are not canonical")
    verify_receipt(value);return value
def bind_remote_targets(receipt:Mapping[str,Any],targets:Sequence[Mapping[str,Any]])->dict[str,Any]:
    verify_receipt(receipt); result=copy.deepcopy(dict(receipt)); rows=[]; seen=set()
    if result.get("remote_target_locators") and list(targets)!=result["remote_target_locators"]:raise ReleaseIdentityError("remote target rows are not the plan-owned locator join")
    for target in targets:
        if not result.get("remote_target_locators"): item=_nfc(dict(target)); tid=item.get("remote_target_id")
        else:
            if set(target)!=set(REMOTE_TARGET_FIELDS):raise ReleaseIdentityError("remote-target-row-v1 has unexpected fields")
            item=_nfc(dict(target));tid=item["remote_target_id"];_url(item["canonical_url"])
        if not isinstance(tid,str) or not tid or tid in seen:raise ReleaseIdentityError("remote target ids must be unique")
        seen.add(tid);rows.append(item)
    result["remote_targets"]=sorted(rows,key=lambda x:x["remote_target_id"]); result["remote_target_registry_sha256"]=component_registry_sha256(result["remote_targets"][:-1] if len(rows)==3 else rows);result["receipt_sha256"]=_rd(result);return result
def _args(values:Sequence[str])->dict[str,str]:
    out={}
    for v in values:
        if "=" not in v:raise ReleaseIdentityError("--component must use COMPONENT_ID=CHECKOUT")
        k,p=v.split("=",1)
        if not k or not p or k in out:raise ReleaseIdentityError("--component values must be unique")
        out[k]=p
    if not out:raise ReleaseIdentityError("at least one --component is required")
    return out
def main(argv:Sequence[str]|None=None)->int:
    p=argparse.ArgumentParser(prog="banodoco-runtime-identity");s=p.add_subparsers(dest="op",required=True);a=s.add_parser("pre-live");a.add_argument("--component",action="append",default=[]);a.add_argument("--output");b=s.add_parser("candidate-core");b.add_argument("--pre-live",required=True);b.add_argument("--component",action="append",default=[]);b.add_argument("--output");c=s.add_parser("verify");c.add_argument("receipt");x=p.parse_args(argv)
    try:
        if x.op=="pre-live":r=create_pre_live_identity(_args(x.component),output=x.output)
        elif x.op=="candidate-core":r=create_candidate_core_identity(x.pre_live,_args(x.component),output=x.output)
        else:r={"ok":True,"identity":load_receipt(x.receipt)["identity"]}
        print(json.dumps(r,sort_keys=True,indent=2));return 0
    except ReleaseIdentityError as e:print(json.dumps({"ok":False,"error":str(e)}));return 1
if __name__=="__main__":raise SystemExit(main())
