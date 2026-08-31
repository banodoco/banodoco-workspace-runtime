"""Neutral-runtime release identity implementation (portable and closed)."""
from __future__ import annotations
import argparse, copy, hashlib, json, os, re, subprocess, tempfile, time, unicodedata
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
RECEIPT_ROOT_ENVIRONMENTS=("ASTRID_RELEASE_RECEIPT_ROOT","BANODOCO_RELEASE_RECEIPT_ROOT","RELEASE_RECEIPT_ROOT")
GENERATOR_ROW_FIELDS=("schema_version","row_kind","generator_id","component_id","entrypoint_component_id","entrypoint_path","entrypoint_sha256","interpreter_tool_id","argv_formula_id","sandbox_policy_id","generator_definition_sha256","input_schema_ids","input_digests","declared_output_roots","tool_ids","output_paths","output_digests","tool_rows","run_ordinal","argv_carrier","argv_sha256","clean_checkout_id","changed_paths","undeclared_changed_paths","started_at","finished_at","exit_code","stop_class","first_run_receipt_sha256","second_run_receipt_sha256","run_receipt_evidence_rows","provenance_input_bindings","producer_id")
CANDIDATE_CORE_FIELDS=("schema_version","governance_binding","component_manifest_sha256","contract_id","runtime_build_id","source_manifest_id","migration_manifest_id","selected_realm_id","trusted_disposition_sha256","pre_live_evidence_root","contract_epoch","runtime_epoch","source_epoch","migration_epoch","activation_epoch","release_epoch","component_rows")

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
    names=_names(root); scope=sorted(set(scope_paths or names)); head=_gt(root,"rev-parse","HEAD"); tree=_gt(root,"rev-parse","HEAD^{tree}"); contract=_scope(names,("contract/","schema","openapi","conformance/")); generated=_scope(names,("generated","/client","client/")); deps=_scope(names,("lock","requirements","pyproject.toml","package.json")); fixtures=_scope(names,("fixture","fixtures")); _=epochs; ref=_gt(root,"symbolic-ref","-q","HEAD",optional=True) or head
    return _shape({"component_id":component_id,"repository_identity":_repo(root),"source_ref":source_ref or ref,"base_oid":head,"base_tree_oid":tree,"integrated_oid":head,"integrated_tree_oid":tree,"subtree_sha256":framed_hash("banodoco.component-subtree.v1", [{"path":p,"oid":_gt(root,"rev-parse",f"HEAD:{p}")} for p in scope]),"contract_sha256":_inv(root,contract),"generator_ids":generated,"dependency_lock_digests":[{"path":p,"sha256":hashlib.sha256(_gb(root,"show",f"HEAD:{p}")).hexdigest()} for p in deps],"fixture_digests":[{"path":p,"sha256":hashlib.sha256(_gb(root,"show",f"HEAD:{p}")).hexdigest()} for p in fixtures],"tool_ids":["TOOL-GIT"],"generator_observation_rows":[],"provenance_input_bindings":[],"producer_id":"PROD-CMD-PACKET:B11.1","epoch_profile_id":"EP-CRSM","freshness_policy_id":"CURRENT-CLEAN-HEAD"})
def resolve_reviewed_components(components:Mapping[str,str|os.PathLike[str]],**kwargs:Any)->list[dict[str,Any]]:return sorted((resolve_component(k,v,**kwargs) for k,v in components.items()),key=lambda x:x["component_id"])
def _clean(components:Mapping[str,str|os.PathLike[str]],output:Any=None)->None:
    if output is not None:
        target=Path(output).expanduser().resolve()
        for path in components.values():
            root=Path(path).expanduser().resolve()
            try: target.relative_to(root)
            except ValueError: continue
            raise ReleaseIdentityError("receipt output may not be inside a component checkout")
    bad=[(k,_dirty(Path(v).expanduser().resolve())) for k,v in components.items() if _dirty(Path(v).expanduser().resolve())]
    if bad:raise ReleaseIdentityError(f"candidate component has uncommitted changes: {bad}")
def _transition(cid:str,local:str,canonical:str,url:str,ref:str)->str:return framed_hash("banodoco.local-to-canonical-repository.v1",[cid,local,canonical,url,ref])
def plan_component_registry()->list[dict[str,Any]]:
    rows=[("NEUTRAL-RUNTIME","banodoco-workspace-runtime-oracle","banodoco/banodoco-workspace-runtime","https://github.com/banodoco/banodoco-workspace-runtime.git"),("ASTRID-CLIENT","peteromallet/Astrid","peteromallet/Astrid","https://github.com/peteromallet/Astrid.git")]
    return [{"remote_target_id":f"REMOTE-TARGET:COMPONENT:{c}","target_kind":"component","component_id":c,"local_repository_identity":l,"repository_identity":r,"canonical_url":u,"destination_ref_or_prefix":"refs/heads/main","expected_old_oid":NONE,"reviewed_source_oid":NONE,"identity_transition_sha256":_transition(c,l,r,u,"refs/heads/main"),"repository_provision_receipt_rows":NONE} for c,l,r,u in rows]
PLAN_COMPONENT_REGISTRY=tuple(plan_component_registry())
def plan_publication_row()->dict[str,Any]:return {"remote_target_id":"REMOTE-TARGET:PUBLICATION","target_kind":"publication","component_id":NONE,"local_repository_identity":NONE,"repository_identity":"banodoco/banodoco-workspace-runtime","canonical_url":"https://github.com/banodoco/banodoco-workspace-runtime.git","destination_ref_or_prefix":"refs/tags/astrid-stage1-evidence/","expected_old_oid":NONE,"reviewed_source_oid":NONE,"identity_transition_sha256":NONE,"repository_provision_receipt_rows":NONE}
def component_registry_sha256(rows:Sequence[Mapping[str,Any]]|None=None)->str:return hashlib.sha256(canonical_bytes(list(rows if rows is not None else plan_component_registry()))).hexdigest()
def _directory_inventory(root:Path)->list[dict[str,str]]:
    if not root.is_dir():raise ReleaseIdentityError("generator staging root is missing")
    out=[]
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():raise ReleaseIdentityError("generator output contains a non-regular entry")
        b=p.read_bytes();out.append({"path":p.relative_to(root).as_posix(),"sha256":hashlib.sha256(b).hexdigest(),"byte_length":str(len(b))})
    return out
def run_b11_1(component_rows:Sequence[Mapping[str,Any]],generator_definitions:Sequence[Mapping[str,Any]],*,contract_bytes:bytes,schema_manifest_bytes:bytes,output_root:str|os.PathLike[str]|None=None)->list[dict[str,Any]]:
    rows=[_shape(r) for r in component_rows]; by={r["component_id"]:r for r in rows}; observed={c:[] for c in by}
    if not generator_definitions:raise ReleaseIdentityError("B11.1 requires declared generator definitions")
    with tempfile.TemporaryDirectory(dir=str(output_root) if output_root else None) as td:
        for d in sorted((dict(x) for x in generator_definitions),key=lambda x:x.get("generator_id","")):
            gid,cid=d.get("generator_id"),d.get("component_id"); checkout=Path(d.get("checkout","")).expanduser().resolve(); ep=checkout/str(d.get("entrypoint_path",""))
            if not isinstance(gid,str) or not isinstance(cid,str) or cid not in by or not ep.is_file() or ep.is_symlink():raise ReleaseIdentityError("B11.1 generator is not bound to a regular reviewed entrypoint")
            invs=[]; receipts=[]
            for n in (1,2):
                run=Path(td)/gid/str(n);stage=run/"staging";inp=run/"inputs";stage.mkdir(parents=True);inp.mkdir();cp=inp/"contract.json";sp=inp/"schema-manifest.json";cp.write_bytes(contract_bytes);sp.write_bytes(schema_manifest_bytes);exe=str(d.get("interpreter_path") or d.get("executable") or "python3");argv=[exe,str(ep),"--contract",str(cp),"--schema-manifest",str(sp),"--output-root",str(stage)];before=_dirty(checkout);started=time.time();res=subprocess.run(argv,cwd=str(checkout),capture_output=True,check=False,timeout=300,env={"PATH":os.environ.get("PATH","")});finished=time.time();after=_dirty(checkout)
                if before!=after:raise ReleaseIdentityError("B11.1 generator changed its checkout")
                if res.returncode!=0:raise ReleaseIdentityError(f"B11.1 generator failed: {gid}")
                inv=_directory_inventory(stage)
                if not inv:raise ReleaseIdentityError("B11.1 generator produced no output")
                invs.append(inv);receipts.append({"schema_version":1,"artifact_kind":"generator-run-receipt","generator_id":gid,"run_ordinal":n,"argv":argv,"argv_sha256":framed_hash("banodoco.generator-run-argv.v1",argv),"output_rows":inv,"started_at":started,"finished_at":finished,"exit_code":0})
            if invs[0]!=invs[1]:raise ReleaseIdentityError("B11.1 generator runs are not byte-identical")
            dd=hashlib.sha256(canonical_bytes(d)).hexdigest();rr=[]
            for rec in receipts:
                raw=canonical_bytes(rec);rr.append({"artifact_id":f"GENERATOR-RUN:{gid}:{rec['run_ordinal']}","artifact_kind":"generator-run-receipt","artifact_schema_id":"evidence-artifact-v1","media_type":"application/json","path":f"embedded/generator-runs/{gid}/{rec['run_ordinal']}.json","content":raw.decode(),"content_sha256":hashlib.sha256(raw).hexdigest(),"artifact_sha256":hashlib.sha256(raw).hexdigest()})
            obs={"schema_version":1,"row_kind":"OBSERVATION","generator_id":gid,"component_id":cid,"entrypoint_component_id":cid,"entrypoint_path":str(d["entrypoint_path"]),"entrypoint_sha256":hashlib.sha256(ep.read_bytes()).hexdigest(),"interpreter_tool_id":d.get("interpreter_tool_id","TOOL-PYTHON"),"argv_formula_id":"GENERATOR-ARGV-V1","sandbox_policy_id":"GENERATOR-READONLY-STAGING-V1","generator_definition_sha256":dd,"input_schema_ids":list(d.get("input_schema_ids",[])),"input_digests":[hashlib.sha256(contract_bytes).hexdigest(),hashlib.sha256(schema_manifest_bytes).hexdigest()],"declared_output_roots":list(d.get("declared_output_roots",["."])),"tool_ids":list(d.get("tool_ids",["TOOL-GIT","TOOL-PYTHON"])),"output_paths":[x["path"] for x in invs[0]],"output_digests":[x["sha256"] for x in invs[0]],"tool_rows":list(d.get("tool_rows",[])),"run_ordinal":NONE,"argv_carrier":NONE,"argv_sha256":NONE,"clean_checkout_id":NONE,"changed_paths":[],"undeclared_changed_paths":[],"started_at":NONE,"finished_at":NONE,"exit_code":NONE,"stop_class":NONE,"first_run_receipt_sha256":hashlib.sha256(canonical_bytes(receipts[0])).hexdigest(),"second_run_receipt_sha256":hashlib.sha256(canonical_bytes(receipts[1])).hexdigest(),"run_receipt_evidence_rows":rr,"provenance_input_bindings":[{"input_id":"CONTRACT-ID","sha256":hashlib.sha256(contract_bytes).hexdigest()},{"input_id":"EXECUTION-SCHEMAS-MANIFEST","sha256":hashlib.sha256(schema_manifest_bytes).hexdigest()},{"input_id":"GENERATOR-DEFINITION","sha256":dd}],"producer_id":"PROD-CMD-PACKET:B11.1"}
            if set(obs)!=set(GENERATOR_ROW_FIELDS):raise ReleaseIdentityError("generator observation schema drift")
            observed[cid].append(obs)
    return [{**r,"generator_ids":[x["generator_id"] for x in sorted(observed.get(r["component_id"],[]),key=lambda x:x["generator_id"])],"generator_observation_rows":sorted(observed.get(r["component_id"],[]),key=lambda x:x["generator_id"])} for r in rows]
execute_b11_1=run_b11_1
def component_registry_sha256(rows:Sequence[Mapping[str,Any]]|None=None)->str:return hashlib.sha256(canonical_bytes(list(rows if rows is not None else plan_component_registry()))).hexdigest()
def _url(u:str)->None:
    p=urlparse(u)
    if p.scheme!="https" or p.netloc!="github.com" or p.username or p.password or p.query or p.fragment or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git",p.path):raise ReleaseIdentityError("canonical URL must be an absolute credential-free HTTPS GitHub URL")
def _locator(u:Any)->None:
    if not isinstance(u,str):raise ReleaseIdentityError("remote locator URL must be a string")
    p=urlparse(u)
    if p.scheme!="https" or p.username or p.password or p.query or p.fragment or ".." in p.path.split("/"):raise ReleaseIdentityError("remote locator must be credential-free HTTPS without traversal")
def join_plan_remote_targets(rows:Sequence[Mapping[str,Any]],*,strict:bool=True,registry_rows:Sequence[Mapping[str,Any]]|None=None)->list[dict[str,Any]]:
    source={r["component_id"]:_shape(r) for r in rows}; registry=[dict(r) for r in (registry_rows if registry_rows is not None else plan_component_registry())]
    if registry_rows is not None and hashlib.sha256(canonical_bytes(registry)).hexdigest()!=component_registry_sha256(plan_component_registry()):raise ReleaseIdentityError("external plan registry digest mismatch")
    if len({r.get("remote_target_id") for r in registry})!=len(registry) or any(set(r)!=set(REMOTE_TARGET_FIELDS) for r in registry):raise ReleaseIdentityError("plan registry rows are not exact and unique")
    if strict and set(source)!={r["component_id"] for r in registry}:raise ReleaseIdentityError("plan-owned component registry join is not total")
    out=[]
    for t in registry:
        s=source.get(t["component_id"])
        if not s or s["repository_identity"]!=t["local_repository_identity"]:raise ReleaseIdentityError("local repository identity does not match plan registry")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}",s["integrated_oid"]):raise ReleaseIdentityError("reviewed_source_oid must be a full Git object ID")
        _url(t["canonical_url"]); item=copy.deepcopy(t); item["reviewed_source_oid"]=s["integrated_oid"]; out.append(item)
    out.append(plan_publication_row()); return out
def build_prelive_manifest(seed_outputs:Mapping[str,Any]|None=None,*,metadata:Mapping[str,Any]|None=None)->dict[str,Any]:
    if seed_outputs=={}:raise ReleaseIdentityError("PRELIVE-MANIFEST is missing required seed bytes")
    outputs=seed_outputs or {s:canonical_bytes({"seed_id":s}) for s in PRELIVE_SEEDS}; seeds=list(PRELIVE_SEEDS); epochs=dict((metadata or {}).get("epochs",{"contract_epoch":NONE,"runtime_epoch":NONE,"source_epoch":NONE,"migration_epoch":NONE,"activation_epoch":NONE,"release_epoch":NONE})); evidence=[]
    if set(outputs)!=set(seeds):raise ReleaseIdentityError("PRELIVE-MANIFEST seed output set is not exactly 47 seeds")
    for s in seeds:
        v=outputs[s]
        if not isinstance(v,(bytes,bytearray)):raise ReleaseIdentityError("PRELIVE seed outputs must be complete bytes")
        data=bytes(v); d=hashlib.sha256(data).hexdigest(); evidence.append({"path":f"evidence/sha256/{d[:2]}/{d}","sha256":d,"producer_id":"CMD-PRELIVE-MANIFEST","token_ids":[s],"epochs":_nfc(epochs),"media_type":"application/json"})
    evidence.sort(key=lambda x:(x["path"],x["sha256"],x["producer_id"])); m={"schema_version":PRELIVE_MANIFEST_SCHEMA,"governance_binding":"LOCAL-STAGE1-RELEASE","seed_ids":seeds,"evidence_rows":evidence,"excluded_ids":list(PRELIVE_EXCLUDED_IDS),"epochs":_nfc(epochs)}; m["manifest_sha256"]=framed_hash("banodoco.pre-live-manifest.v1",m); return m
def _rd(r:Mapping[str,Any])->str:return framed_hash("banodoco.release-receipt.v1",{k:v for k,v in r.items() if k not in {"receipt_sha256","identity"}})
def create_pre_live_identity(components:Mapping[str,str|os.PathLike[str]],*,metadata:Mapping[str,Any]|None=None,output:Any=None,seed_outputs:Mapping[str,Any]|None=None)->dict[str,Any]:
    _clean(components,output); rows=resolve_reviewed_components(components); meta=dict(metadata or {}); manifest=build_prelive_manifest(seed_outputs,metadata=meta); evidence=[]
    for r in rows:
        b=canonical_bytes(r); d=hashlib.sha256(b).hexdigest(); evidence.append({"path":f"evidence/sha256/{d[:2]}/{d}","sha256":d,"producer_id":"CMD-IDENTITY:pre-live-root","token_ids":[r["component_id"]],"epochs":meta.get("epochs",{}),"media_type":"application/json"})
    evidence.sort(key=lambda x:(x["path"],x["sha256"],x["producer_id"])); identity=framed_hash("banodoco.pre-live-evidence-root.v1",{"component_rows":rows,"evidence_rows":evidence,"manifest_sha256":manifest["manifest_sha256"]}); strict=set(r["component_id"] for r in rows)=={"ASTRID-CLIENT","NEUTRAL-RUNTIME"} and all(r["repository_identity"] in {"peteromallet/Astrid","banodoco-workspace-runtime-oracle"} for r in rows); locators=join_plan_remote_targets(rows) if strict else []; rec={"schema_version":SCHEMA_VERSION,"kind":"pre-live-root","operation_id":"CMD-IDENTITY:pre-live-root","identity":identity,"pre_live_manifest":manifest,"evidence_rows":evidence,"component_rows":rows,"remote_target_locators":locators,"remote_target_registry_sha256":component_registry_sha256(plan_component_registry()) if locators else NONE,"metadata":_nfc(meta)}; rec["receipt_sha256"]=_rd(rec); _write(rec,output); return rec
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
def _configured_root()->Path|None:
    for name in RECEIPT_ROOT_ENVIRONMENTS:
        value=os.environ.get(name)
        if value:return Path(value).expanduser().resolve()
    return None
def _safe(p:Any,root:Path|None=None)->Path:
    raw=Path(p).expanduser()
    if ".." in raw.parts:raise ReleaseIdentityError("receipt path may not contain '..'")
    target=raw.absolute(); cur=Path(target.anchor)
    for part in target.parts[1:-1]:
        cur/=part
        if cur.exists() and cur.is_symlink() and cur != Path("/tmp"):raise ReleaseIdentityError("receipt path contains a symlink")
    if target.exists() and target.is_symlink():raise ReleaseIdentityError("receipt path is a symlink")
    if root is not None:
        try:target.relative_to(root)
        except ValueError:raise ReleaseIdentityError("receipt path is outside configured receipt root")
    return target
def _write(r:Mapping[str,Any],output:Any)->None:
    if output is None:return
    target=_safe(output,_configured_root()); target.parent.mkdir(parents=True,exist_ok=True); data=canonical_bytes(r)+b"\n"; target.write_bytes(data)
    if target.read_bytes()!=data:raise ReleaseIdentityError("stored receipt bytes changed during write")
def verify_receipt(r:Mapping[str,Any])->str:
    if r.get("schema_version")!=SCHEMA_VERSION or r.get("receipt_sha256")!=_rd(r):raise ReleaseIdentityError("release receipt digest or schema mismatch")
    if r.get("kind")=="pre-live-root":
        m=r.get("pre_live_manifest")
        if not isinstance(m,Mapping) or set(m)!={"schema_version","governance_binding","seed_ids","evidence_rows","excluded_ids","epochs","manifest_sha256"} or m.get("schema_version")!=PRELIVE_MANIFEST_SCHEMA or m.get("seed_ids")!=list(PRELIVE_SEEDS) or len(m.get("seed_ids",[]))!=47:raise ReleaseIdentityError("PRELIVE-MANIFEST seed/schema projection mismatch")
        evidence=m.get("evidence_rows")
        if not isinstance(evidence,list) or len(evidence)!=47:raise ReleaseIdentityError("PRELIVE-MANIFEST evidence cardinality mismatch")
        for row in evidence:
            if set(row)!={"path","sha256","producer_id","token_ids","epochs","media_type"} or row.get("producer_id")!="CMD-PRELIVE-MANIFEST" or row.get("media_type")!="application/json" or not isinstance(row.get("token_ids"),list) or len(row["token_ids"])!=1 or row["token_ids"][0] not in PRELIVE_SEEDS or row.get("path")!=f"evidence/sha256/{row.get('sha256','')[:2]}/{row.get('sha256','')}" or not re.fullmatch(r"[0-9a-f]{64}",str(row.get("sha256"))):raise ReleaseIdentityError("PRELIVE-MANIFEST evidence row mismatch")
        if {row["token_ids"][0] for row in evidence}!=set(PRELIVE_SEEDS):raise ReleaseIdentityError("PRELIVE-MANIFEST evidence is not a bijection")
        if m.get("manifest_sha256")!=framed_hash("banodoco.pre-live-manifest.v1",{k:m[k] for k in m if k!="manifest_sha256"}):raise ReleaseIdentityError("pre-live manifest digest mismatch")
        rows=_sets(r.get("component_rows",[])); expected=framed_hash("banodoco.pre-live-evidence-root.v1",{"component_rows":[rows[k] for k in sorted(rows)],"evidence_rows":r.get("evidence_rows"),"manifest_sha256":m["manifest_sha256"]})
    elif r.get("kind")=="candidate-core":
        core=r.get("candidate_core")
        if not isinstance(core,Mapping) or set(core)!=set(CANDIDATE_CORE_FIELDS):raise ReleaseIdentityError("candidate-core-object-v1 has unexpected or missing fields")
        expected=framed_hash("banodoco.candidate-core.v1",core)
    else:raise ReleaseIdentityError("unknown release receipt kind")
    if expected!=r.get("identity"):raise ReleaseIdentityError("release identity mismatch")
    return expected
def load_receipt(path:Any)->dict[str,Any]:
    target=_safe(path,_configured_root())
    try:
        raw=target.read_bytes(); value=json.loads(raw[:-1].decode()) if raw.endswith(b"\n") else (_ for _ in ()).throw(ReleaseIdentityError("receipt is not canonical stored bytes"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError) as e:raise ReleaseIdentityError("cannot retrieve release receipt") from e
    if not isinstance(value,dict) or canonical_bytes(value)+b"\n"!=raw:raise ReleaseIdentityError("receipt bytes are not canonical")
    verify_receipt(value);return value
def bind_remote_targets(receipt:Mapping[str,Any],targets:Sequence[Mapping[str,Any]])->dict[str,Any]:
    verify_receipt(receipt); result=copy.deepcopy(dict(receipt)); rows=[]; seen=set()
    if result.get("remote_target_locators") and list(targets)!=result["remote_target_locators"]:raise ReleaseIdentityError("remote target rows are not the plan-owned locator join")
    for target in targets:
        if not result.get("remote_target_locators"):
            item=_nfc(dict(target)); tid=item.get("remote_target_id")
            if "canonical_url" in item:_locator(item["canonical_url"])
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
