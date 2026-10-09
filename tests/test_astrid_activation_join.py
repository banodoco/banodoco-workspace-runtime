"""CPU-only Runtime-to-committed-Astrid activation interoperability proof.

The graph and role-custody references are deterministic fixtures. Runtime's
launcher, durable receipt publisher, credential store, relay framing, and the
selected Astrid GenericHost activation/control receiver remain real.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from runtime_protocol.auth import CredentialStore
from runtime_protocol.errors import AuthorizationError
from runtime_protocol.local_execution_supervisor import (
    CONTROL_VERSION as RELAY_VERSION,
    LocalExecutionRelay,
    RelayError,
    receive_frame,
    send_frame,
    serve_control,
)
from runtime_protocol.local_worker import (
    LocalWorkerLauncher,
    LocalWorkerObservation,
    LocalWorkerProfile,
    ProcessIdentity,
    _selected_profile_payload,
)
from runtime_protocol.local_worker_composition import CrossProcessWorkerPreparer, _actual_executable, _file_digest
from banodoco_local.custody_broker import default_process_identity


ASTRID_ROOT = Path("/Users/peteromalley/Documents/reigh-workspace/Astrid/.otto/worktrees/three-effort-post-completion-integration-20261001")
ASTRID_PYTHON = Path("/Users/peteromalley/Documents/reigh-workspace/Astrid/.venv/bin/python")
RUNTIME_ROOT = Path(__file__).resolve().parents[1]


# Explicit child program: this is the only graph substitution. It still enters
# committed LocalExecutionPreparation.serve_control and
# _await_worker_activation; it does not synthesize activation frames or ACKs.
_ASTRID_RECEIVER = r'''import hashlib, json, os, signal, subprocess, sys, time
from pathlib import Path
from astrid.core.execution.generic_host import LocalExecutionPreparation, _await_worker_activation
from astrid.core.execution.custody_broker import default_process_identity

control_fd, activation_fd = map(int, sys.argv[1:3])
operation_id, channel_id, credential_file, scope, config_path = sys.argv[3:]
config = json.loads(Path(config_path).read_text())
events = Path(config["events"])
astrid_root = Path(config["astrid_root"]).resolve()

def imported_manifest(root):
    result={}
    for name,module in tuple(sys.modules.items()):
        origin=getattr(module,"__file__",None)
        if not origin: continue
        path=Path(origin).resolve()
        try: path.relative_to(root)
        except ValueError: continue
        if path.is_file(): result[name]={"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    return result

def event(suffix, stage, payload):
    events.with_suffix(suffix).write_text(json.dumps({"stage":stage,"monotonic_ns":time.monotonic_ns(),**payload},sort_keys=True))

def ref(role, pid, birth):
    return {"version":"runtime.role-custody-reference/v1", "scope_root":scope,
      "role":role, "generation":1, "target":{"pid":pid,"birth_id":birth,
      "uid":os.getuid(),"audit_token_sha256":"sha256:"+"a"*64,
      "audit_token_pidversion":max(1,pid)}}

class CpuGraph:
    def __init__(self, *, request):
        self.request=request; self.engine=None; self.listener_pid=None; self.listener_birth=None
        self.refs={}; self.aborted=False
    def prepare(self):
        engine_code = "import subprocess,sys,time,signal; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(600)']); print(p.pid,flush=True); signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));\ntry: time.sleep(600)\nfinally: p.terminate(); print('listener-exit:'+str(p.wait()),flush=True)"
        self.engine=subprocess.Popen([sys.executable,"-c",engine_code], start_new_session=True,
                                     stdout=subprocess.PIPE, text=True)
        self.listener_pid=int(self.engine.stdout.readline().strip())
        self.listener_birth=default_process_identity(self.listener_pid)["birth_id"]
        engine_id=default_process_identity(self.engine.pid)
        host_id=default_process_identity(os.getpid())
        self.refs={"engine":ref("engine",self.engine.pid,engine_id["birth_id"]),
                   "engine_listener":ref("engine_listener",self.listener_pid,self.listener_birth)}
        self.measured={"processes":{"host":{"pid":os.getpid(),"birth_id":host_id["birth_id"]},
                                    "engine":{"pid":self.engine.pid,"birth_id":engine_id["birth_id"]},
                                    "engine_listener":{"pid":self.listener_pid,"birth_id":self.listener_birth}},
                       "engine_binding":{"supervisor_pid":self.engine.pid,"listener_pid":self.listener_pid,
                                         "listener_parent_pid":self.engine.pid,"socket_owner_pid":self.listener_pid},
                       "session_config_digest":self.request["profile"]["session_config_digest"],
                       "custody_capabilities":self.refs}
        return self.measured
    def report(self): return self.measured
    def known_custody_capabilities(self): return self.refs
    def abort(self):
        if self.aborted: return self.cleanup
        if self.listener_pid:
            try: os.kill(self.listener_pid, 15)
            except ProcessLookupError: pass
        if self.engine:
            try: os.kill(self.engine.pid, 15)
            except ProcessLookupError: pass
        if self.engine:
            self.engine.wait(timeout=3)
            cleanup_line=self.engine.stdout.readline().strip()
            if not cleanup_line.startswith("listener-exit:"):
                raise RuntimeError("engine fixture did not report its retained listener wait")
            listener_exit=int(cleanup_line.split(":",1)[1])
        else: listener_exit=0
        self.cleanup={role:{"generation":value["generation"],"target":value["target"],
                            "exit_code":listener_exit if role=="engine_listener" else self.engine.returncode,
                            "proof_kind":"retained-child-exit"} for role,value in self.refs.items()}
        self.aborted=True
        return self.cleanup

prep=LocalExecutionPreparation(operation_id=operation_id,channel_id=channel_id,graph_factory=CpuGraph)
prep.serve_control(control_fd)
def stop(_sig,_frame):
    prep.abort()
    raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
try:
    grant=_await_worker_activation(activation_fd, operation_id=operation_id,channel_id=channel_id,
                                   credential_file=credential_file,timeout_seconds=15,require_receipt=True)
    events.with_suffix(".eof-accepted").write_text("receiver returned only after Runtime half-close")
    host_source=Path(sys.modules[LocalExecutionPreparation.__module__].__file__).resolve()
    event(".receiver-returned.json","receiver_returned",{
          "operation_id":grant["operation_id"],"channel_id":grant["channel_id"],
          "activation_id":grant["activation_id"],"executor_incarnation":grant["executor_incarnation"],
          "evidence_digest":grant["evidence_digest"],"host_pid":os.getpid(),
          "host_birth_id":default_process_identity(os.getpid())["birth_id"],
          "interpreter":sys.executable,"wrapper_path":str(Path(__file__).resolve()),
          "wrapper_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "generic_host_source":str(host_source),
          "generic_host_sha256":hashlib.sha256(host_source.read_bytes()).hexdigest()})
except Exception as exc:
    prep.abort()
    event(".rejected.json","receiver_rejected",{"error_type":type(exc).__name__})
    events.with_suffix(".rejected").write_text(type(exc).__name__)
    while True: time.sleep(.1)
events.write_text(json.dumps({"activation":"accepted","activation_id":grant["activation_id"],
                              "host_pid":os.getpid(),"host_birth_id":default_process_identity(os.getpid())["birth_id"],
                              "interpreter":sys.executable,"wrapper_path":str(Path(__file__).resolve()),
                              "wrapper_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}))
events.with_suffix(".modules.json").write_text(json.dumps(imported_manifest(astrid_root),sort_keys=True))
# Keep the host-control descriptor live after activation for report and abort.
while True: time.sleep(.1)
'''


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_request(value):
    grant=value.get("grant",{})
    return {"version":value.get("version"),"operation_id":value.get("operation_id"),
      "channel_id":value.get("channel_id"),"grant":{key:grant.get(key) for key in
      ("activation_id","executor_incarnation","evidence_digest")},"host":value.get("host")}


def _safe_receipt(value):
    grant=value.get("grant",{})
    return {"version":value.get("version"),"operation_id":value.get("operation_id"),
      "channel_id":value.get("channel_id"),"grant":{key:grant.get(key) for key in
      ("activation_id","executor_incarnation","evidence_digest")},"host":value.get("host")}


def _safe_ack(value):
    return {key:value.get(key) for key in ("version","operation_id","channel_id","activation_id",
      "executor_incarnation","evidence_digest","host")}


def _record_phase(events, suffix, stage, payload):
    events.with_suffix(suffix).write_text(json.dumps({"stage":stage,"monotonic_ns":time.monotonic_ns(),**payload},sort_keys=True))


class _ObservedChannel:
    """Passive frame observer around the real Runtime-relay socket."""
    def __init__(self, channel, events):
        self.channel=channel; self.events=events; self.pending=bytearray(); self.closed=False; self.phase="prepare"
    def sendall(self, value): return self.channel.sendall(value)
    def recv(self, size):
        chunk=self.channel.recv(size)
        if chunk:
            self.pending.extend(chunk)
            while b"\n" in self.pending:
                line,_,tail=self.pending.partition(b"\n"); self.pending=bytearray(tail)
                try: frame=json.loads(line)
                except Exception: continue
                if isinstance(frame,dict) and ("accepted" in frame or "error_code" in frame):
                    safe={"version":frame.get("version"),"status":frame.get("status"),
                          "error_code":frame.get("error_code")}
                    if isinstance(frame.get("accepted"),dict): safe["accepted"]=_safe_ack(frame["accepted"])
                    _record_phase(self.events,f".outer-{self.phase}-response.json","runtime_outer_response",safe)
        return chunk
    def shutdown(self, how): return self.channel.shutdown(how)
    def close(self):
        self.channel.close(); self.closed=True
    def fileno(self): return self.channel.fileno()
    def __getattr__(self, name): return getattr(self.channel,name)


def _bounded_error(exc, profile):
    message=str(exc)[:200]
    message=message.replace(str(profile.support_root),"[support-root]")
    return {"type":type(exc).__name__,"message":message}


def _wait_for(path: Path, timeout: float = 2.0) -> Path:
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if path.is_file(): return path
        time.sleep(.01)
    raise AssertionError(f"expected subprocess evidence was not written: {path.name}")


def _fixture_profile(root: Path) -> LocalWorkerProfile:
    session_root = root / "out" / "sessions" / "cpu-proof"
    config = {"runtime_root":str(root),"cwd":str(root),"server_log_path":str(session_root/"comfy.log"),
              "port":18888,"locality":"managed_local_server","warm_policy":"auto","ready_timeout_sec":5}
    session_digest="sha256:"+hashlib.sha256(json.dumps(config,indent=2,sort_keys=True).encode()).hexdigest()
    py=Path(sys.executable).resolve(); exe_digest=_digest(py)
    launch={"module":"vibecomfy.commands.session","session_root":str(session_root),"config":config,
            "source_revision":"1"*40,"source_content_digest":"sha256:"+"3"*64,
            "listener_argv":[str(py),"-c","pass"],
            "adapter_pins":{key:"sha256:"+"4"*64 for key in
                ("session_source_sha256","spawn_sha256","cleanup_sha256","stop_sha256","adapter_source_sha256")}}
    return LocalWorkerProfile(profile_id="cpu-proof",workspace_uuid="workspace-cpu-proof",realm_root=root/"realm",
      support_root=root/"support",machine_id="cpu-proof-machine",worker_executable=py,host_executable=py,
      engine_executable=py,engine_listener_executable=py,engine_endpoint="http://127.0.0.1:18888",
      worker_artifact_digest=exe_digest,host_artifact_digest=exe_digest,engine_artifact_digest=exe_digest,
      engine_listener_artifact_digest=exe_digest,session_config_digest=session_digest,profile_revision="fixture-r1",
      profile_digest="sha256:"+"5"*64,release_digest="sha256:"+"6"*64,
      engine_launch=launch)


class _RetainedRelay:
    def __init__(self, pid): self.pid=pid
    def verify(self):
        observed=default_process_identity(self.pid)
        if observed is None: raise RelayError("relay process identity disappeared")
        return observed


class _Adapter(CrossProcessWorkerPreparer):
    """Use production activation methods with a real serve_control subprocess."""
    def __init__(self, profile, config, *, events, drop_ack=False, misbind=False):
        super().__init__(profile=profile,config=config,environment={},timeout_seconds=15,cleanup_timeout_seconds=2)
        self.events=events; self.drop_ack=drop_ack; self.misbind=misbind; self.session=None; self.thread=None
        self._current=None

    def prepare(self, profile, *, operation_id, channel_id):
        from runtime_protocol.local_execution_supervisor import host_prepare_request
        runtime_end,relay_end=socket.socketpair(); runtime_end.settimeout(5)
        host_scope=str(profile.support_root/"custody"/operation_id)
        Path(host_scope).mkdir(parents=True,exist_ok=True)
        owner=default_process_identity(os.getpid())
        preparation=host_prepare_request(operation_id=operation_id,channel_id=channel_id,owner_epoch="cpu-proof-epoch",
          runtime_owner={"pid":os.getpid(),"uid":os.getuid(),"birth_id":owner["birth_id"],
                         "runtime_instance_id":"cpu-proof-epoch","coordinator_epoch":"cpu-proof-epoch"},
          profile=_selected_profile_payload(profile),custody_scope=host_scope)
        relay_script=("from tests.test_astrid_activation_join import _serve_test_relay; "
                      "s=__import__('sys'); _serve_test_relay(int(s.argv[1]),s.argv[2],s.argv[3]=='1',s.argv[4]=='1')")
        self.events.with_suffix(".relay-wrapper.txt").write_text(relay_script)
        env=dict(os.environ); env["PYTHONPATH"]=str(RUNTIME_ROOT)+os.pathsep+str(ASTRID_ROOT)
        process=subprocess.Popen([str(ASTRID_PYTHON),"-c",relay_script,str(relay_end.fileno()),str(self.events),
          "1" if self.drop_ack else "0", "1" if self.misbind else "0"],cwd=str(RUNTIME_ROOT),env=env,stdin=subprocess.DEVNULL,
          stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,close_fds=True,pass_fds=(relay_end.fileno(),),start_new_session=True)
        relay_end.close()
        relay_identity=default_process_identity(process.pid)
        if relay_identity is None: raise AssertionError("Runtime relay subprocess identity was not observable")
        observed_control=_ObservedChannel(runtime_end,self.events)
        handle=SimpleNamespace(worker=process,birth_id=relay_identity["birth_id"],control=observed_control,
          rpc_lock=threading.RLock(),relay=True,closed=False,activated=False,retained=_RetainedRelay(process.pid),
          owner_epoch="cpu-proof-epoch",custody_scope=host_scope,preparation=preparation,report_value=None)
        self._active=handle; self._current=handle
        send_frame(runtime_end,{"version":RELAY_VERSION,"command":"prepare","preparation":preparation,"config":{}})
        response=receive_frame(runtime_end)
        if response.get("status")!="ok":
            process.kill(); process.wait(timeout=2)
            raise AssertionError(f"Runtime relay prepare failed: {response}; stderr={process.stderr.read().decode(errors='replace')}")
        handle.report_value=response["report"]
        return handle

    def report(self,handle):
        send_frame(handle.control,{"version":RELAY_VERSION,"command":"report"})
        result=receive_frame(handle.control)
        if result.get("status")!="ok": raise AssertionError(f"Runtime relay report failed: {result}")
        handle.report_value=result["report"]
        return result["report"]

    def abort(self,handle):
        if handle.closed: return
        handle.control.phase="abort"
        send_frame(handle.control,{"version":RELAY_VERSION,"command":"abort"})
        result=receive_frame(handle.control)
        if result.get("status")!="ok": raise AssertionError(f"Runtime relay abort unresolved: {result}")
        handle.cleanup_result=result
        try: handle.control.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        handle.control.close()
        try: handle.worker.wait(timeout=4)
        except subprocess.TimeoutExpired:
            handle.worker.kill(); handle.worker.wait(timeout=2)
        handle.closed=True
        roles=handle.report_value.get("processes",{}) if isinstance(handle.report_value,dict) else {}
        self.cleanup_evidence={"relay_abort_response":result,"relay_wait_returncode":handle.worker.returncode,
          "relay_process_absent":default_process_identity(handle.worker.pid) is None,
          "runtime_control_descriptor_closed":handle.control.closed and handle.control.fileno()==-1,
          "roles":{role:{"pid":item.get("pid"),"independently_absent":default_process_identity(item["pid"]) is None}
                   for role,item in roles.items() if isinstance(item,dict) and isinstance(item.get("pid"),int)}}

    def activate(self,handle,grant):
        handle.control.phase="activation"
        try:
            return super().activate(handle,grant)
        except Exception as exc:
            _record_phase(self.events,".adapter-error.json","runtime_adapter_error",_bounded_error(exc,self.profile))
            raise

    def control_alive(self,handle): return not handle.closed
    def current_handle(self): return self._current
    def cancel_current(self):
        if self._current is not None: self.abort(self._current)


class _HostSession:
    def __init__(self,preparation,profile,config,*,events,drop_ack,misbind=False,
                 receiver_program=_ASTRID_RECEIVER, receiver_config=None, credential_actor="cpu-proof"):
        self.timeout = 5.0
        self.preparation=preparation; self.drop_ack=drop_ack; self._request=None
        self.misbind=misbind
        self.control,self.control_child=socket.socketpair(); self.activation,self.activation_child=socket.socketpair()
        self.control.settimeout(5); self.activation.settimeout(5)
        self.events=events
        receiver=events.parent/"astrid_receiver.py"; receiver.write_text(receiver_program)
        self.wrapper_bytes=receiver.read_bytes()
        config_file=events.parent/"receiver-config.json"
        config_file.write_text(json.dumps({"events":str(events),"astrid_root":str(ASTRID_ROOT),
                                          **(receiver_config or {})}))
        env=dict(os.environ); env["PYTHONPATH"]=str(RUNTIME_ROOT)+os.pathsep+str(ASTRID_ROOT)
        self.process=subprocess.Popen([str(ASTRID_PYTHON),str(receiver),str(self.control_child.fileno()),
          str(self.activation_child.fileno()),preparation["operation_id"],preparation["channel_id"],
          str(Path(profile["support_root"])/"credentials"/(credential_actor+".token")),preparation["custody_scope"],str(config_file)],
          cwd=str(ASTRID_ROOT),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
          close_fds=True,pass_fds=(self.control_child.fileno(),self.activation_child.fileno()),start_new_session=True)
        self.control_child.close(); self.activation_child.close()
        identity=default_process_identity(self.process.pid)
        if identity is None: raise AssertionError("Astrid subprocess identity was not observable")
        self.host_birth=identity["birth_id"]
        self.bridge=LocalExecutionRelay(host_pid=self.process.pid,host_birth_id=self.host_birth,
          exchange=self.exchange,verify_host=self.verify_host)
    def verify_host(self):
        value=default_process_identity(self.process.pid)
        if self.process.poll() is not None or value is None or value["birth_id"]!=self.host_birth:
            raise RelayError("Astrid subprocess identity changed")
    def exchange(self,request): send_frame(self.control,request); return receive_frame(self.control)
    def begin_activation(self,grant):
        required={"version","operation_id","channel_id","credential_file","executor_incarnation","evidence_digest","acceptance_mode","activation_id"}
        if set(grant)!=required or grant.get("version")!="runtime.local-worker-activation/v1":
            raise RelayError("Runtime activation grant is not exact")
        identity=default_process_identity(self.process.pid)
        if identity is None or identity["birth_id"]!=self.host_birth: raise RelayError("host identity changed before activation")
        frame={**dict(grant),"host":{"pid":self.process.pid,"birth_id":self.host_birth}}
        if self.misbind: frame["channel_id"]="wrong-channel"
        send_frame(self.activation,frame)
        self._request=receive_frame(self.activation)
        expected={"version":"astrid.local-worker-activation-request/v1","operation_id":grant["operation_id"],
          "channel_id":grant["channel_id"],"grant":{key:grant[key] for key in
          ("activation_id","credential_file","executor_incarnation","evidence_digest")},"host":frame["host"]}
        if self._request!=expected: raise RelayError("Astrid activation request differs from exact Runtime grant")
        _record_phase(self.events,".request.json","astrid_activation_request",_safe_request(self._request))
        return self._request
    def finish_activation(self,receipt):
        # Use the same host activation socket protocol as NativeHostSession.
        expected={**self._request,"version":"runtime.local-worker-activation-recorded/v1"}
        if dict(receipt)!=expected: raise RelayError("Runtime receipt differs from Astrid request")
        record_path=Path(self.preparation["custody_scope"])/"activation-record.json"
        durable=json.loads(record_path.read_text())
        if durable.get("receipt")!=dict(receipt) or durable.get("state")!="recorded":
            raise RelayError("Runtime activation record was not durable before receipt forwarding")
        _record_phase(self.events,".publication.json","runtime_durable_publication",{
          "version":durable.get("version"),"state":durable.get("state"),
          "record_sha256":hashlib.sha256(record_path.read_bytes()).hexdigest(),"receipt":_safe_receipt(receipt)})
        _record_phase(self.events,".forwarding.json","astrid_receipt_forwarding",_safe_receipt(receipt))
        self.events.with_suffix(".receipt-forwarded").write_text(hashlib.sha256(record_path.read_bytes()).hexdigest())
        send_frame(self.activation,dict(receipt)); self.activation.shutdown(socket.SHUT_WR)
        _record_phase(self.events,".half-close.json","activation_half_close_completed",_safe_receipt(receipt))
        accepted=receive_frame(self.activation)
        required={"version":"astrid.local-worker-activation-accepted/v1","operation_id":receipt["operation_id"],
          "channel_id":receipt["channel_id"],"executor_incarnation":receipt["grant"]["executor_incarnation"],
          "evidence_digest":receipt["grant"]["evidence_digest"],"host":receipt["host"],
          "activation_id":receipt["grant"]["activation_id"]}
        if accepted!=required: raise RelayError("Astrid activation ACK differs from receipt")
        self.events.with_suffix(".ack").write_text(json.dumps(accepted))
        _record_phase(self.events,".ack.json","astrid_activation_ack",_safe_ack(accepted))
        if self.drop_ack: raise RelayError("test relay dropped the received Astrid ACK")
        self.activation.close()
        return accepted
    def report(self): return self.bridge.report()
    def abort(self): return self.bridge.abort()
    def reap_host(self):
        descriptor_before={"control":self.control.fileno(),"activation":self.activation.fileno()}
        if self.process.poll() is None:
            self.process.terminate()
        try: code=self.process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            self.process.kill(); code=self.process.wait(timeout=2)
        host_identity_after=default_process_identity(self.process.pid)
        self.control.close()
        try:self.activation.close()
        except OSError:pass
        self.events.with_suffix(".host-cleanup.json").write_text(json.dumps({
          "stage":"host_cleanup","wait_returncode":code,
          "control_descriptor_before":descriptor_before["control"],
          "activation_descriptor_before":descriptor_before["activation"],
          "control_descriptor_closed":self.control.fileno()==-1,
          "activation_descriptor_closed":self.activation.fileno()==-1,
          "independent_process_absent":host_identity_after is None},sort_keys=True))
        return code


def _serve_test_relay(descriptor, events_value, drop_ack, misbind):
    """Subprocess entry point; the actual Runtime serve_control owns framing."""
    channel=socket.socket(fileno=descriptor); channel.settimeout(15)
    events=Path(events_value); state={}
    manifest={}
    for name,module in tuple(sys.modules.items()):
        origin=getattr(module,"__file__",None)
        if not origin: continue
        path=Path(origin).resolve()
        try: path.relative_to(RUNTIME_ROOT)
        except ValueError: continue
        if path.is_file(): manifest[name]={"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    events.with_suffix(".runtime-modules.json").write_text(json.dumps(manifest,sort_keys=True))
    def reference(scope,role):
        if role=="relay": target=default_process_identity(os.getpid())
        else:
            session=state.get("session")
            target=default_process_identity(session.process.pid) if session else None
        if target is None: raise RelayError("test custody fixture target is not observable")
        return {"version":"runtime.role-custody-reference/v1","scope_root":scope,"role":role,"generation":1,
          "target":{"pid":target["pid"],"birth_id":target["birth_id"],"uid":os.getuid(),
                    "audit_token_sha256":"sha256:"+"b"*64,"audit_token_pidversion":max(1,target["pid"])}}
    def factory(preparation,config,*,retain):
        session=_HostSession(preparation,preparation["profile"],config,events=events,drop_ack=drop_ack,misbind=misbind)
        state["session"]=session; retain(session); return session
    try:
        serve_control(channel,session_factory=factory,reference_reader=reference,
                      relay_identity=lambda:default_process_identity(os.getpid()))
    except RelayError as exc:
        if "closed" not in str(exc): raise
    finally:
        channel.close()


class _ObservedCredentialStore(CredentialStore):
    def __init__(self,root,*,ack_path,observations):
        super().__init__(root); self.ack_path=ack_path; self.observations=observations
    def enable_actor(self,actor):
        assert self.ack_path.is_file(),"Runtime enabled credential before Astrid ACK"
        assert any(item["after_ack"] for item in self.observations),"credential enable preceded post-ACK observation"
        super().enable_actor(actor)


class _Inspector:
    def __init__(self,profile,credentials,events,observations):
        self.profile=profile; self.credentials=credentials; self.events=events; self.observations=observations
    def observe(self,handle):
        report=handle.report_value
        def proc(role):
            item=report["processes"][role]
            fact=default_process_identity(item["pid"])
            if fact is None or fact["birth_id"]!=item["birth_id"]: raise AssertionError(f"{role} identity mismatch")
            executable=_actual_executable(item["pid"])
            return ProcessIdentity(pid=item["pid"],birth_id=item["birth_id"],uid=fact["uid"],
              parent_pid=fact["parent_pid"],process_group=os.getpgid(item["pid"]),session_id=os.getsid(item["pid"]),
              executable=executable,artifact_digest=_file_digest(executable))
        engine=proc("engine"); listener=proc("engine_listener"); host=proc("host"); worker=proc("worker")
        after_ack=self.events.with_suffix(".ack").is_file()
        token_path=self.credentials.path_for("cpu-proof")
        enabled=False
        if token_path.is_file():
            try: self.credentials.load(token_path.read_text().strip()); enabled=True
            except AuthorizationError: pass
            assert not enabled,"credential became usable before final post-ACK observation"
        self.observations.append({"after_ack":after_ack,"enabled":enabled})
        refs=report["custody_capabilities"]
        return LocalWorkerObservation(machine_id=self.profile.machine_id,uid=os.getuid(),workspace_uuid=self.profile.workspace_uuid,
          realm_root=self.profile.realm_root,support_root=self.profile.support_root,worker=worker,host=host,engine=engine,
          engine_listener=listener,engine_listener_socket_owner_pid=listener.pid,engine_endpoint=self.profile.engine_endpoint,
          session_config_digest=self.profile.session_config_digest,owner_epoch=report["owner_epoch"],
          custody_scope=report["custody_scope"],custody_capabilities=refs)


def _launch(tmp_path, *, drop_ack=False, misbind=False):
    root=tmp_path.resolve(); profile=_fixture_profile(root)
    events=root/"events.json"; observations=[]
    credentials=_ObservedCredentialStore(profile.support_root/"credentials",ack_path=events.with_suffix(".ack"),observations=observations)
    adapter=_Adapter(profile,{},events=events,drop_ack=drop_ack,misbind=misbind)
    launcher=LocalWorkerLauncher(credentials=credentials,profiles={profile.profile_id:profile},preparer=adapter,
      inspector=_Inspector(profile,credentials,events,observations),workspace_uuid=profile.workspace_uuid,realm_root=profile.realm_root,
      support_root=profile.support_root,runtime_pid=os.getpid(),actor="cpu-proof",scopes=("worker:claim",))
    return launcher,credentials,adapter,events,profile


def _run_case(tmp_path, *, drop_ack=False, misbind=False):
    launcher,credentials,adapter,events,profile=_launch(tmp_path,drop_ack=drop_ack,misbind=misbind)
    result=None; initiating_error=None; shutdown_error=None; active_token_usable=False; metadata_before_shutdown=None; report_before_shutdown=None; activated_before_shutdown=False
    try:
        result=launcher.start(profile.profile_id,profile.workspace_uuid)
        metadata_before_shutdown=credentials.actor_metadata("cpu-proof")
        if metadata_before_shutdown:
            active_token_usable=credentials.load(credentials.path_for("cpu-proof").read_text().strip())["actor"]=="cpu-proof"
        report_before_shutdown=adapter.report(adapter._current)
        activated_before_shutdown=adapter._current.activated
    except Exception as exc:
        initiating_error=_bounded_error(exc,profile)
    finally:
        try:
            handles=launcher.begin_shutdown()
            launcher.finish_shutdown(handles)
        except Exception as exc:
            shutdown_error=_bounded_error(exc,profile)
        handle=adapter._current
        report=handle.report_value if handle is not None else None
        final_processes={}
        if isinstance(report,dict):
            for role,item in report.get("processes",{}).items():
                pid=item.get("pid") if isinstance(item,dict) else None
                if isinstance(pid,int): final_processes[role]={"pid":pid,"independently_absent":default_process_identity(pid) is None}
        try: host_cleanup=json.loads(events.with_suffix(".host-cleanup.json").read_text())
        except (OSError,ValueError): host_cleanup=None
        cleanup={"initiating_error":initiating_error,"shutdown_error":shutdown_error,
          "metadata_before_shutdown":metadata_before_shutdown is not None,
          "active_token_usable_before_shutdown":active_token_usable,
          "report_before_shutdown":report_before_shutdown is not None,
          "activated_before_shutdown":activated_before_shutdown,
          "adapter_abort":getattr(adapter,"cleanup_evidence",None),"host_cleanup":host_cleanup,
          "final_process_observation":final_processes,
          "runtime_control_descriptor_closed":bool(handle and handle.control.closed and handle.control.fileno()==-1),
          "credentials_enabled":credentials.actor_metadata("cpu-proof") is not None}
        cleanup["cleanup_proven"]=bool(
          shutdown_error is None and cleanup["adapter_abort"] is not None and
          cleanup["adapter_abort"].get("relay_process_absent") and
          cleanup["adapter_abort"].get("runtime_control_descriptor_closed") and
          all(item["independently_absent"] for item in final_processes.values()) and
          host_cleanup is not None and host_cleanup.get("control_descriptor_closed") and
          host_cleanup.get("activation_descriptor_closed") and host_cleanup.get("independent_process_absent"))
        _record_phase(events,".case-cleanup.json","scenario_cleanup",cleanup)
    return {"launcher":launcher,"credentials":credentials,"adapter":adapter,"events":events,
      "profile":profile,"result":result,"initiating_error":initiating_error,"cleanup":cleanup}


def test_runtime_relay_to_committed_generic_host_activation_receiver_cpu(tmp_path):
    main=_run_case(tmp_path)
    launcher=main["launcher"]; credentials=main["credentials"]; adapter=main["adapter"]; events=main["events"]
    assert main["initiating_error"] is None, f"launch failed after cleanup: {main['initiating_error']}"
    assert main["result"]["state"]=="active"
    assert main["cleanup"]["cleanup_proven"], f"cleanup evidence incomplete: {main['cleanup']}"
    record=json.loads((Path(adapter._current.custody_scope)/"activation-record.json").read_text())
    ack=json.loads(events.with_suffix(".ack").read_text()); accepted=json.loads(_wait_for(events).read_text())
    assert record["state"]=="recorded"
    assert record["receipt"]["grant"]["activation_id"]==ack["activation_id"]==accepted["activation_id"]
    assert record["receipt"]["host"]==ack["host"]=={"pid":accepted["host_pid"],"birth_id":accepted["host_birth_id"]}
    assert events.with_suffix(".receipt-forwarded").is_file() and events.with_suffix(".eof-accepted").is_file()
    assert main["cleanup"]["metadata_before_shutdown"] and main["cleanup"]["active_token_usable_before_shutdown"]
    assert main["cleanup"]["report_before_shutdown"] and main["cleanup"]["activated_before_shutdown"]
    assert credentials.actor_metadata("cpu-proof") is None
    astrid_modules=json.loads(_wait_for(events.with_suffix(".modules.json")).read_text())
    assert astrid_modules["astrid.core.execution.generic_host"]=={
      "path":str(ASTRID_ROOT/"astrid/core/execution/generic_host.py"),
      "sha256":"3796a2131adc4c1431b65e89446be9fe83fd627e2a131b63adf39d1990901a29"}
    assert astrid_modules["astrid.core.execution.custody_broker"]=={
      "path":str(ASTRID_ROOT/"astrid/core/execution/custody_broker.py"),
      "sha256":"71f2520156e77cab2570680b1f500f91ac5ec3b3fdefa87246658a111b976d4f"}
    runtime_modules=json.loads(_wait_for(events.with_suffix(".runtime-modules.json")).read_text())
    for module,relative,digest in (
      ("runtime_protocol.local_worker","runtime_protocol/local_worker.py","11d3bbb3a36869aa9bbc86400d18e3b718d429f91bb7ce98c8cf233b415b0beb"),
      ("runtime_protocol.local_worker_composition","runtime_protocol/local_worker_composition.py","e87fd4f7439bd48e86e0e2e390f983c2ec042e81323eaa750758d28d2820d656"),
      ("runtime_protocol.local_execution_supervisor","runtime_protocol/local_execution_supervisor.py","bd6dd65d29565c2b631a8cf32701988db081d798bc2c4a81bffeba06fb345e4a"),
      ("runtime_protocol.errors","runtime_protocol/errors.py","3d4287e17e0b9ad4c17b296b2f444120eb5c1efd6a3479b09060eee1c5ec9e71")):
        assert runtime_modules[module]=={"path":str(RUNTIME_ROOT/relative),"sha256":digest}
    assert runtime_modules["banodoco_local.custody_broker"]=={
      "path":str(RUNTIME_ROOT/"banodoco_local/custody_broker.py"),
      "sha256":"f2a0b4f54be140616df6cd31f91f0b4958c120cb89e0e7eea35bdc43c286b7d6"}
    phases=[json.loads(events.with_suffix(suffix).read_text()) for suffix in
      (".request.json",".publication.json",".forwarding.json",".half-close.json",".ack.json",".outer-activation-response.json")]
    assert [item["stage"] for item in phases]==[
      "astrid_activation_request","runtime_durable_publication","astrid_receipt_forwarding",
      "activation_half_close_completed","astrid_activation_ack","runtime_outer_response"]
    assert [item["monotonic_ns"] for item in phases]==sorted(item["monotonic_ns"] for item in phases)
    assert phases[5]["status"]=="ok"
    returned=json.loads(events.with_suffix(".receiver-returned.json").read_text())
    for key in ("operation_id","channel_id","activation_id","executor_incarnation","evidence_digest"):
        assert returned[key]==ack.get(key,record["receipt"].get(key,record["receipt"]["grant"].get(key)))
    assert returned["host_pid"]==ack["host"]["pid"] and returned["host_birth_id"]==ack["host"]["birth_id"]
    assert returned["interpreter"]==str(ASTRID_PYTHON)
    assert returned["wrapper_sha256"]==hashlib.sha256(_ASTRID_RECEIVER.encode()).hexdigest()
    assert returned["generic_host_source"]==str(ASTRID_ROOT/"astrid/core/execution/generic_host.py")
    assert returned["generic_host_sha256"]=="3796a2131adc4c1431b65e89446be9fe83fd627e2a131b63adf39d1990901a29"
    assert accepted["wrapper_sha256"]==hashlib.sha256(_ASTRID_RECEIVER.encode()).hexdigest()
    assert Path(accepted["wrapper_path"]).read_bytes()==_ASTRID_RECEIVER.encode()
    assert _wait_for(events.with_suffix(".relay-wrapper.txt")).read_text().startswith("from tests.test_astrid_activation_join import _serve_test_relay;")
    assert accepted["interpreter"]==str(ASTRID_PYTHON)

    lost_root=tmp_path/"lost-ack"
    lost_root.mkdir()
    lost=_run_case(lost_root,drop_ack=True)
    lost_credentials=lost["credentials"]; lost_adapter=lost["adapter"]; lost_events=lost["events"]
    assert lost["initiating_error"] is not None
    assert lost["cleanup"]["cleanup_proven"], f"lost-ACK cleanup incomplete: {lost['cleanup']}"
    lost_record=Path(lost_adapter._current.custody_scope)/"activation-record.json"
    assert lost_record.is_file() and json.loads(lost_record.read_text())["state"]=="recorded"
    assert lost_events.with_suffix(".ack").is_file()
    assert lost_adapter._current.worker.poll() is not None
    assert lost_adapter._current.cleanup_result["host_result"]["status"]=="cleaned"
    assert lost_credentials.actor_metadata("cpu-proof") is None
    for role in ("host","engine","engine_listener"):
        pid=lost_adapter._current.report_value["processes"][role]["pid"]
        assert default_process_identity(pid) is None, f"lost-ACK {role} process remained"

    wrong_root=tmp_path/"wrong-binding"
    wrong_root.mkdir()
    wrong=_run_case(wrong_root,misbind=True)
    wrong_credentials=wrong["credentials"]; wrong_adapter=wrong["adapter"]; wrong_events=wrong["events"]
    assert wrong["initiating_error"] is not None
    assert wrong["cleanup"]["cleanup_proven"], f"rejected-binding cleanup incomplete: {wrong['cleanup']}"
    wrong_record=Path(wrong_adapter._current.custody_scope)/"activation-record.json"
    assert not wrong_record.exists()
    assert wrong_events.with_suffix(".rejected").is_file()
    assert not wrong_events.with_suffix(".ack").exists()
    assert wrong_adapter._current.worker.poll() is not None
    assert wrong_adapter._current.cleanup_result["host_result"]["status"]=="cleaned"
    assert wrong_credentials.actor_metadata("cpu-proof") is None
    for role in ("host","engine","engine_listener"):
        pid=wrong_adapter._current.report_value["processes"][role]["pid"]
        assert default_process_identity(pid) is None, f"rejected-binding {role} process remained"


# Joined contract proof substitutions are explicit and confined to this harness.
# These are NOT kernel audit tokens or authenticated native Runtime migration.
# All producer validators, protected journals, role designation/transfer, actual
# HTTP credential admission, canonical registration and fence release stay real.
_JOIN_SUBSTITUTIONS = {
    "kernel_identity": "Synthetic audit words/hash/pidversion over observed live fixture birth/uid; actual native token identity is unproven",
    "current_actor": "CPU current-actor provider selects A or separately retained B fixture process; B is not a second running Runtime daemon",
    "peer_actor": "CPU provider binds each explicitly selected original/fresh/host channel to fixture launch identity; native peer credentials are not claimed",
    "profile_graph": "Synthetic selected Vibe/profile/readiness and empty capability pack with disposable sleeping engine/listener",
    "runtime_transition": "One real canonical service and HTTP server changes its advertised A/B instance; no installed daemon restart is qualified",
    "watcher_schedule": "_JoinedProtocolLauncher._start_watcher suppresses only background scheduling; A retirement/background watcher behavior/native-installed recovery are unproven",
    "cleanup": "Only retained Popen terminate/kill/wait; native role-capability signaling is not exercised",
}

_JOIN_PINS = {
    "runtime_protocol/local_execution_handoff.py": "42956a5e0978ea100715ae6dcc5a9114b9ab9594baab2a106456dd643799bdf0",
    "runtime_protocol/daemon.py": "8626c04257f158d7df0a8b2a13991a89a21e3a29651839bbfc5c98dacfd1a57b",
    "runtime_protocol/local_worker.py": "ea54b20b9a755e89c83081707c38ccdea316adc80bea803764c1189c2ea570a8",
    "runtime_protocol/local_worker_composition.py": "0537009aa2baf7f1d673c0c6f9898dc3578ed4ad100e088a700fca81d828c2f2",
    "runtime_protocol/local_execution_supervisor.py": "f1b376dc6a42d4239a3d88999cbe8e9f24d91c934e0b0961fb8447d1a8e18dd9",
    "runtime_protocol/local_worker_handoff.py": "6ba6df2e4232d9be0977ddc0e8e6acd2fdd0036ecbef924ad3eb20e921a12209",
    "runtime_protocol/service.py": "12f0ead81c632fb145374258096d30299e1f5e0ec24acd5926e220d0bcc6288e",
    "runtime_protocol/auth.py": "003bf4babf911f92a77feed9ad6731d26946863e8e3116d7995e9f4ba86739c2",
    "runtime_protocol/store.py": "348f78e1adebd2ef034edb86a33a303ca56ada3518605b239eb4f567bda7f138",
    "banodoco_local/custody_broker.py": "f2a0b4f54be140616df6cd31f91f0b4958c120cb89e0e7eea35bdc43c286b7d6",
}
_JOIN_ASTRID_PINS = {
    "astrid/core/execution/generic_host.py": "7fa3bcf80eaa1cb308e18396a177bb0e4592da7333509f0e826c458bc4db7c8d",
    "astrid/core/execution/custody_broker.py": "71f2520156e77cab2570680b1f500f91ac5ec3b3fdefa87246658a111b976d4f",
    "astrid/sdk/host_bootstrap.py": "317f3f942d914ff6cf39177d846f84d2239e654642034a8ae4297b822af6eed6",
}


def _join_token(pid):
    """Explicit CPU token provider, always bound to a live observed fixture."""
    import struct
    identity = default_process_identity(pid)
    if identity is None:
        raise RelayError("CPU fixture incarnation is no longer observable")
    words = [identity["uid"], 0, 0, 0, 0, pid, 0, pid + 1]
    return {"pid": pid, "uid": identity["uid"], "pidversion": pid + 1,
            "sha256": "sha256:" + hashlib.sha256(struct.pack("=8I", *words)).hexdigest(), "words": words}


def _join_actor(custody, pid):
    return custody.AuthenticatedCleanupActor(lambda: _join_token(pid), default_process_identity)


def _install_join_providers(custody, *, current_pid, peer_pid, patch=None):
    """Replace only native identity providers; retain their real consumers."""
    def assign(owner, name, value):
        if patch is None: setattr(owner, name, value)
        else: patch.setattr(owner, name, value)
    def details(words):
        value = _join_token(int(words[5]))
        if list(words) != value["words"]:
            raise RelayError("CPU token words changed")
        return {k: value[k] for k in ("pid", "uid", "pidversion", "sha256")}
    assign(custody, "audit_token_details", details)
    assign(custody, "current_process_audit_token", _join_token)
    assign(custody.AuthenticatedCleanupActor, "current",
           classmethod(lambda cls, **_kwargs: _join_actor(custody, current_pid())))
    assign(custody.AuthenticatedCleanupActor, "private_peer",
           classmethod(lambda cls, channel, **_kwargs: _join_actor(custody, peer_pid(channel))))


def _join_designate(custody, scope, role, *, target_pid, owner_pid):
    authority = custody.RoleCustodyAuthority(Path(scope), role)
    actor = _join_actor(custody, owner_pid)
    identity, token = default_process_identity(target_pid), _join_token(target_pid)
    assert identity is not None
    authority.designate_pending(actor=actor, identity=identity, token=token, owner_epoch="A")
    authority.bind_target(actor=actor, generation=1, identity=identity, token=token)
    return authority.reference()


class _JoinCpuGraph:
    """Engine retains listener handle; host retains engine handle and wait."""
    def __init__(self, *, request):
        self.request = request; self.engine = None; self.refs = {}; self.cleanup = None
        self._cleanup_lock = threading.RLock(); self._cleanup_error = None

    def prepare(self):
        from astrid.core.execution import custody_broker as custody
        engine_program = (
            "import subprocess,sys,time,signal,json; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "print(child.pid,flush=True); "
            "signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));\n"
            "try: time.sleep(60)\n"
            "finally:\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            " child.terminate()\n"
            " try: code=child.wait(timeout=3)\n"
            " except subprocess.TimeoutExpired: child.kill(); code=child.wait(timeout=2)\n"
            " print(json.dumps({'listener_wait':code}),flush=True)\n"
        )
        self.engine = subprocess.Popen([sys.executable, "-c", engine_program],
                                       stdout=subprocess.PIPE, text=True, close_fds=True, start_new_session=True)
        self.listener_pid = int(self.engine.stdout.readline().strip())
        scope = self.request["custody_scope"]
        for role, pid in (("engine", self.engine.pid), ("engine_listener", self.listener_pid)):
            self.refs[role] = _join_designate(custody, scope, role, target_pid=pid, owner_pid=os.getpid())
        processes = {role: {"pid": pid, "birth_id": default_process_identity(pid)["birth_id"]}
                     for role, pid in (("host", os.getpid()), ("engine", self.engine.pid), ("engine_listener", self.listener_pid))}
        self.measured = {"processes": processes, "engine_binding": {
            "supervisor_pid": self.engine.pid, "listener_pid": self.listener_pid,
            "listener_parent_pid": self.engine.pid, "socket_owner_pid": self.listener_pid},
            "session_config_digest": self.request["profile"]["session_config_digest"],
            "custody_capabilities": self.refs}
        return self.measured

    def report(self): return self.measured
    def known_custody_capabilities(self): return self.refs

    def abort(self):
        # Host-finally and the production control thread may both arrive here.
        # Keep the single retained wait/error; a retry never repeats signaling.
        with self._cleanup_lock:
            if self.cleanup is not None: return self.cleanup
            if self._cleanup_error is not None: raise self._cleanup_error
            try:
                if self.engine is None:
                    raise RelayError("CPU engine launch/wait obligation is unresolved")
                if self.engine.poll() is None: self.engine.terminate()
                try: engine_exit = self.engine.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    self.engine.kill(); engine_exit = self.engine.wait(timeout=2)
                listener_wait = json.loads(self.engine.stdout.readline())["listener_wait"]
                self.engine.stdout.close()
                self.cleanup = {role: {"generation": ref["generation"], "target": ref["target"],
                                      "exit_code": listener_wait if role == "engine_listener" else engine_exit,
                                      "proof_kind": "retained-child-exit"} for role, ref in self.refs.items()}
                return self.cleanup
            except BaseException as exc:
                self._cleanup_error = exc
                raise


_JOINED_RECEIVER = r'''import sys
from tests.test_astrid_activation_join import _joined_host_main
_joined_host_main(sys.argv[1:])
'''


def _join_import_manifest():
    """Actual child consumption, separate from endpoint preflight provenance."""
    import sysconfig
    stdlib = Path(sysconfig.get_path("stdlib")).resolve(); result = {}
    for name, module in tuple(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if not origin: continue
        path = Path(origin).resolve()
        if not path.is_file() or (path.is_relative_to(stdlib) and "site-packages" not in path.parts): continue
        result[name] = {"origin": str(path), "sha256": _digest(path)}
    return {"actual_loaded_nonstdlib_modules": result, "interpreter": str(Path(sys.executable).resolve()),
            "interpreter_sha256": _digest(Path(sys.executable).resolve()), "version": sys.version}


def _join_exception(exc, *, secret=None):
    import traceback
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    if secret: text = text.replace(secret, "[credential-redacted]")
    return {"type": type(exc).__name__, "traceback_tail": text[-8192:]}


def _join_identity_failure(events, role, phase, expected, observed):
    _record_phase(events, ".identity-failure.json", "joined_identity_refusal", {
        "role": role, "phase": phase, "expected_identity": expected, "observed_identity": observed})


def _join_stderr(process, events, suffix):
    """Drain only currently available bytes, bounded and never awaiting EOF."""
    import select
    stream = process.stderr
    data = bytearray()
    if stream is not None and not stream.closed:
        while len(data) < 8192 and select.select([stream], [], [], 0)[0]:
            chunk = os.read(stream.fileno(), min(4096, 8192 - len(data)))
            if not chunk: break
            data.extend(chunk)
    path = events.with_suffix(suffix)
    # Keep cumulative bounded diagnostics across pre-cleanup and retained wait.
    previous = path.read_bytes() if path.is_file() else b""
    path.write_bytes((previous + bytes(data))[-8192:])
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": _digest(path)}


class _JoinedHostSession(_HostSession):
    """Joined-only serialized cleanup; old activation fixtures stay untouched."""
    def __init__(self, *args, **kwargs):
        self._cleanup_lock = threading.RLock(); self._abort_result = None
        self._abort_error = None; self._host_wait = None
        self.events = kwargs.get("events")  # Retain before fallible base setup.
        try: super().__init__(*args, **kwargs)
        except BaseException as original:
            try:
                process = getattr(self, "process", None)
                _join_identity_failure(self.events, "host", "launch_sealing",
                    {"pid": process.pid if process else None, "birth_id": getattr(self, "host_birth", None)},
                    default_process_identity(process.pid) if process else None)
                if process is not None: _join_stderr(process, self.events, ".host-stderr.txt")
            except BaseException as diagnostic:
                try: original.add_note("Joined construction diagnostic failed: " + type(diagnostic).__name__)
                except BaseException: pass
            raise  # Preserve the original construction exception.

    def verify_host(self):
        value = default_process_identity(self.process.pid)
        if self.process.poll() is not None or value is None or value["birth_id"] != self.host_birth:
            _join_identity_failure(self.events, "host", "verify_host",
                {"pid": self.process.pid, "birth_id": self.host_birth}, value)
            _join_stderr(self.process, self.events, ".host-stderr.txt")
            raise RelayError("Astrid subprocess identity changed")

    def begin_activation(self, grant):
        try: return super().begin_activation(grant)
        except BaseException as exc:
            _join_identity_failure(self.events, "host", "begin_activation",
                {"pid": self.process.pid, "birth_id": self.host_birth}, default_process_identity(self.process.pid))
            _join_stderr(self.process, self.events, ".host-stderr.txt")
            raise

    def abort(self):
        with self._cleanup_lock:
            if self._abort_result is not None: return self._abort_result
            if self._abort_error is not None: raise self._abort_error
            _join_stderr(self.process, self.events, ".host-stderr.txt")
            try:
                self._abort_result = super().abort()
                return self._abort_result
            except BaseException as exc:
                self._abort_error = exc
                _join_stderr(self.process, self.events, ".host-stderr.txt")
                raise

    def reap_host(self):
        with self._cleanup_lock:
            if self._host_wait is not None: return self._host_wait
            _join_stderr(self.process, self.events, ".host-stderr.txt")
            # The first TERM starts the child's outer finally; its handler then
            # ignores repeats. No other reaper/signal path exists in this fixture.
            self._host_wait = super().reap_host()
            _join_stderr(self.process, self.events, ".host-stderr.txt")
            self.process.stderr.close()
            return self._host_wait


def _joined_host_main(argv):
    import signal
    control_fd, activation_fd = map(int, argv[:2])
    operation, channel, credential_file, scope, config_path = argv[2:]
    config = json.loads(Path(config_path).read_text()); events = Path(config["events"])
    prep = control_thread = control_identity = None; token = None
    cleanup = {"status": "unresolved", "errors": []}
    phase = "host_setup"
    try:
        from astrid.core.execution import generic_host as host_module
        from astrid.core.execution import custody_broker as custody
        from banodoco_workspace_client import ApiError
        control_stat = os.fstat(control_fd)
        control_identity = (control_stat.st_dev, control_stat.st_ino)
        _install_join_providers(custody, current_pid=os.getpid, peer_pid=lambda _sock: os.getppid())
        prep = host_module.LocalExecutionPreparation(operation_id=operation, channel_id=channel, graph_factory=_JoinCpuGraph)
        metrics = {"gate_openings": 0, "registration_publications": 0, "dispatch_calls": {}}
        original_dispatch = prep.dispatch
        def observed_dispatch(request):
            owner = prep._claim_host
            before = owner.handoff_quiescence() if owner is not None else None
            reply = original_dispatch(request)
            after = owner.handoff_quiescence() if owner is not None else None
            command = request.get("command", "unknown")
            metrics["dispatch_calls"][command] = metrics["dispatch_calls"].get(command, 0) + 1
            if before and after and before["claim_gate_closed"] and not after["claim_gate_closed"]:
                metrics["gate_openings"] += 1
            events.with_suffix(".host-metrics.json").write_text(json.dumps(metrics, sort_keys=True))
            _record_phase(events, ".host-phase.json", "actual_host_dispatch", {"command": command, "reply": reply, "before": before, "after": after})
            return reply
        prep.dispatch = observed_dispatch  # Passive observer, preserves actual receiver/ACK.
        control_thread = prep.serve_control(control_fd)
        def stop(_sig, _frame):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop)
        phase = "activation"
        grant = host_module._await_worker_activation(activation_fd, operation_id=operation, channel_id=channel,
                                                     credential_file=credential_file, timeout_seconds=15, require_receipt=True)
        prep.retain_activation_grant(grant)
        token = Path(credential_file).read_text().strip()
        client = host_module.RuntimeProtocolClient(config["runtime_endpoint"], token, timeout=3)
        phase = "credential_readiness"
        deadline = time.monotonic() + 5
        while True:
            try: client._authenticate_worker("astrid-pack-host"); break
            except ApiError as exc:
                if exc.status != 401 or exc.code != "unauthorized" or time.monotonic() >= deadline: raise
                time.sleep(.01)
        host = host_module.GenericPackHost(pack_roots=[], client=client)
        host.source_epoch = "joined-empty-pack-source"
        record = SimpleNamespace(id="cpu-cap", capability_digest="sha256:" + "d" * 64,
                                 source_digest="e" * 64, dependency_digest="f" * 64,
                                 matrix={}, ready=True, resource_keys=(), estimated_scratch_bytes=0,
                                 estimated_output_bytes=0, manifest=lambda: {"id": "cpu-cap", "ready": True})
        host.capabilities = {record.id: record}
        host.discover = lambda: None  # Named synthetic empty pack/readiness, not registration.
        host.preflight = lambda: [record]
        host.execution_policy = SimpleNamespace(assert_budget_available=lambda: None)
        host_module._registration_verified_facts = lambda: []
        original_executor_rpc = client.register_executor
        def observe_executor_rpc(*args, **kwargs):
            _record_phase(events, ".registration-rpc.json", "actual_registration_rpc", {
                "quiescence": host.handoff_quiescence(), "fence_exists": (Path(scope).parent.parent / "local-execution-claim-fence.json").is_file()})
            return original_executor_rpc(*args, **kwargs)
        client.register_executor = observe_executor_rpc
        original_end = host._handoff_end_registration
        def observed_end():
            original_end(); metrics["registration_publications"] += 1
            events.with_suffix(".host-metrics.json").write_text(json.dumps(metrics, sort_keys=True))
        host._handoff_end_registration = observed_end
        prep.attach_claim_host(host)
        phase = "initial_registration"
        host.register()
        phase = "claim_loop"
        events.with_suffix(".claim-owner-ready.json").write_text(json.dumps({"host": os.getpid(), "registered": host._registered_runtime_state}))
        claim_probe = events.with_suffix(".probe-closed-claim.json")
        claim_probed = False
        while True:
            if claim_probe.is_file() and not claim_probed:
                before = host.handoff_quiescence()
                returned = host.claim_once()
                _record_phase(events, ".closed-claim-result.json", "actual_host_claim_once", {
                    "before": before, "after": host.handoff_quiescence(), "returned_none": returned is None})
                claim_probed = True
            time.sleep(.02)
    except BaseException as exc:
        # Save the original host failure before any graph/descriptor teardown.
        cleanup["original_host_exception"] = _join_exception(exc, secret=token)
        cleanup["failed_phase"] = phase
        events.with_suffix(".host-exception.json").write_text(json.dumps({
            "phase": phase, "role": "host", "expected_identity": {"pid": os.getpid()},
            "observed_identity": default_process_identity(os.getpid()),
            "exception": cleanup["original_host_exception"]}, sort_keys=True))
        raise
    finally:
        # Repeated TERM cannot interrupt publication of the original error/waits.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            if prep is not None:
                try:
                    cleanup["abort"] = prep.abort()
                    cleanup["retained_graph_waits"] = prep.graph.cleanup if prep.graph else None
                    cleanup["status"] = "cleaned"
                except BaseException as exc:
                    cleanup["errors"].append(_join_exception(exc, secret=token))
            if control_identity is not None:
                try:
                    current_stat = os.fstat(control_fd)
                    if (current_stat.st_dev, current_stat.st_ino) != control_identity:
                        _join_identity_failure(events, "host", "control_cleanup", control_identity,
                                               (current_stat.st_dev, current_stat.st_ino))
                        raise RelayError("owned control descriptor identity changed")
                    wakeup = socket.socket(fileno=os.dup(control_fd))
                    try: wakeup.shutdown(socket.SHUT_RDWR)
                    finally: wakeup.close()
                except OSError: pass
            if control_thread is not None: control_thread.join(1)
            cleanup["control_thread_stopped"] = control_thread is not None and not control_thread.is_alive()
            if prep is not None and prep._handoff_lock_fd is not None:
                os.close(prep._handoff_lock_fd); prep._handoff_lock_fd = None
            # Activation consumer owns/closes its socket; never close a reused fd.
            cleanup["closed_fds"] = {"control": cleanup["control_thread_stopped"],
                                     "activation": phase != "host_setup", "handoff_lock": prep is not None and prep._handoff_lock_fd is None}
            cleanup["actual_imports"] = _join_import_manifest()
        except BaseException as exc:
            cleanup["errors"].append(_join_exception(exc, secret=token))
        finally:
            if cleanup["errors"] or not cleanup.get("control_thread_stopped"):
                cleanup["status"] = "unresolved"
            # Outermost cleanup publication survives errors in cleanup itself.
            events.with_suffix(".receiver-cleanup.json").write_text(json.dumps(cleanup, sort_keys=True))


def _serve_joined_relay(descriptor, events_value, config_value):
    import signal
    from banodoco_local import custody_broker as custody
    from runtime_protocol import local_execution_supervisor as supervisor
    from runtime_protocol.local_worker_handoff import HandoffSuccessorListener
    channel = socket.socket(fileno=descriptor); channel.settimeout(15)
    events = Path(events_value); config = json.loads(Path(config_value).read_text())
    _install_join_providers(custody, current_pid=os.getpid,
        peer_pid=lambda sock: config["source_pid"] if sock.fileno() == channel.fileno() else config["successor_pid"])
    state = {}; accepted = []
    original_endpoint = supervisor._native_handoff_endpoint
    def observed_endpoint(*args, **kwargs):
        endpoint = original_endpoint(*args, **kwargs); state["endpoint"] = endpoint; return endpoint
    supervisor._native_handoff_endpoint = observed_endpoint
    original_accept = HandoffSuccessorListener.accept
    def observed_accept(listener):
        peer, request = original_accept(listener); accepted.append(peer.channel); return peer, request
    HandoffSuccessorListener.accept = observed_accept
    def factory(preparation, launch_config, *, retain):
        session = _JoinedHostSession.__new__(_JoinedHostSession)
        state["session"] = session; retain(session)
        session.__init__(preparation, preparation["profile"], launch_config, events=events, drop_ack=False,
            receiver_program=_JOINED_RECEIVER, receiver_config={"runtime_endpoint": config["runtime_endpoint"]},
            credential_actor="astrid-pack-host")
        _join_designate(custody, preparation["custody_scope"], "host", target_pid=session.process.pid, owner_pid=os.getpid())
        return session
    def stop(_sig, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    try:
        supervisor.serve_control(channel, session_factory=factory)
    except RelayError as exc:
        if "closed" not in str(exc): raise
    except BaseException as exc:
        events.with_suffix(".relay-exception.json").write_text(json.dumps(_join_exception(exc), sort_keys=True))
        raise
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        cleanup = {"stage": "relay_finally", "errors": []}
        session = state.get("session")
        if session:
            try: cleanup["graph_abort"] = session.abort()
            except BaseException as exc: cleanup["errors"].append(type(exc).__name__)
            try: cleanup["host_retained_wait"] = session.reap_host()
            except BaseException as exc: cleanup["errors"].append(type(exc).__name__)
        endpoint = state.get("endpoint")
        listener = endpoint.successor_listener if endpoint else None
        if listener: listener.close()
        for sock in [channel, *accepted]: sock.close()
        cleanup["control_fds_closed"] = all(sock.fileno() == -1 for sock in [channel, *accepted])
        cleanup["listener_closed"] = listener is None or listener.closed
        cleanup["actual_imports"] = _join_import_manifest()
        events.with_suffix(".relay-finally.json").write_text(json.dumps(cleanup, sort_keys=True))


class _JoinedRetainedRelay(_RetainedRelay):
    """Retain the already owned child before any fallible identity observation."""
    def __init__(self, child, *, events):
        self.child = child; self.pid = child.pid; self.events = events
        self._identity = None; self._guard = threading.RLock()

    def pin(self, observed):
        with self._guard:
            identity = {key: observed[key] for key in ("pid", "uid", "birth_id")}
            if identity["pid"] != self.child.pid or self._identity is not None:
                raise RelayError("owned joined relay launch identity cannot be repinned")
            self._identity = identity

    def poll(self):
        with self._guard:
            return self.child.poll()  # Actual retained child exit state, never fabricated alive.

    def verify(self):
        with self._guard:
            exit_code = self.child.poll()
            observed = default_process_identity(self.child.pid)
            expected = self._identity
            if (expected is None or exit_code is not None or observed is None
                    or any(observed.get(key) != expected[key] for key in ("pid", "uid", "birth_id"))):
                try:
                    _join_identity_failure(self.events, "relay", "retained_verify", expected,
                                           {"identity": observed, "retained_exit_code": exit_code})
                except BaseException: pass  # Diagnostics cannot replace the refusal.
                raise RelayError("owned joined relay is exited, absent, unpinned or changed")
            return observed


class _JoinedAdapter(_Adapter):
    def __init__(self, profile, *, events, endpoint, successor):
        super().__init__(profile, {}, events=events)
        self.endpoint, self.successor = endpoint, successor

    def prepare(self, profile, *, operation_id, channel_id):
        from banodoco_local import custody_broker as custody
        from runtime_protocol.local_execution_supervisor import host_prepare_request
        runtime_end, relay_end = socket.socketpair(); runtime_end.settimeout(5)
        scope = profile.support_root / "custody" / operation_id; scope.mkdir(parents=True, mode=0o700); scope.chmod(0o700)
        source = default_process_identity(os.getpid())
        preparation = host_prepare_request(operation_id=operation_id, channel_id=channel_id, owner_epoch="A",
            runtime_owner={"pid": source["pid"], "uid": source["uid"], "birth_id": source["birth_id"],
                           "runtime_instance_id": "A", "coordinator_epoch": "A"},
            profile=_selected_profile_payload(profile), custody_scope=str(scope))
        config_file = self.events.parent / "joined-relay-config.json"
        config_file.write_text(json.dumps({"source_pid": os.getpid(), "successor_pid": self.successor.pid,
                                          "runtime_endpoint": self.endpoint}))
        wrapper = "from tests.test_astrid_activation_join import _serve_joined_relay; import sys; _serve_joined_relay(int(sys.argv[1]),sys.argv[2],sys.argv[3])"
        self.events.with_suffix(".relay-wrapper.txt").write_text(wrapper)
        env = dict(os.environ); env["PYTHONPATH"] = str(RUNTIME_ROOT) + os.pathsep + str(ASTRID_ROOT)
        process = subprocess.Popen([str(ASTRID_PYTHON), "-c", wrapper, str(relay_end.fileno()), str(self.events), str(config_file)],
            cwd=RUNTIME_ROOT, env=env, pass_fds=(relay_end.fileno(),), close_fds=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
        relay_end.close()
        # Retain the launch before any fallible seal/report RPC.
        handle = SimpleNamespace(worker=process, control=_ObservedChannel(runtime_end, self.events), rpc_lock=threading.RLock(),
            relay=True, closed=False, activated=False, retained=_JoinedRetainedRelay(process, events=self.events), owner_epoch="A",
            custody_scope=str(scope), preparation=preparation, report_value=None)
        self._active = self._current = handle
        identity = default_process_identity(process.pid)
        if identity is None:
            _join_identity_failure(self.events, "relay", "prepare", {"pid": process.pid}, identity)
            _join_stderr(process, self.events, ".relay-stderr.txt")
            raise RelayError("owned CPU relay identity unresolved")
        handle.retained.pin(identity)
        handle.birth_id = identity["birth_id"]
        _join_designate(custody, scope, "relay", target_pid=process.pid, owner_pid=os.getpid())
        send_frame(runtime_end, {"version": RELAY_VERSION, "command": "prepare", "preparation": preparation, "config": {}})
        response = receive_frame(runtime_end)
        if response.get("status") != "ok": raise RelayError("joined CPU preparation unresolved")
        handle.report_value = response["report"]
        return handle


class _JoinedInspector(_Inspector):
    active_observation = False

    def observe(self, handle):
        report = handle.report_value
        def proc(role):
            item = report["processes"][role]; fact = default_process_identity(item["pid"])
            if fact is None or fact["birth_id"] != item["birth_id"]:
                _join_identity_failure(self.events, role, "independent_observation", item, fact)
                _join_stderr(handle.worker, self.events, ".relay-stderr.txt")
                raise RelayError("joined child incarnation changed")
            executable = _actual_executable(item["pid"])
            return ProcessIdentity(pid=item["pid"], birth_id=item["birth_id"], uid=fact["uid"], parent_pid=fact["parent_pid"],
                process_group=os.getpgid(item["pid"]), session_id=os.getsid(item["pid"]), executable=executable, artifact_digest=_file_digest(executable))
        worker, host, engine, listener = (proc(role) for role in ("worker", "host", "engine", "engine_listener"))
        token_path = self.credentials.path_for("astrid-pack-host"); enabled = False
        if token_path.is_file():
            try: self.credentials.load(token_path.read_text().strip()); enabled = True
            except AuthorizationError: pass
        after_ack = self.events.with_suffix(".ack").is_file()
        if not self.active_observation: assert not enabled, "credential enabled before final post-ACK observation"
        self.observations.append({"after_ack": after_ack, "enabled": enabled})
        return LocalWorkerObservation(machine_id=self.profile.machine_id, uid=os.getuid(), workspace_uuid=self.profile.workspace_uuid,
            realm_root=self.profile.realm_root, support_root=self.profile.support_root, worker=worker, host=host, engine=engine,
            engine_listener=listener, engine_listener_socket_owner_pid=listener.pid, engine_endpoint=self.profile.engine_endpoint,
            session_config_digest=self.profile.session_config_digest, owner_epoch=report["owner_epoch"], custody_scope=report["custody_scope"],
            custody_capabilities=report["custody_capabilities"])


class _JoinedProtocolLauncher(LocalWorkerLauncher):
    """Astra-approved CPU scheduling boundary; every owner validator stays real.

    One canonical service/HTTP server represents A→B. Retained dummy B supplies
    the substituted auth identity; no second Runtime daemon starts. This proves
    joined protocol/registration/finalization/replay, not retirement, background
    liveness scheduling, native signaling or installed recovery.
    """
    def _start_watcher(self):
        # Exactly this scheduling method is suppressed, selected before launch.
        # Do not alter check_liveness, reports, identities or failure outcomes.
        return None


def test_runtime_relay_to_generic_host_successor_finalization_cpu(tmp_path, monkeypatch):
    """One joined journey, four scenarios; no ACK/journal validator substitute."""
    import copy
    from dataclasses import replace
    from banodoco_local import custody_broker as custody
    from runtime_protocol.daemon import RuntimeDaemon, WORKER_ACTOR, WORKER_SCOPES
    from runtime_protocol.errors import ConflictError
    from runtime_protocol.local_execution_handoff import VERSION, digest, read_protected
    from runtime_protocol.local_worker import _credential_commit_generation
    from runtime_protocol.local_worker_handoff import successor_authentication_digest, relay_transition_id
    from runtime_protocol.server import RuntimeHTTPServer, RuntimeHandler
    from runtime_protocol.service import RuntimeService
    from runtime_protocol.store import RealmStore
    for root, pins in ((RUNTIME_ROOT, _JOIN_PINS), (ASTRID_ROOT, _JOIN_ASTRID_PINS)):
        for path, pin in pins.items(): assert _digest(root / path) == "sha256:" + pin
    root = tmp_path.resolve(); root.chmod(0o700)
    cleanup = {"status": "unresolved", "errors": []}; final_request = None; evidence = {}; b_control = None
    service = server = server_thread = successor = adapter = credentials = preparer_b = None
    events = root / "joined-events.json"
    try:
        RealmStore.initialize(root / "realm")
        support = root / "support"; support.mkdir(mode=0o700)
        service = RuntimeService(root / "realm", support_root=support)
        daemon = RuntimeDaemon(root / "realm", support_root=support)
        daemon.service = service; daemon.instance_id = "A"
        server = RuntimeHTTPServer(("127.0.0.1", 0), RuntimeHandler)
        daemon.httpd = server; server.runtime = service; server.daemon_runtime = daemon
        events = root / "joined-events.json"; observations = []
        credentials = _ObservedCredentialStore(support / "credentials", ack_path=events.with_suffix(".ack"), observations=observations)
        daemon.credentials = credentials; server.credentials = credentials
        service.set_local_claim_generation_verifier(daemon._verify_local_claim_generation, actor=WORKER_ACTOR)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True); server_thread.start()
        successor = subprocess.Popen([str(ASTRID_PYTHON), "-c", "import time; time.sleep(60)"], close_fds=True)
        actor_state = {"pid": os.getpid()}; selected_relay = {"pid": None}
        _install_join_providers(custody, current_pid=lambda: actor_state["pid"], peer_pid=lambda _sock: selected_relay["pid"], patch=monkeypatch)
        profile = replace(_fixture_profile(root), workspace_uuid=service.realm["id"])
        adapter = _JoinedAdapter(profile, events=events, endpoint=daemon.endpoint, successor=successor)
        inspector = _JoinedInspector(profile, credentials, events, observations)
        launcher_a = _JoinedProtocolLauncher(credentials=credentials, profiles={profile.profile_id: profile}, preparer=adapter,
            inspector=inspector, workspace_uuid=profile.workspace_uuid, realm_root=profile.realm_root, support_root=profile.support_root,
            runtime_pid=os.getpid(), actor=WORKER_ACTOR, scopes=WORKER_SCOPES)
        preparer_b = CrossProcessWorkerPreparer(profile=profile, config={}, environment={}, timeout_seconds=5, cleanup_timeout_seconds=2)
        launcher_b = _JoinedProtocolLauncher(credentials=credentials, profiles={profile.profile_id: profile}, preparer=preparer_b,
            inspector=inspector, workspace_uuid=profile.workspace_uuid, realm_root=profile.realm_root, support_root=profile.support_root,
            runtime_pid=successor.pid, actor=WORKER_ACTOR, scopes=WORKER_SCOPES)
        daemon.local_worker_launcher = launcher_a
        registrations = []; original_registration = service.register_executor
        def observed_registration(body, **kwargs):
            result = original_registration(body, **kwargs)
            registrations.append({"source_epoch": body.get("source_epoch"), "runtime_instance": daemon.instance_id,
                                  "fence": copy.deepcopy(service._local_claim_fence)})
            return result
        monkeypatch.setattr(service, "register_executor", observed_registration)
        launched = launcher_a.start(profile.profile_id, profile.workspace_uuid)
        assert launched["state"] == "active"
        receipt = launcher_a.cleanup_receipt_snapshot()
        assert receipt is not None
        inspector.active_observation = True
        handle = adapter._current; selected_relay["pid"] = handle.worker.pid
        _wait_for(events.with_suffix(".claim-owner-ready.json"), 5)
        assert len(registrations) == 1
        scope = Path(handle.custody_scope); activation_before = (scope / "activation-record.json").read_bytes()
        def credential_state():
            # Existing owner path validates the full generation; never hash
            # or publish bearer bytes as a fixture identity.
            with credentials._lock:
                return {"commit_generation": _credential_commit_generation(credentials, WORKER_ACTOR),
                        "metadata_digest": digest(credentials.actor_metadata(WORKER_ACTOR))}
        credential_before = credential_state()
        identity = credentials.load(credentials.path_for(WORKER_ACTOR).read_text().strip())
        claim_body = {"executor_id": WORKER_ACTOR, "capability_ids": [], "runtime_epoch": service.health()["runtime_epoch"]}
        assert service.claim_next(claim_body, identity=identity, idempotency_key="joined-old-claim") is None
        binding = {"operation_id": handle.preparation["operation_id"], "channel_id": handle.preparation["channel_id"],
            "handoff_id": "joined-handoff", "nonce_digest": digest({"fixture_nonce": "joined"}),
            "deadline_unix_ms": time.time_ns() // 1_000_000 + 120_000, "workspace_uuid": profile.workspace_uuid,
            "profile_binding_digest": receipt["profile_binding_digest"], "launch_evidence_digest": receipt["evidence_digest"],
            "activation_record_digest": "sha256:" + hashlib.sha256(activation_before).hexdigest(),
            "executor_incarnation": receipt["executor_incarnation"], "custody_scope": str(scope),
            "original_owner_epoch": "A", "source_owner_epoch": "A", "new_owner_epoch": "B",
            "source_owner": _join_actor(custody, os.getpid()).verify(), "new_owner": _join_actor(custody, successor.pid).verify(),
            "credential_generation_digest": _credential_commit_generation(credentials, WORKER_ACTOR),
            "original_roles": receipt["custody_capabilities"], "current_roles": receipt["custody_capabilities"],
            "source_relay_reference": receipt["custody_capabilities"]["relay"]}
        binding["intent_digest"] = digest({"version": VERSION, "binding": binding})
        def request(command, payload=None): return {"version": VERSION, "command": command, "binding": binding, "payload": payload or {}}
        pause = daemon.forward_local_execution_handoff(request("handoff_prepare")); assert pause["status"] == "ok"
        fence = read_protected(service._local_claim_fence_path()); assert fence["state"] == "held"
        events.with_suffix(".probe-closed-claim.json").write_text(json.dumps({"handoff_id": binding["handoff_id"]}))
        host_claim_probe = json.loads(_wait_for(events.with_suffix(".closed-claim-result.json")).read_text())
        assert host_claim_probe["before"]["claim_gate_closed"] is True and host_claim_probe["returned_none"]
        assert host_claim_probe["before"] == host_claim_probe["after"]
        for key in ("joined-old-claim", "joined-new-claim"):
            with pytest.raises(ConflictError, match="claims are fenced"):
                service.claim_next(claim_body, identity=identity, idempotency_key=key)
        with pytest.raises(ConflictError, match="claims are fenced"):
            service.resume_attempt({"nonce": "fixture", "authorization": "fixture", "runtime_epoch": service.health()["runtime_epoch"]}, identity=identity)
        export = {"version": "runtime.local-execution-handoff-export/v1", **{k: binding[k] for k in
            ("handoff_id", "intent_digest", "nonce_digest", "credential_generation_digest", "source_owner_epoch", "source_relay_reference", "launch_evidence_digest")},
            "host_pause_ack_digest": digest(pause), "task_fence_digest": digest(fence), "descriptor_identity_digest": digest({"retained_source_fd": handle.control.fileno()})}
        seal = {"version": "runtime.local-execution-handoff-seal/v1", **{k: export[k] for k in
            ("handoff_id", "intent_digest", "nonce_digest", "credential_generation_digest", "source_owner_epoch", "source_relay_reference", "host_pause_ack_digest", "task_fence_digest")},
            "export_digest": digest(export), "target_owner_epoch": "B", "successor_incarnation": binding["new_owner"]}
        sealed = daemon.forward_local_execution_handoff(request("handoff_export_sealed", {"export_metadata": export, "seal_record": seal, "sealed_record_digest": digest(seal)}))
        assert sealed["status"] == "ok"
        ack = {"version": "runtime.role-custody-designation/v1", "transition_id": relay_transition_id(binding), "role": "relay",
            "generation": binding["source_relay_reference"]["generation"] + 1, "owner_epoch": "B", "actor": binding["new_owner"], "target": binding["source_relay_reference"]["target"]}
        adopt = request("handoff_adopt", {"export_digest": digest(export), "sealed_record_digest": digest(seal), "task_fence_digest": digest(fence),
            "relay_transfer_ack": ack, "successor_authentication_digest": successor_authentication_digest(binding, binding["new_owner"])})
        # Original A connection cannot become fresh B even with correct payload.
        assert adapter.handoff_command(handle, adopt)["status"] == "unresolved"
        actor_state["pid"] = successor.pid; daemon.instance_id = "B"; daemon.local_worker_launcher = launcher_b
        adopted = daemon.adopt_local_execution_handoff(adopt, receipt); assert adopted["status"] == "ok"
        b_control = preparer_b.adopted_handoff_obligation()
        health = service.health(); runtime = {"endpoint": daemon.endpoint, "protocol": health["protocol"], "schema_digest": health["schema_digest"],
            "runtime_epoch": health["runtime_epoch"], "runtime_session_id": service.runtime_session_id, "runtime_instance_id": "B", "coordinator_epoch": "B"}
        relay_ref = {**binding["source_relay_reference"], "generation": ack["generation"]}
        rebound = daemon.forward_local_execution_handoff(request("handoff_commit", {"new_runtime": runtime, "task_fence_digest": digest(fence), "relay_reference": relay_ref}))
        assert rebound["status"] == "ok" and rebound["quiescence"]["claim_gate_closed"] is True
        assert len(registrations) == 2 and registrations[-1]["fence"] == fence
        registration_rpc = json.loads(events.with_suffix(".registration-rpc.json").read_text())
        assert registration_rpc["quiescence"]["registration_rpc_in_flight"] == 1
        assert registration_rpc["quiescence"]["claim_gate_closed"] is True and registration_rpc["fence_exists"]
        assert read_protected(service._local_claim_fence_path()) == fence
        registered_digest = digest(rebound["registered_state"])
        for command in ("resume_prepare", "resume_commit"):
            result = daemon.forward_local_execution_handoff(request(command, {"new_runtime": runtime, "task_fence_digest": digest(fence), "registered_state_digest": registered_digest}))
            assert result["status"] == "ok" and result["quiescence"]["claim_gate_closed"] is True
            assert read_protected(service._local_claim_fence_path()) == fence
        final_request = request("handoff_finalize", {"task_fence_digest": digest(fence), "registered_state_digest": registered_digest})
        outward_observation = {}
        def deliver_final_outward(final_input, *, drop):
            actual_reply = daemon.forward_local_execution_handoff(final_input)
            actual_release = read_protected(service._local_claim_fence_path())
            assert actual_release["state"] == "released" and actual_release["release_ack_digest"] == digest(actual_reply)
            # Passive producer observer sees the ACK; the calling consumer
            # receives no result on the deliberately dropped delivery.
            outward_observation["actual_reply"] = actual_reply
            if drop:
                _record_phase(events, ".lost-outward-ack.json", "outward_ack_dropped_after_durable_release", {
                    "release_digest": digest(actual_release), "ack_digest": digest(actual_reply)})
                raise TimeoutError("fixture dropped outward ACK after durable release")
            return actual_reply
        with pytest.raises(TimeoutError, match="outward ACK"):
            deliver_final_outward(final_request, drop=True)
        final = outward_observation["actual_reply"]
        released = read_protected(service._local_claim_fence_path())
        assert final["status"] == "ok" and final["quiescence"]["claim_gate_closed"] is False
        assert released == {**fence, "state": "released", "release_ack_digest": digest(final)}
        assert read_protected(scope / "host-handoff-state.json")["reply"] == final
        for name in ("runtime", "relay"):
            state = read_protected(scope / (name + "-handoff-state.json"))
            assert state["phase"] == "finalized" and state["entries"][binding["handoff_id"] + ":handoff_finalize"]["reply"] == final
        def side_effects():
            return {"registration_calls": len(registrations), "host_metrics": json.loads(events.with_suffix(".host-metrics.json").read_text()),
                "durable_files": {name: _digest(scope / name) for name in ("host-handoff-state.json", "relay-handoff-state.json", "runtime-handoff-state.json", "designation-relay.json", "activation-record.json")},
                "fence": _digest(service._local_claim_fence_path()), "credential_state": credential_state(),
                "task_counts": {table: service.store.conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("tasks", "attempts", "reservations", "execution_bindings")}}
        before_replay = side_effects()
        assert deliver_final_outward(final_request, drop=False) == final
        assert side_effects() == before_replay
        assert before_replay["host_metrics"]["gate_openings"] == 1
        assert before_replay["host_metrics"]["registration_publications"] == 2
        assert all(count == 0 for count in before_replay["task_counts"].values())
        assert (scope / "activation-record.json").read_bytes() == activation_before
        assert credential_state() == credential_before
        assert service.claim_next(claim_body, identity=identity, idempotency_key="joined-after-release") is None
        evidence = {"pause": pause, "sealed": sealed, "adopted": adopted, "rebound": rebound, "final": final, "released": released,
                    "stable_side_effects": before_replay, "registration_observations": registrations,
                    "actual_closed_claim_probe": host_claim_probe, "actual_registration_rpc": registration_rpc}
    finally:
        # Every assertion/setup failure after retained launch still has a cleanup
        # handoff. PID absence is corroboration, never our retained wait proof.
        if adapter is not None and adapter._current is not None:
            handle = adapter._current
            cleanup["relay_stderr_before_cleanup"] = _join_stderr(handle.worker, events, ".relay-stderr.txt")
            if b_control is None and preparer_b is not None: b_control = preparer_b.adopted_handoff_obligation()
            control = b_control.control if b_control is not None else handle.control
            try:
                send_frame(control, {"version": RELAY_VERSION, "command": "abort"})
                response = receive_frame(control)
                cleanup["abort_response"] = response
                if response.get("status") != "ok": cleanup["errors"].append("abort_unresolved")
            except BaseException as exc: cleanup["errors"].append(type(exc).__name__)
            for control in (handle.control, b_control.control if b_control is not None else None):
                if control is not None: control.close()
            if handle.worker.poll() is None: handle.worker.terminate()
            try: cleanup["relay_retained_wait"] = handle.worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                handle.worker.kill(); cleanup["relay_retained_wait"] = handle.worker.wait(timeout=2)
            cleanup["runtime_control_closed"] = handle.control.fileno() == -1
            cleanup["successor_control_closed"] = b_control is None or b_control.control.fileno() == -1
            for suffix, name in ((".receiver-cleanup.json", "receiver"), (".relay-finally.json", "relay"), (".host-cleanup.json", "host"), (".host-exception.json", "original_host_exception")):
                path = events.with_suffix(suffix)
                cleanup[name] = json.loads(path.read_text()) if path.is_file() else None
            cleanup["relay_stderr_after_wait"] = _join_stderr(handle.worker, events, ".relay-stderr.txt")
            handle.worker.stderr.close()
        if successor is not None:
            if successor.poll() is None: successor.terminate()
            try: cleanup["successor_retained_wait"] = successor.wait(timeout=3)
            except subprocess.TimeoutExpired:
                successor.kill(); cleanup["successor_retained_wait"] = successor.wait(timeout=2)
        if credentials is not None:
            credentials.revoke(WORKER_ACTOR)
            cleanup["credential_removed"] = credentials.actor_metadata(WORKER_ACTOR) is None
        else: cleanup["credential_removed"] = True
        if server is not None:
            if server_thread is not None and server_thread.is_alive(): server.shutdown()
            server.server_close()
        if server_thread is not None: server_thread.join(2)
        if service is not None: service.close()
        cleanup["http_server_closed"] = (server is None or server.fileno() == -1) and (server_thread is None or not server_thread.is_alive())
        receiver_cleanup = cleanup.get("receiver") or {}
        relay_cleanup = cleanup.get("relay") or {}
        host_cleanup = cleanup.get("host") or {}
        cleanup["status"] = "cleaned" if (not cleanup["errors"] and receiver_cleanup.get("status") == "cleaned"
            and receiver_cleanup.get("control_thread_stopped") and all(receiver_cleanup.get("closed_fds", {}).values())
            and receiver_cleanup.get("retained_graph_waits") is not None and not relay_cleanup.get("errors")
            and relay_cleanup.get("control_fds_closed") and relay_cleanup.get("listener_closed")
            and host_cleanup.get("control_descriptor_closed") and host_cleanup.get("activation_descriptor_closed")
            and cleanup.get("runtime_control_closed") and cleanup.get("successor_control_closed") and cleanup["credential_removed"] and cleanup["http_server_closed"]) else "unresolved"
        events.with_suffix(".joined-proof-manifest.json").write_text(json.dumps({"substitutions": _JOIN_SUBSTITUTIONS,
            "runtime_pins": _JOIN_PINS, "astrid_pins": _JOIN_ASTRID_PINS, "harness_sha256": _digest(Path(__file__)),
            "receiver_wrapper_sha256": "sha256:" + hashlib.sha256(_JOINED_RECEIVER.encode()).hexdigest(),
            "evidence": evidence, "cleanup": cleanup}, sort_keys=True))
    assert cleanup["status"] == "cleaned", cleanup
