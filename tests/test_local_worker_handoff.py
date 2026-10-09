"""Bounded native peer proof and CPU-only durable-transfer protocol proof.

No engine, provider, task execution, nonchild exit or joined takeover claim.
The first two containers deliberately require the real Darwin primitive.
"""
import array
import copy
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys

import pytest

from banodoco_local import custody_broker as custody
from runtime_protocol import local_worker_handoff as handoff
from runtime_protocol.errors import ConflictError
from runtime_protocol.local_execution_handoff import (
    VERSION, HandoffJournal, digest, read_protected, write_protected,
)
from test_local_execution_supervisor import _handoff_case


CHILD = r'''
import json, socket, sys
from banodoco_local.custody_broker import AuthenticatedCleanupActor
from runtime_protocol.local_worker_handoff import connect_fresh_successor, send_frame
actor = AuthenticatedCleanupActor.current().verify()
print(json.dumps(actor), flush=True)
line = sys.stdin.readline()
if not line:
    sys.exit(0)
data = json.loads(line)
if data['mode'] == 'inherited':
    channel = socket.socket(fileno=data['fd'])
else:
    channel, relay = connect_fresh_successor(data['binding'], data['seal'], timeout=4)
channel.settimeout(4)
try:
    send_frame(channel, data['frame'])
    try:
        channel.recv(1)
    except (TimeoutError, ConnectionResetError):
        pass
finally:
    channel.close()
'''


def _child(*, pass_fds=()):
    child = subprocess.Popen([sys.executable, '-c', CHILD], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, pass_fds=pass_fds)
    assert select.select([child.stdout], [], [], 8)[0], 'native actor startup timed out'
    line = child.stdout.readline()
    if not line:
        child.wait(timeout=8)
        pytest.fail('native kernel identity unavailable: ' + child.stderr.read())
    return child, json.loads(line)


def _reap(child):
    child.stdin.close()
    # This directly owned disposable child has a finite socket deadline.
    # No numeric signal or nonchild death inference is used.
    assert child.wait(timeout=10) == 0, child.stderr.read()
    child.stdout.close(); child.stderr.close()


def _adoption(binding, *, seal='sha256:' + '2' * 64):
    ack = {'version': 'runtime.role-custody-designation/v1',
           'transition_id': handoff.relay_transition_id(binding), 'role': 'relay',
           'generation': binding['source_relay_reference']['generation'] + 1,
           'owner_epoch': binding['new_owner_epoch'], 'actor': binding['new_owner'],
           'target': binding['source_relay_reference']['target']}
    return {'version': VERSION, 'command': 'handoff_adopt', 'binding': binding,
            'payload': {'export_digest': 'sha256:' + '1' * 64,
                        'sealed_record_digest': seal, 'task_fence_digest': 'sha256:' + '3' * 64,
                        'relay_transfer_ack': ack,
                        'successor_authentication_digest': handoff.successor_authentication_digest(binding, binding['new_owner'])}}


def _repin_intent(binding):
    binding['intent_digest'] = digest({'version': VERSION, 'binding': {k: v for k, v in binding.items() if k != 'intent_digest'}})


@pytest.mark.parametrize('mismatch', ['none', 'incarnation', 'operation'])
def test_fresh_successor_peer_binds_exact_incarnation_and_operation(tmp_path, mismatch):
    """Real post-exec B connection; same UID is insufficient authority."""
    parent = custody.AuthenticatedCleanupActor.current().verify()
    child, actor = _child()
    listener = peer = None
    try:
        request, _ = _handoff_case(tmp_path)
        b = request['binding']; b['source_owner'] = parent; b['new_owner'] = actor
        b['source_relay_reference']['target'] = parent
        b['original_roles']['relay']['target'] = parent
        _repin_intent(b)
        adoption = _adoption(b); seal = adoption['payload']['sealed_record_digest']
        listener = handoff.HandoffSuccessorListener(b, seal, timeout=4)
        wire = copy.deepcopy(adoption)
        if mismatch == 'incarnation':
            wire['binding']['new_owner']['birth_id'] += '-wrong'
            _repin_intent(wire['binding'])
        elif mismatch == 'operation':
            wire['binding']['operation_id'] += '-wrong'
            _repin_intent(wire['binding'])
        child.stdin.write(json.dumps({'mode': 'fresh', 'binding': b, 'seal': seal,
                                    'frame': {'version': 'runtime.local-execution-control/v1', 'command': 'handoff', 'request': wire}}) + '\n')
        child.stdin.flush()
        if mismatch == 'none':
            peer, frame = listener.accept()
            assert peer.actor.verify() == actor
            assert peer.verify(frame['request']) == actor
            assert peer.channel.get_inheritable() is False
            peer.channel.close(); peer = None
        else:
            with pytest.raises(ConflictError):
                listener.accept()
    finally:
        if peer is not None:
            peer.channel.close()
        if listener is not None:
            listener.close()
        _reap(child)


def test_inherited_creator_descriptor_cannot_authenticate_successor(tmp_path):
    from runtime_protocol.local_execution_supervisor import RelayHandoffEndpoint
    parent_actor = custody.AuthenticatedCleanupActor.current()
    parent = parent_actor.verify()
    source, inherited = socket.socketpair()
    child, actor = _child(pass_fds=(inherited.fileno(),))
    try:
        request, reply = _handoff_case(tmp_path)
        b = request['binding']; b.update(source_owner=parent, new_owner=actor)
        designation = custody.RoleCustodyAuthority(Path(b['custody_scope']), 'relay')
        identity = custody.default_process_identity(parent['pid'])
        token = custody.current_process_audit_token(parent['pid'])
        designation.designate_pending(actor=parent_actor, identity=identity, token=token, owner_epoch='A')
        designation.bind_target(actor=parent_actor, generation=1, identity=identity, token=token)
        b['source_relay_reference'] = designation.reference()
        b['current_roles']['relay'] = designation.reference()
        b['original_roles']['relay'] = designation.reference()
        _repin_intent(b)
        journal = HandoffJournal(tmp_path / 'custody' / 'original-channel-state.json',
                                 writer=parent, owner_epoch='A',
                                 authority=lambda: designation.verify_reference(b['source_relay_reference'], expected_actor=parent, owner_epoch='A'))
        reply.update(binding_digest=digest(b), request_digest=digest(request), custody_capabilities=b['current_roles'])
        journal.begin(request); journal.finish(request, reply)
        fence_path = tmp_path / 'custody' / 'original-channel-fence.json'
        write_protected(fence_path, {'version': 'runtime.local-execution-claim-fence/v1', 'state': 'held',
                        **{k: b[k] for k in ('workspace_uuid', 'executor_incarnation', 'credential_generation_digest', 'operation_id', 'handoff_id', 'intent_digest', 'source_owner_epoch')},
                        'target_owner_epoch': 'B', 'fence_generation': 1, 'release_ack_digest': None})
        protected = {path: path.read_bytes() for path in (journal.path, designation.path, fence_path)}
        adoption = _adoption(b)
        child.stdin.write(json.dumps({'mode': 'inherited', 'fd': inherited.fileno(),
                                    'frame': {'version': 'runtime.local-execution-control/v1', 'command': 'handoff', 'request': adoption}}) + '\n')
        child.stdin.flush(); inherited.close(); source.settimeout(4)
        frame = handoff.receive_frame(source)
        # LOCAL_PEERTOKEN can reflect B after B sends on an inherited socket.
        # Record the actual observation; kernel identity alone does not make
        # this original channel a newly accepted successor connection.
        observed_peer = custody.AuthenticatedCleanupActor.private_peer(source).verify()
        observation_path = tmp_path / 'custody' / 'inherited-peer-observation.json'
        write_protected(observation_path, {'source_owner': parent, 'sender': actor,
                                         'kernel_peer': observed_peer, 'transport': 'original_inherited_channel'})
        assert read_protected(observation_path)['kernel_peer'] == observed_peer
        events = []
        class Bridge:
            def _call(self, request):
                events.append('host_progression')
                pytest.fail('original channel must not progress the host')
        def forbidden(name):
            def callback(*args):
                events.append(name)
                pytest.fail('original channel must not admit or transfer successor')
            return callback
        endpoint = RelayHandoffEndpoint(Bridge(), journal,
                        # Isolate the routing refusal even if the current
                        # kernel peer already verifies as B. The production
                        # source binding additionally pins/checks original A.
                        verify_binding=lambda _: custody.AuthenticatedCleanupActor.private_peer(source).verify(),
                        verify_fence=forbidden('fence_progression'),
                        verify_successor=forbidden('successor_admission'),
                        transfer_successor=forbidden('custody_transfer'))
        original_channels = {source: None}  # serve_control's original route
        outcome = endpoint.handoff(frame['request'], successor_peer=original_channels[source])
        assert outcome['status'] == 'unresolved' and outcome['error_code'] == 'identity_unresolved'
        assert outcome['registered_state'] is None and outcome['quiescence']['observation_status'] == 'unknown'
        assert endpoint.successor_listener is None and not events
        assert {path: path.read_bytes() for path in protected} == protected
    finally:
        source.close(); inherited.close(); _reap(child)


@pytest.mark.parametrize('invalid', ['duplicate_root', 'duplicate_nested', 'nonfinite', 'altered_seal', 'valid'])
def test_transfer_rejects_duplicate_keys_and_mismatched_seal(tmp_path, monkeypatch, invalid):
    request, _ = _handoff_case(tmp_path)
    b = request['binding']; b['source_owner'] = custody.AuthenticatedCleanupActor.current().verify()
    _repin_intent(b); seal = 'sha256:' + '2' * 64
    frame = {'version': handoff.TRANSFER_VERSION, 'deadline_unix_ms': b['deadline_unix_ms'],
             'binding_digest': digest(b), 'sealed_record_digest': seal}
    encoded = json.dumps(frame).encode()
    if invalid == 'duplicate_root':
        encoded = encoded[:-1] + b',"version":"duplicate"}'
    elif invalid == 'duplicate_nested':
        encoded = encoded[:-1] + b',"extra":{"x":1,"x":2}}'
    elif invalid == 'nonfinite':
        encoded = encoded[:-1] + b',"extra":NaN}'
    elif invalid == 'altered_seal':
        frame['sealed_record_digest'] = 'sha256:' + '9' * 64
        encoded = json.dumps(frame).encode()
    source, target = socket.socketpair(); control, other = socket.socketpair()
    tcp = socket.socket(); tcp.bind(('127.0.0.1', 0)); tcp.listen(1)
    received = []
    close = handoff._close_descriptors
    def record_close(fds):
        received.extend(fds); close(fds)
    monkeypatch.setattr(handoff, '_close_descriptors', record_close)
    try:
        rights = array.array('i', [control.fileno(), tcp.fileno()])
        source.sendmsg([encoded + b'\n'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())])
        if invalid == 'valid':
            transfer = handoff.receive_bound_authority_transfer(target, binding=b,
                        sealed_record_digest=seal, expected_listener=tcp.getsockname())
            assert not os.get_inheritable(transfer.worker_control_fd)
            assert not os.get_inheritable(transfer.listener_fd)
            transfer.close()
        else:
            with pytest.raises(ConflictError):
                handoff.receive_bound_authority_transfer(target, binding=b,
                        sealed_record_digest=seal, expected_listener=tcp.getsockname())
        assert len(received) == 2
        for fd in received:
            with pytest.raises(OSError):
                os.fstat(fd)
        assert os.fstat(control.fileno()) and os.fstat(tcp.fileno())
    finally:
        for channel in (source, target, control, other, tcp):
            channel.close()


def _durable_case(tmp_path, monkeypatch):
    """Fake kernel providers; real protected files/locks/fsync/ledger logic."""
    identities = {pid: {'pid': pid, 'uid': 501, 'birth_id': f'birth-{pid}'} for pid in (10, 11, 20, 21, 22, 23)}
    tokens = {pid: {'pid': pid, 'uid': 501, 'pidversion': pid + 1,
                   'sha256': 'sha256:' + f'{pid:064x}', 'words': [pid] * 8} for pid in identities}
    monkeypatch.setattr(custody, 'audit_token_details', lambda words: {k: v for k, v in tokens[words[0]].items() if k != 'words'})
    monkeypatch.setattr(custody, 'default_process_identity', identities.get)
    monkeypatch.setattr(custody, 'current_process_audit_token', tokens.get)
    actors = {pid: custody.AuthenticatedCleanupActor(lambda pid=pid: tokens[pid], identities.get) for pid in (10, 11, 20)}
    prepare, reply = _handoff_case(tmp_path); b = prepare['binding']
    b.update(source_owner=actors[10].verify(), new_owner=actors[11].verify())
    authorities = {}
    for role, pid in (('relay', 20), ('host', 21), ('engine', 22), ('engine_listener', 23)):
        authority = custody.RoleCustodyAuthority(Path(b['custody_scope']), role)
        owner = actors[10] if role == 'relay' else actors[20]
        authority.designate_pending(actor=owner, identity=identities[pid], token=tokens[pid], owner_epoch='A')
        authority.bind_target(actor=owner, generation=1, identity=identities[pid], token=tokens[pid])
        authorities[role] = authority
        b['current_roles'][role] = authority.reference()
    b['source_relay_reference'] = b['current_roles']['relay']
    b['original_roles'] = copy.deepcopy(b['current_roles']); _repin_intent(b)
    reply.update(binding_digest=digest(b), request_digest=digest(prepare), custody_capabilities=b['current_roles'])
    journal = HandoffJournal(tmp_path / 'custody' / 'runtime-handoff-state.json', writer=b['source_owner'], owner_epoch='A',
                 authority=lambda: authorities['relay'].verify_reference(b['source_relay_reference'], expected_actor=b['source_owner'], owner_epoch='A'))
    journal.begin(prepare); journal.finish(prepare, reply)
    fence = {'version': 'runtime.local-execution-claim-fence/v1', 'state': 'held',
             **{k: b[k] for k in ('workspace_uuid', 'executor_incarnation', 'credential_generation_digest', 'operation_id', 'handoff_id', 'intent_digest', 'source_owner_epoch')},
             'target_owner_epoch': 'B', 'fence_generation': 1, 'release_ack_digest': None}
    fence_path = tmp_path / 'custody' / 'task-fence.json'; write_protected(fence_path, fence)
    export = {'version': 'runtime.local-execution-handoff-export/v1',
              **{k: b[k] for k in ('handoff_id', 'intent_digest', 'nonce_digest', 'credential_generation_digest', 'source_owner_epoch', 'source_relay_reference', 'launch_evidence_digest')},
              'host_pause_ack_digest': digest(reply), 'task_fence_digest': digest(fence), 'descriptor_identity_digest': 'sha256:' + '7' * 64}
    seal = {'version': 'runtime.local-execution-handoff-seal/v1',
            **{k: export[k] for k in ('handoff_id', 'intent_digest', 'nonce_digest', 'credential_generation_digest', 'source_owner_epoch', 'source_relay_reference', 'host_pause_ack_digest', 'task_fence_digest')},
            'export_digest': digest(export), 'target_owner_epoch': 'B', 'successor_incarnation': b['new_owner']}
    sealed = {**prepare, 'command': 'handoff_export_sealed', 'payload': {'export_metadata': export, 'seal_record': seal, 'sealed_record_digest': digest(seal)}}
    sealed_reply = {**reply, 'command': sealed['command'], 'request_digest': digest(sealed), 'phase': 'export_sealed'}
    journal.begin(sealed); journal.finish(sealed, sealed_reply)
    adoption = _adoption(b, seal=digest(seal)); adoption['payload'].update(export_digest=digest(export), task_fence_digest=digest(fence))
    peer = handoff.FreshSuccessorPeer(None, actors[11], digest(b), digest(seal))
    checks = []
    def verify_fence(request):
        observed = read_protected(fence_path)
        assert observed == fence and request['payload']['task_fence_digest'] == digest(observed)
        checks.append(observed['fence_generation'])
    return adoption, peer, actors, authorities, journal, verify_fence, checks, prepare, fence_path


@pytest.mark.parametrize('window', ['normal', 'before_role_commit', 'after_role_commit', 'after_writer_commit'])
def test_writer_transfer_reconciles_committed_relay_ack_and_fences_stale_source(tmp_path, monkeypatch, window):
    request, peer, actors, authorities, journal, fence, checks, prepare, fence_path = _durable_case(tmp_path, monkeypatch)
    b = request['binding']; authority = authorities['relay']
    delegated = {role: item.path.read_bytes() for role, item in authorities.items() if role != 'relay'}
    original_fence = fence_path.read_bytes()
    transfer = authority.transfer; reconcile = journal.reconcile_writer_transfer
    def move(**kwargs):
        if window == 'before_role_commit':
            raise OSError('before role commit')
        result = transfer(**kwargs)
        if window == 'after_role_commit':
            raise OSError('after role commit')
        return result
    def finish(*args, **kwargs):
        result = reconcile(*args, **kwargs)
        raise OSError('after writer commit')
    monkeypatch.setattr(authority, 'transfer', move)
    if window == 'after_writer_commit':
        monkeypatch.setattr(journal, 'reconcile_writer_transfer', finish)
    invoke = lambda: handoff.transfer_relay_to_successor(request, peer=peer, source_actor=actors[10], runtime_journal=journal, authority=authority, verify_fence=fence)
    if window != 'normal':
        with pytest.raises(OSError, match=window.replace('_', ' ')):
            invoke()
        state = read_protected(journal.path)
        assert state['writer_transfer']['state'] == ('committed' if window == 'after_writer_commit' else 'prepared')
        assert authority.reference()['generation'] == (1 if window == 'before_role_commit' else 2)
        if window != 'before_role_commit':
            with pytest.raises((ConflictError, custody.CustodyError)):
                journal.replay(prepare)
    monkeypatch.setattr(authority, 'transfer', transfer)
    monkeypatch.setattr(journal, 'reconcile_writer_transfer', reconcile)
    result = invoke(); assert result['state'] == 'committed'
    state = read_protected(journal.path)
    assert state['writer_incarnation'] == b['new_owner'] and state['writer_owner_epoch'] == 'B'
    assert state['writer_generation'] == 2 and state['binding'] == b
    assert state['ownership']['relay_reference']['generation'] == 2
    frozen = journal.path.read_bytes(); ledger = authority.path.read_bytes()
    assert invoke() == result  # Exact replay closes every lost-ACK window.
    assert journal.path.read_bytes() == frozen and authority.path.read_bytes() == ledger
    assert len(read_protected(authority.path)['transitions']) == 1
    with pytest.raises((ConflictError, custody.CustodyError)):
        journal.replay(prepare)
    # Even with a permissive callback, the stale object's pinned writer/epoch
    # cannot become B's journal writer from a serialized frame.
    stale = HandoffJournal(journal.path, writer=b['source_owner'], owner_epoch='A', authority=lambda: None)
    with pytest.raises(ConflictError, match='stale.*writer'):
        stale.replay(prepare)
    changed = copy.deepcopy(request); changed['binding']['handoff_id'] += '-changed'; _repin_intent(changed['binding'])
    with pytest.raises(ConflictError):
        handoff.transfer_relay_to_successor(changed, peer=peer, source_actor=actors[10], runtime_journal=journal, authority=authority, verify_fence=fence)
    # Old A control mutations cannot forward after designation moves. A's
    # read-only historical evidence is distinct from active authority.
    from runtime_protocol.local_execution_supervisor import RelayHandoffEndpoint
    class Bridge:
        def _call(self, request):
            pytest.fail('stale A descriptor forwarded a mutation')
    endpoint = RelayHandoffEndpoint(Bridge(), journal, verify_binding=lambda _: None,
                                    verify_fence=fence, verify_active_owner=lambda _: authority.verify_reference(b['source_relay_reference'], expected_actor=b['source_owner'], owner_epoch='A'))
    assert endpoint.handoff(prepare)['status'] != 'ok'
    assert fence_path.read_bytes() == original_fence and checks
    assert {role: authorities[role].path.read_bytes() for role in delegated} == delegated
