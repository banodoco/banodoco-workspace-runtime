from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


@pytest.fixture
def service(tmp_path):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    value = RuntimeService(root)
    yield value
    value.close()


def write(service, actor='alice', content='Use local generation.', version=0, key='save', scope='user', project=None):
    return service.update_preferences(scope, content, version, key, project, identity={'actor': actor})


def read(service, actor='alice', scope='user', project=None):
    return service.get_preferences(scope, project, identity={'actor': actor})


def test_empty_reads_are_noncreating_and_actor_scoped(service):
    before = service.store.conn.execute('SELECT COUNT(*) FROM command_idempotency').fetchone()[0]
    for actor in ['alice', 'bob']:
        result = read(service, actor)
        assert result == {'scope': 'user', 'actor_id': actor, 'project_id': None,
                          'document_id': f'preferences:user:{actor}', 'content': '', 'version': 0,
                          'created_at': None, 'updated_at': None}
    with pytest.raises(ConflictError):
        write(service, version=1, key='invalid-first-version')
    assert service.store.conn.execute('SELECT COUNT(*) FROM user_preferences').fetchone()[0] == 0
    assert service.store.conn.execute('SELECT COUNT(*) FROM command_idempotency').fetchone()[0] == before
    alice = write(service)
    bob = write(service, actor='bob', content='Cloud is fine.')
    assert alice['receipt'] is bob['receipt'] is None
    assert read(service)['content'] == 'Use local generation.'
    assert read(service, 'bob')['content'] == 'Cloud is fine.'
    assert service.store.conn.execute('SELECT COUNT(*) FROM project_sequences').fetchone()[0] == 0
    rows = service.store.conn.execute('SELECT aggregate_id,txn_id,first_project_seq,last_project_seq FROM command_idempotency').fetchall()
    assert {r['aggregate_id'] for r in rows} == {'preferences:user:alice', 'preferences:user:bob'}
    assert all(r['txn_id'] is None and r['first_project_seq'] is None and r['last_project_seq'] is None for r in rows)


@pytest.mark.parametrize('scope', ['user', 'project'])
def test_first_writers_race_and_stale_unchanged_content_conflicts(service, scope):
    project = service.create_project({'name': 'Race', 'slug': 'race'})['id'] if scope == 'project' else None
    barrier = Barrier(2)
    def attempt(key):
        barrier.wait()
        try:
            return write(service, key=key, scope=scope, project=project)
        except ConflictError:
            return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ['one', 'two']))
    assert results.count('conflict') == 1
    assert read(service, scope=scope, project=project)['version'] == 1
    with pytest.raises(ConflictError):
        write(service, version=0, key='unchanged-stale', scope=scope, project=project)
    second = write(service, version=1, key='unchanged-current', scope=scope, project=project)
    assert second['data']['version'] == 2
    with pytest.raises(ConflictError):
        write(service, version=1, key='unchanged-now-stale', scope=scope, project=project)
    assert service.store.conn.execute('SELECT COUNT(*) FROM command_idempotency').fetchone()[0] == 2


def test_durable_replay_precedes_cas_after_restart(tmp_path):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    original = write(service)
    write(service, content='Updated guidance', version=1, key='later')
    service.close()
    restarted = RuntimeService(root)
    try:
        assert write(restarted) == original
        assert read(restarted)['version'] == 2
        for changed in [dict(content='Different body'), dict(version=1)]:
            with pytest.raises(ConflictError, match='different input'):
                write(restarted, **changed)
        assert read(restarted)['version'] == 2
    finally:
        restarted.close()


def test_preference_transaction_rolls_back_row_and_command_together(service, monkeypatch):
    original = service._command_record
    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError('simulate commit failure')
    monkeypatch.setattr(service, '_command_record', fail)
    with pytest.raises(RuntimeError, match='simulate commit failure'):
        write(service)
    assert read(service)['version'] == 0
    assert service.store.conn.execute('SELECT COUNT(*) FROM command_idempotency').fetchone()[0] == 0


def test_project_selection_explicit_target_reserved_documents_and_receipts(service):
    first = service.create_project({'name': 'First', 'slug': 'first'})['id']
    second = service.create_project({'name': 'Second', 'slug': 'second'})['id']
    with pytest.raises(NotFoundError):
        read(service, scope='project')
    service.select_project('alice', first, idempotency_key='select')
    before = service.store.conn.execute('SELECT COUNT(*) FROM command_idempotency').fetchone()[0]
    assert read(service, scope='project')['version'] == 0
    assert service.store.conn.execute('SELECT COUNT(*) FROM project_documents').fetchone()[0] == 0
    assert service.store.conn.execute('SELECT COUNT(*) FROM command_idempotency').fetchone()[0] == before
    first_result = write(service, scope='project')
    assert first_result['receipt']['project_id'] == first
    assert first_result['receipt']['project_seq'][0] > 0
    explicit = write(service, scope='project', project=second, key='second')
    assert explicit['data']['project_id'] == second
    assert explicit['data']['document_id'] != first_result['data']['document_id']
    assert write(service, scope='project') == first_result
    assert read(service, scope='project')['project_id'] == first
    doc = first_result['data']['document_id']
    for patch in [{'kind': 'notes'}, {'content': {}}, {'document_id': 'retargeted'}]:
        with pytest.raises(ValidationError):
            service.update_document(first, doc, {'expected_version': 1, **patch}, idempotency_key='invalid')
    for document_id, kind, content in [
        (f'preferences:project:{first}', 'notes', ''),
        (f'preferences:project:{first}', 'astrid.preferences', {}),
        (f'preferences:project:{second}', 'astrid.preferences', ''),
        ('arbitrary', 'astrid.preferences', ''),
    ]:
        with pytest.raises(ValidationError):
            service.create_document(first, {'document_id': document_id, 'kind': kind, 'content': content}, idempotency_key='bad-create')
    updated = service.update_document(first, doc, {'expected_version': 1, 'content': 'Generic edit'}, idempotency_key='generic-edit')
    assert updated['receipt']['project_id'] == first
    assert read(service, scope='project')['content'] == 'Generic edit'
    with pytest.raises(ConflictError):
        write(service, scope='project', content='Generic edit', version=1, key='stale')
    notes = service.create_document(first, {'document_id': 'notes', 'kind': 'example.notes', 'content': {}}, idempotency_key='notes')
    assert [r['document_id'] for r in service.list_documents(first, kind='example.notes')['items']] == ['notes']
    assert service.list_documents(first, kind='missing')['items'] == []
    assert notes['receipt']['project_id'] == first


def test_generic_document_json_null_update_round_trips(service):
    project = service.create_project({'name': 'JSON null', 'slug': 'json-null'})['id']
    service.create_document(project, {'document_id': 'pack:config', 'kind': 'example.config', 'content': {'enabled': True}}, idempotency_key='create')
    updated = service.update_document(project, 'pack:config', {'expected_version': 1, 'content': None}, idempotency_key='write-null')
    assert updated['data']['content'] is None
    assert service.get_document(project, 'pack:config')['content'] is None


@pytest.mark.parametrize('content,version', [(None, 0), ({}, 0), ('markdown', True), ('markdown', -1), ('markdown', 1.0)])
def test_preference_content_and_version_validation(service, content, version):
    with pytest.raises(ValidationError):
        write(service, content=content, version=version)
    assert read(service)['version'] == 0


def request(daemon, token, method, route, body=None, key=None):
    headers = {'Authorization': f'Bearer {token}'}
    if key:
        headers['Idempotency-Key'] = key
    raw = json.dumps(body).encode() if body is not None else None
    req = Request(daemon.endpoint + route, data=raw, method=method, headers=headers)
    try:
        with urlopen(req) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def test_http_derives_owner_and_rejects_caller_ownership(tmp_path):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / 'support').start()
    try:
        alice, _ = daemon.credentials.provision('alice', ['projects:read', 'projects:write'])
        bob, _ = daemon.credentials.provision('bob', ['projects:read', 'projects:write'])
        readonly, _ = daemon.credentials.provision('reader', ['projects:read'])
        for token in [alice, bob]:
            status, result = request(daemon, token, 'PUT', '/v1/preferences/user', {'content': token[-8:], 'expected_version': 0}, 'same-key')
            assert status == 200 and result['receipt'] is None
        assert request(daemon, alice, 'GET', '/v1/preferences/user')[1]['actor_id'] == 'alice'
        assert request(daemon, bob, 'GET', '/v1/preferences/user')[1]['actor_id'] == 'bob'
        for query in ['?project_id=anything', '?project_id=', '?actor_id=bob', '?project_id=a&project_id=b']:
            assert request(daemon, alice, 'GET', '/v1/preferences/user' + query)[0] in (400, 422)
        for field in ['actor_id', 'owner', 'project_id', 'scope']:
            assert request(daemon, alice, 'PUT', '/v1/preferences/user', {'content': '', 'expected_version': 1, field: 'bob'}, 'bad')[0] == 400
        assert request(daemon, alice, 'PUT', '/v1/preferences/user', {'content': '', 'expected_version': 1})[0] == 400
        assert request(daemon, readonly, 'PUT', '/v1/preferences/user', {'content': '', 'expected_version': 0}, 'read-only')[0] == 401
        assert request(daemon, alice, 'GET', '/v1/preferences/invalid')[0] == 422
    finally:
        daemon.stop()


def test_generated_clients_decode_user_null_and_project_committed_receipts(tmp_path):
    from banodoco_workspace_client import WorkspaceClient
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / 'support').start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        empty = client.get_preferences('user')
        assert empty.version == 0 and empty.content == ''
        user = client.update_preferences('user', 'Local generation', 0, 'user')
        assert user.receipt is None and user.data.version == 1 and user.content == 'Local generation'
        assert client.update_preferences('user', 'Local generation', 0, 'user') == user
        project = client.create_project('Client project', slug='client-project', idempotency_key='project')
        client.select_project(project.project_id, idempotency_key='select')
        selected = client.get_preferences('project')
        assert selected.project_id == project.project_id and selected.version == 0
        saved = client.update_preferences('project', 'Project guidance', 0, 'project-prefs')
        assert saved.receipt['project_id'] == project.project_id
        assert saved.version == 1 and saved.data.scope == 'project'
        assert client.get_preferences('project', project.project_id).content == 'Project guidance'
        assert client.current_project()['project']['project_id'] == project.project_id
        client.create_document(project.project_id, 'brief', 'demo.brief', {'content': 'Brief'}, idempotency_key='brief')
        duplicate = client.create_document(project.project_id, 'brief', 'demo.brief', {'content': 'Brief'}, idempotency_key='brief-repeated')
        assert duplicate.receipt['command_kind'] == 'document.create'
        documents, cursor = client.list_documents(project.project_id, kind='demo.brief')
        assert [item.document_id for item in documents] == ['brief'] and cursor is None
    finally:
        daemon.stop()
