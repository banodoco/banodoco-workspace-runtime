from __future__ import annotations

import base64
import errno
import hashlib
import http.client
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from runtime_protocol.cas import IO_CHUNK_BYTES
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, NotFoundError, ProtocolError, ValidationError
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aKz8AAAAASUVORK5CYII=')


@pytest.fixture
def service(tmp_path):
    RealmStore.initialize(tmp_path / 'realm').close()
    value = RuntimeService(tmp_path / 'realm')
    yield value
    value.close()


@pytest.fixture
def daemon(tmp_path):
    RealmStore.initialize(tmp_path / 'realm').close()
    value = RuntimeDaemon(tmp_path / 'realm', support_root=tmp_path / 'support').start()
    yield value
    value.stop()


def handler(payload, headers, maximum=1024):
    value = object.__new__(RuntimeHandler)
    value.headers = Message()
    for key, item in headers:
        value.headers.add_header(key, item)
    value.rfile = io.BytesIO(payload)
    value.server = SimpleNamespace(runtime=SimpleNamespace(max_object_bytes=maximum))
    return value


@pytest.mark.parametrize(('payload', 'headers', 'expected'), [
    (b'abc', [('Content-Length', '3')], b'abc'),
    (b'', [('Content-Length', '0')], b''),
    (b'2\r\nab\r\n1;ext=yes\r\nc\r\n0\r\n\r\n', [('Transfer-Encoding', 'chunked')], b'abc'),
])
def test_binary_framing_valid(payload, headers, expected):
    assert b''.join(handler(payload, headers)._binary_chunks()) == expected


@pytest.mark.parametrize(('payload', 'headers'), [
    (b'abc', []), (b'abc', [('Content-Length', '-1')]),
    (b'abc', [('Content-Length', '3'), ('Content-Length', '3')]),
    (b'abc', [('Content-Length', '3,3')]), (b'abc', [('Content-Length', '9' * 5000)]),
    (b'abc', [('Content-Length', '1025')]), (b'ab', [('Content-Length', '3')]),
    (b'', [('Content-Length', '0'), ('Transfer-Encoding', 'chunked')]),
    (b'', [('Transfer-Encoding', 'gzip, chunked')]),
    (b'', [('Transfer-Encoding', 'chunked'), ('Transfer-Encoding', 'chunked')]),
    (b'', [('Content-Length', '0'), ('Content-Encoding', 'gzip')]),
    (b'nothex\r\n', [('Transfer-Encoding', 'chunked')]),
    (b'3\r\nab', [('Transfer-Encoding', 'chunked')]),
    (b'1\r\naXX', [('Transfer-Encoding', 'chunked')]),
    (b'401\r\n', [('Transfer-Encoding', 'chunked')]),
    (b'0\r\nX-Trailer: nope\r\n\r\n', [('Transfer-Encoding', 'chunked')]),
    (b'1\r\na\r\n', [('Transfer-Encoding', 'chunked')]),
])
def test_bad_binary_framing_rejected_without_unbounded_read(payload, headers):
    with pytest.raises(ProtocolError):
        list(handler(payload, headers)._binary_chunks())


def assert_clean(service):
    assert not list((service.store.staging_root / 'uploads').glob('*.upload'))
    assert service.store.conn.execute('SELECT COUNT(*) FROM objects').fetchone()[0] == 0
    assert service.store.conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] == 0
    assert not list(service.cas.root.glob('*/*'))


def test_failed_hash_incomplete_body_and_iterator_cancellation_clean_stage(service):
    for chunks, expected in [((b'abc',), 'sha256:' + '0' * 64),
                             (handler(b'ab', [('Content-Length', '3')])._binary_chunks(), None)]:
        with pytest.raises((ConflictError, ProtocolError)):
            service.stage_object(chunks, expected_digest=expected)
        assert_clean(service)

    def cancelled():
        yield b'abc'
        raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        service.stage_object(cancelled())
    assert_clean(service)


def test_disk_full_during_transfer_and_publication_clean_state(service, monkeypatch):
    original = os.fsync
    with monkeypatch.context() as scoped:
        scoped.setattr(os, 'fsync', lambda fd: (_ for _ in ()).throw(OSError(errno.ENOSPC, 'injected disk full')))
        with pytest.raises(OSError):
            service.stage_object((b'abc',))
    assert_clean(service)

    with service.stage_object((b'abc',)) as staged:
        with monkeypatch.context() as scoped:
            original_publish = service.cas.publish
            def fail_after_link(*args, **kwargs):
                original_publish(*args, **kwargs)
                raise OSError(errno.ENOSPC, 'injected publication failure')
            scoped.setattr(service.cas, 'publish', fail_after_link)
            with pytest.raises(OSError):
                service.ingest_object(staged, idempotency_key='disk-full')
    assert_clean(service)
    assert not list((service.store.staging_root / 'publications').glob('*.json'))
    result = service.ingest_object(b'abc', idempotency_key='disk-full')
    assert result['data']['size'] == 3


def test_stream_and_hash_do_not_hold_sqlite_transaction(service, monkeypatch):
    project = service.create_project({'name': 'Import', 'slug': 'import'}, idempotency_key='project')['id']
    def chunks():
        assert not service.store.conn.in_transaction
        yield PNG
    verify = service.cas.existing_identity
    def checked_verify(*args):
        assert not service.store.conn.in_transaction
        return verify(*args)
    monkeypatch.setattr(service.cas, 'existing_identity', checked_verify)
    monkeypatch.setattr(service, '_verify_open_file', lambda *a, **k: pytest.fail('large hash entered settlement transaction'))
    with service.stage_object(chunks()) as staged:
        result = service.import_media(project, staged, media_type='image/png', original_name='still.png', actor_id='owner', idempotency_key='import')
    assert result['data']['status'] == 'completed'
    assert service.store.conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] == 1
    assert service.store.conn.execute('SELECT COUNT(*) FROM generations').fetchone()[0] == 1


@pytest.mark.parametrize(('data', 'media_type'), [(b'not a PNG', 'image/png'), (PNG, 'video/mp4'), (PNG, 'image/jpeg'), (b'#EXTM3U\nhttps://example.com/file', 'video/mp4')])
def test_ui_media_validation_rejects_undecodable_or_mismatched_data(service, data, media_type):
    project = service.create_project({'name': 'Bad media', 'slug': 'bad'}, idempotency_key='bad-project')['id']
    with pytest.raises(ValidationError):
        service.import_media(project, data, media_type=media_type, actor_id='owner', idempotency_key='bad')
    assert_clean(service)
    # Generic CAS retains arbitrary-blob support.
    assert service.ingest_object(data, media_type=media_type, idempotency_key='blob')['data']['size'] == len(data)


def test_configuration_can_lower_but_never_raise_hard_maximum(tmp_path, monkeypatch):
    RealmStore.initialize(tmp_path / 'realm').close()
    monkeypatch.setenv('RUNTIME_MAX_OBJECT_BYTES', '2')
    value = RuntimeService(tmp_path / 'realm')
    try:
        with pytest.raises(ValidationError):
            value.ingest_object(b'abc', idempotency_key='too-big')
    finally:
        value.close()
    monkeypatch.setenv('RUNTIME_MAX_OBJECT_BYTES', str(5 * 1024 ** 3 + 1))
    with pytest.raises(ValidationError):
        RuntimeService(tmp_path / 'realm')


def request(daemon, method, path, body=None, *, headers=None, chunks=False):
    url = urlsplit(daemon.endpoint)
    connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
    connection.request(method, path, body=body, headers={'Authorization': 'Bearer ' + daemon.token, **(headers or {})}, encode_chunked=chunks)
    response = connection.getresponse()
    value = response.status, dict(response.headers), response.read()
    connection.close()
    return value


def test_real_http_chunked_import_replay_and_restart(daemon):
    status, _, body = request(daemon, 'POST', '/v1/projects', json.dumps({'name': 'HTTP', 'slug': 'http'}).encode(), headers={'Content-Type': 'application/json', 'Idempotency-Key': 'project'})
    assert status == 201
    project = json.loads(body)['data']['project_id']
    path = f'/v1/projects/{project}/media-imports'
    headers = {'Content-Type': 'image/png', 'X-Original-Name': 'still.png', 'Idempotency-Key': 'operation'}
    status, _, body = request(daemon, 'POST', path, iter([PNG[:30], PNG[30:]]), headers=headers, chunks=True)
    assert status == 201
    first = json.loads(body)
    assert first['data']['status'] == 'completed'
    status, _, body = request(daemon, 'POST', path, PNG, headers=headers)
    assert status == 201 and json.loads(body) == first
    old_root, support = daemon.root, daemon.support_root
    daemon.stop()
    reopened = RuntimeDaemon(old_root, support_root=support).start()
    try:
        status, _, body = request(reopened, 'POST', path, PNG, headers=headers)
        assert status == 201 and json.loads(body) == first
        status, _, body = request(reopened, 'GET', path + '/operation')
        assert status == 200 and json.loads(body)['asset_id'] == first['data']['asset_id']
    finally:
        reopened.stop()


def test_slow_cancelled_upload_and_unconsumed_download_do_not_block_health(daemon):
    url = urlsplit(daemon.endpoint)
    sock = socket.create_connection((url.hostname, url.port), timeout=5)
    sock.sendall((f'POST /v1/objects HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {daemon.token}\r\nIdempotency-Key: interrupted\r\nContent-Length: 2097152\r\n\r\n').encode() + b'a')
    # A health request must work while the first handler waits for more bytes.
    assert request(daemon, 'GET', '/v1/health')[0] == 200
    sock.shutdown(socket.SHUT_WR)
    response = sock.recv(4096)
    assert b'400' in response.split(b'\r\n', 1)[0]
    sock.close()
    status, _, body = request(daemon, 'POST', '/v1/objects', b'abc', headers={'Idempotency-Key': 'interrupted'})
    assert status == 201
    assert json.loads(body)['data']['size'] == 3
    payload = b'x' * (8 * 1024 * 1024)
    status, _, body = request(daemon, 'POST', '/v1/objects', payload, headers={'Idempotency-Key': 'download'})
    assert status == 201
    object_id = json.loads(body)['data']['object_id']
    sock = socket.create_connection((url.hostname, url.port), timeout=5)
    sock.sendall((f'GET /v1/objects/{object_id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {daemon.token}\r\n\r\n').encode())
    assert b'200' in sock.recv(512).split(b'\r\n', 1)[0]
    assert request(daemon, 'GET', '/v1/health')[0] == 200
    sock.close()
    assert request(daemon, 'HEAD', '/v1/objects/' + object_id)[1]['Content-Length'] == str(len(payload))


def test_empty_objects_range_and_if_range(daemon):
    status, _, body = request(daemon, 'POST', '/v1/objects', b'', headers={'Idempotency-Key': 'empty'})
    assert status == 201
    path = '/v1/objects/' + json.loads(body)['data']['object_id']
    status, headers, body = request(daemon, 'GET', path)
    assert status == 200 and headers['Content-Length'] == '0' and body == b''
    status, headers, _ = request(daemon, 'GET', path, headers={'Range': 'bytes=0-'})
    assert status == 416 and headers['Content-Range'] == 'bytes */0'
    status, _, body = request(daemon, 'POST', '/v1/objects', b'0123456789', headers={'Idempotency-Key': 'range'})
    path = '/v1/objects/' + json.loads(body)['data']['object_id']
    status, headers, body = request(daemon, 'GET', path, headers={'Range': 'bytes=0-1', 'If-Range': '"other"'})
    assert status == 200 and body == b'0123456789'
    status, headers, body = request(daemon, 'GET', path, headers={'Range': 'bytes=0-1', 'If-Range': headers['ETag']})
    assert status == 206 and body == b'01'


@pytest.mark.parametrize('crash_at', ['transfer', 'publication', 'receipt'])
def test_process_crash_recovery_keeps_truthful_receipts(tmp_path, crash_at):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    script = '''
import os, sys
from runtime_protocol.service import RuntimeService
service = RuntimeService(sys.argv[1])
point = sys.argv[2]
if point == 'transfer':
    def chunks():
        yield b'abc'
        os._exit(71)
    service.stage_object(chunks())
elif point == 'publication':
    publish = service.cas.publish
    def crash(*args, **kwargs):
        publish(*args, **kwargs)
        os._exit(72)
    service.cas.publish = crash
    service.ingest_object(b'abc', idempotency_key='operation')
else:
    service.ingest_object(b'abc', idempotency_key='operation')
    os._exit(73)
'''
    process = subprocess.run([sys.executable, '-c', script, str(root), crash_at], capture_output=True, timeout=15)
    assert process.returncode in (71, 72, 73), process.stderr.decode()
    service = RuntimeService(root)
    try:
        assert not list((service.store.staging_root / 'uploads').glob('*.upload'))
        count = service.store.conn.execute('SELECT COUNT(*) FROM objects').fetchone()[0]
        assert count == (1 if crash_at == 'receipt' else 0)
        if crash_at != 'receipt':
            assert not list(service.cas.root.glob('*/*'))
        result = service.ingest_object(b'abc', idempotency_key='operation')
        assert service.ingest_object(b'abc', idempotency_key='operation') == result
        assert service.store.conn.execute('SELECT COUNT(*) FROM objects').fetchone()[0] == 1
        assert not list((service.store.staging_root / 'publications').glob('*.json'))
    finally:
        service.close()


def test_changed_same_size_cas_is_verified_before_playback(service, monkeypatch):
    imported = service.ingest_object(b'abc', idempotency_key='cache')
    digest = imported['data']['object_id']
    # Repeated ranges use immutable stat identity; they do not rehash every seek.
    with monkeypatch.context() as scoped:
        scoped.setattr(service, '_verify_open_file', lambda *a, **k: pytest.fail('rehashed an unchanged CAS object'))
        for _ in range(3):
            metadata, stream = service.open_object(digest)
            with stream:
                stream.seek(1)
                assert stream.read(1) == b'b'
    service.cas.path_for(digest.removeprefix('sha256:')).write_bytes(b'xyz')
    with pytest.raises(ConflictError, match='hash or size'):
        service.open_object(digest)


def test_verification_after_reopen_runs_outside_database_mutex(tmp_path, monkeypatch):
    RealmStore.initialize(tmp_path / 'realm').close()
    value = RuntimeService(tmp_path / 'realm')
    result = value.ingest_object(b'abc', idempotency_key='restart-cache')
    value.close()
    value = RuntimeService(tmp_path / 'realm')
    try:
        verify = value._verify_open_file
        def checked(*args, **kwargs):
            assert not value.store.conn.in_transaction
            assert not value.store._mutex._is_owned()
            return verify(*args, **kwargs)
        monkeypatch.setattr(value, '_verify_open_file', checked)
        metadata, stream = value.open_object(result['data']['object_id'])
        with stream:
            assert stream.read() == b'abc'
    finally:
        value.close()


def test_process_crash_during_import_settlement_has_no_duplicate_active_task(tmp_path):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    value = RuntimeService(root)
    project = value.create_project({'name': 'Crash', 'slug': 'crash'}, idempotency_key='project')['id']
    value.close()
    script = '''
import base64, os, sys
from runtime_protocol.service import RuntimeService
service = RuntimeService(sys.argv[1])
service.store._associate_managed_outputs = lambda *a, **k: os._exit(74)
service.import_media(sys.argv[2], base64.b64decode(sys.argv[3]), media_type='image/png', original_name='still.png', actor_id='owner', idempotency_key='catalog-crash')
'''
    process = subprocess.run([sys.executable, '-c', script, str(root), project, base64.b64encode(PNG).decode()], capture_output=True, timeout=15)
    assert process.returncode == 74, process.stderr.decode()
    value = RuntimeService(root)
    try:
        pending = value.get_media_import(project, 'catalog-crash')
        assert pending['status'] == 'pending'
        assert value.store.conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] == 0
        assert value.store.conn.execute('SELECT COUNT(*) FROM generations').fetchone()[0] == 0
        result = value.import_media(project, PNG, media_type='image/png', original_name='still.png', actor_id='owner', idempotency_key='catalog-crash')
        assert result['data']['status'] == 'completed'
        assert value.import_media(project, PNG, media_type='image/png', original_name='still.png', actor_id='owner', idempotency_key='catalog-crash') == result
        assert value.store.conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] == 1
        assert value.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE status='running'").fetchone()[0] == 0
        assert value.store.conn.execute('SELECT COUNT(*) FROM generations').fetchone()[0] == 1
        assert value.store.conn.execute('SELECT COUNT(*) FROM generation_variants').fetchone()[0] == 1
    finally:
        value.close()
