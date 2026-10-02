"""Opt-in 2GiB loopback streaming/seek proof; no duplicated large fixture.

Run: PYTHONPATH=packages/python:. python3 tests/stress_streaming_media.py
The TemporaryDirectory and fresh isolated realm are removed even on failure.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import resource
import shutil
import struct
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore

SIZE = 2 * 1024 ** 3
CHUNK = 1024 ** 2


def main():
    free = shutil.disk_usage(tempfile.gettempdir()).free
    if free < SIZE + 2 * 1024 ** 3:
        raise RuntimeError('need 4GiB free before bounded2GiB stress fixture')
    with tempfile.TemporaryDirectory(prefix='r1-streaming-stress-') as temporary:
        root = Path(temporary)
        clip = root / 'tiny.mp4'
        subprocess.run(['ffmpeg', '-v', 'error', '-f', 'lavfi', '-i', 'testsrc2=size=64x64:rate=10', '-t', '1',
                        '-c:v', 'libx264', '-threads', '1', '-movflags', '+faststart', str(clip)], check=True)
        prefix = clip.read_bytes()
        RealmStore.initialize(root / 'realm').close()
        daemon = RuntimeDaemon(root / 'realm', support_root=root / 'support').start()
        try:
            endpoint = urlsplit(daemon.endpoint)
            auth = {'Authorization': 'Bearer ' + daemon.token}
            def request(method, path, body=None, headers=None):
                connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=120)
                connection.request(method, path, body=body, headers={**auth, **(headers or {})})
                response = connection.getresponse()
                result = response.status, dict(response.headers), response.read()
                connection.close()
                return result
            status, _, body = request('POST', '/v1/projects', json.dumps({'slug': 'stress', 'name': 'Stress'}).encode(),
                {'Content-Type': 'application/json', 'Idempotency-Key': 'stress-project'})
            assert status == 201, body
            project = json.loads(body)['data']['project_id']
            hasher = hashlib.sha256()
            zeros = bytes(CHUNK)
            def chunks():
                free_atom = struct.pack('>I4s', SIZE - len(prefix), b'free')
                for chunk in (prefix, free_atom):
                    hasher.update(chunk)
                    yield chunk
                remaining = SIZE - len(prefix) - len(free_atom)
                while remaining:
                    chunk = zeros[:min(CHUNK, remaining)]
                    hasher.update(chunk)
                    remaining -= len(chunk)
                    yield chunk
            stopped = threading.Event()
            latencies = []
            def health():
                while not stopped.wait(.1):
                    start = time.monotonic()
                    assert request('GET', '/v1/health')[0] == 200
                    latencies.append(time.monotonic() - start)
            watcher = threading.Thread(target=health, daemon=True)
            watcher.start()
            baseline_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            begin = time.monotonic()
            status, _, body = request('POST', f'/v1/projects/{project}/media-imports', chunks(),
                {'Content-Length': str(SIZE), 'Content-Type': 'video/mp4', 'X-Original-Name': '2gib.mp4', 'Idempotency-Key': 'stress-import'})
            elapsed = time.monotonic() - begin
            stopped.set()
            watcher.join(3)
            assert status == 201, body
            imported = json.loads(body)
            digest = 'sha256:' + hasher.hexdigest()
            assert imported['data']['asset_id'] == digest
            assert imported['data']['size'] == SIZE
            assert imported['data']['status'] == 'completed'
            path = '/v1/objects/' + digest
            status, headers, body = request('HEAD', path)
            assert status == 200 and int(headers['Content-Length']) == SIZE and not body
            for start, end in [(0, len(prefix) - 1), (SIZE - 32, SIZE - 1), (1024 ** 3, 1024 ** 3 + 31)]:
                status, headers, body = request('GET', path, headers={'Range': f'bytes={start}-{end}'})
                assert status == 206 and len(body) == end - start + 1
                assert headers['Content-Range'] == f'bytes {start}-{end}/{SIZE}'
                if start == 0:
                    assert body == prefix
                else:
                    assert body == bytes(32)
            decoded = subprocess.run(['ffmpeg', '-v', 'error', '-headers', 'Authorization: Bearer ' + daemon.token + '\r\n',
                '-ss', '0.5', '-i', daemon.endpoint + path, '-frames:v', '1', '-threads', '1', '-f', 'framehash', '-'],
                capture_output=True, timeout=30)
            assert decoded.returncode == 0, decoded.stderr.decode().replace(daemon.token, '<redacted>')
            assert any(line and not line.startswith(b'#') for line in decoded.stdout.splitlines())
            assert daemon.service.store.conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0] == 1
            assert daemon.service.store.conn.execute('SELECT COUNT(*) FROM generation_variants').fetchone()[0] == 1
            assert not list((daemon.service.store.staging_root / 'uploads').glob('*.upload'))
            peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # macOS reports bytes; Linux reports KiB.
            multiplier = 1 if os.uname().sysname == 'Darwin' else 1024
            assert peak_rss * multiplier < 256 * 1024 ** 2
            print(json.dumps({'bytes': SIZE, 'seconds': round(elapsed, 3), 'baseline_rss_bytes': baseline_rss * multiplier,
                'peak_rss_bytes': peak_rss * multiplier, 'rss_growth_bytes': (peak_rss - baseline_rss) * multiplier,
                'health_requests': len(latencies), 'health_max_seconds': round(max(latencies, default=0), 4),
                'disk_free_before_bytes': free, 'large_fixture_cas_bytes': SIZE, 'tiny_fixture_bytes': len(prefix),
                'object_digest': digest, 'http_seek_decode': 'passed', 'large_fixture_removed_on_exit': True}, sort_keys=True))
        finally:
            daemon.stop()


if __name__ == '__main__':
    main()
