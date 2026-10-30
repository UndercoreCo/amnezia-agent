from pathlib import Path
import pytest
from test_engine import engine, create
from app.usage import UsageSnapshots
from app.domain import Fault
from app.main import create_app
from fastapi.testclient import TestClient


class Meter:
    def __init__(self):
        self.epoch = 'boot1'
        self.values = {'key': {'rx': 100, 'tx': 200, 'generation': 'peer1'}}
    def transfer_snapshot(self):
        return self.epoch, self.values


def test_directions_baseline_restart_and_same_peer_recreation(tmp_path):
    path = tmp_path/'usage.db'
    store, backend = UsageSnapshots(path), Meter()
    rows = [{'client_id': 'client', 'public_key': 'key'}]
    store.capture(backend, rows)
    first = store.read('client')[0]
    assert (first['download_bytes'], first['upload_bytes']) == ('200', '100')
    backend.values['key']['tx'] = 500
    UsageSnapshots(path).capture(backend, rows)
    second = store.read('client')[0]
    assert second['counter_epoch'] == first['counter_epoch'] and second['sequence'] > first['sequence']
    assert second['baseline_download_bytes'] == '200'
    # A reset can already exceed the old count. Generation, not only a decrease, distinguishes it.
    backend.values['key'].update(tx=1000, generation='peer2')
    store.capture(backend, rows)
    values = store.read('client')
    assert len(values) == 2 and values[0]['is_final']
    assert values[1]['baseline_download_bytes'] == '1000' and not values[1]['complete']
    backend.epoch = 'boot2'
    store.capture(backend, rows)
    assert len(store.read('client')) == 3


def test_counter_decrease_absence_and_final_snapshot(tmp_path):
    store, backend = UsageSnapshots(tmp_path/'usage.db'), Meter()
    rows = [{'client_id': 'client', 'public_key': 'key'}]
    store.capture(backend, rows)
    backend.values['key']['rx'] = 1
    store.capture(backend, rows)
    assert len(store.read('client')) == 2
    store.capture(backend, rows, {'key'})
    backend.values = {}
    store.capture(backend, rows)
    assert all(s['is_final'] for s in store.read('client'))
    assert store.read('missing') == []


def test_invalid_counter_does_not_commit(tmp_path):
    store, backend = UsageSnapshots(tmp_path/'usage.db'), Meter()
    backend.values['key']['rx'] = -1
    with pytest.raises(Fault, match='counter_invalid'):
        store.capture(backend, [{'client_id': 'c', 'public_key': 'key'}])
    assert store.read('c') == []


def test_usage_http_auth_identity_and_no_reconcile(engine, monkeypatch):
    created = create(engine)
    client = TestClient(create_app('t'*40, engine.execute, server_id='test-node'))
    url = '/v1/clients/'+created['client_id']+'/usage'
    assert client.get(url).status_code == 401
    headers = {'Authorization': 'Bearer '+'t'*40}
    assert client.get(url, headers=headers).status_code == 422
    monkeypatch.setenv('AWG_USAGE_ENABLED', '1')
    key = engine.rows()[0]['public_key']
    monkeypatch.setattr(engine.backend, 'transfer_snapshot', lambda: ('boot', {key: {'rx': 9, 'tx': 18, 'generation': '1'}}), raising=False)
    monkeypatch.setattr(engine, 'reconcile', lambda: pytest.fail('measurement must not reconcile'))
    result = client.get(url, headers=headers)
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'contracts'))
    from check import assert_response
    assert_response('amnezia', 'GET', '/v1/clients/{client_id}/usage', result)
    assert result.status_code == 200 and 'no-store' in result.headers['cache-control']
    assert result.json()['server_id'] == 'test-node'
    assert result.json()['samples'][0]['upload_bytes'] == '9'
    assert 'public_key' not in result.text and 'private' not in result.text


def test_collection_error_never_blocks_create_or_revoke(engine, monkeypatch):
    monkeypatch.setenv('AWG_USAGE_ENABLED', '1')
    monkeypatch.setattr(engine.backend, 'transfer_snapshot', lambda: (_ for _ in ()).throw(OSError('disk failed')), raising=False)
    value = create(engine)
    engine.execute({'operation': 'disable', 'client_id': value['client_id']})
    assert not engine.backend.peers
