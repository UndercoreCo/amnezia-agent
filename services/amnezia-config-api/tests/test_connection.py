"""Atomic export shares the existing serialized reconcile and access guards."""
import pytest
from datetime import timedelta
from fastapi.testclient import TestClient
from app.domain import Fault, now, stamp
from app.main import create_app
from test_engine import engine, create
from test_control_lease import grant


def test_atomic_response_reconciles_once_and_preserves_configuration(engine, monkeypatch, caplog):
    peer = create(engine)
    expected = engine.execute({'operation': 'configuration', 'client_id': peer['client_id']})['configuration']
    reconciles = []
    real = engine.reconcile
    def reconcile():
        reconciles.append(True)
        return real()
    monkeypatch.setattr(engine, 'reconcile', reconcile)
    client = TestClient(create_app('t' * 40, engine.execute, server_id='test-node'))
    with caplog.at_level('INFO', logger='uvicorn.error.diagnostics'):
        response = client.get('/v1/clients/' + peer['client_id'] + '/connection', headers={'Authorization': 'Bearer ' + 't' * 40})
    value = response.json()
    assert response.status_code == 200 and 'no-store' in response.headers['cache-control']
    assert len(reconciles) == 1
    assert value['server_id'] == 'test-node' and value['schema_version'] == 1
    assert value['client']['client_id'] == peer['client_id'] and value['client']['status'] == 'active'
    assert value['configuration'] == expected
    assert 'secret' not in value['client'] and 'public_key' not in value['client']
    assert expected.split('PrivateKey = ')[1].splitlines()[0] not in caplog.text
    assert '"operation":"connection"' in caplog.text


@pytest.mark.parametrize('failure, code', [('expired', 410), ('disabled', 410), ('missing_peer', 410), ('lease', 503), ('unknown', 404)])
def test_atomic_export_never_releases_unavailable_access(engine, failure, code):
    peer = create(engine)
    if failure == 'expired':
        with engine.store.db() as db:
            db.execute('UPDATE clients SET expires_at=?', (stamp(now()-timedelta(seconds=1)),))
    elif failure == 'disabled':
        engine.execute({'operation': 'disable', 'client_id': peer['client_id']})
    elif failure == 'missing_peer':
        engine.backend.peers.clear()
    elif failure == 'lease':
        grant(engine)
        engine.control_lease.deadline = 0
    elif failure == 'unknown':
        peer['client_id'] = 'wgapi_' + '0'*32
    with pytest.raises(Fault) as caught:
        engine.execute({'operation':'connection','client_id':peer['client_id']})
    assert caught.value.status == code


def test_atomic_route_is_authenticated_and_validates_id():
    calls = []
    client = TestClient(create_app('t'*40, lambda command: calls.append(command)))
    assert client.get('/v1/clients/wgapi_'+'a'*32+'/connection').status_code == 401
    assert client.get('/v1/clients/invalid/connection', headers={'Authorization':'Bearer '+'t'*40}).status_code == 422
    assert calls == []


def test_atomic_route_requires_configured_server_identity(monkeypatch):
    monkeypatch.delenv('AWG_API_SERVER_ID', raising=False)
    calls=[]
    client=TestClient(create_app('t'*40, lambda command: calls.append(command)))
    response=client.get('/v1/clients/wgapi_'+'a'*32+'/connection', headers={'Authorization':'Bearer '+'t'*40})
    assert response.status_code==503 and calls==[]
