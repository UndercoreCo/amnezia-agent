from datetime import timedelta
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from app import domain
from app.domain import Engine, Store, Fault, stamp, now
from app.main import create_app

class Kernel:
    def __init__(self):
        self.epoch, self.peers, self.lost = 'boot-1', set(), False
    def snapshot(self):
        return self.epoch, self.peers.copy(), {}
    def apply(self, rows):
        self.peers = {r['public_key'] for r, s in rows}
        if rows and self.lost:
            self.lost = False
            raise Fault('lost_response', 503)
    def configuration(self, row, secret):
        return '[Interface]\nPrivateKey = '+secret['private']+'\n[Peer]\nPublicKey = test\n'

@pytest.fixture
def engine(tmp_path):
    return Engine(Store(tmp_path/'state.db', Fernet.generate_key()), Kernel())

def create(engine, external='vpn_test', end=None):
    return engine.execute({'operation':'create','external_id':external,'name':'Phone','expires_at':end or stamp(now()+timedelta(days=3))})

def test_repeat_and_encrypted_storage(engine):
    end=stamp(now()+timedelta(days=3)); first=create(engine,end=end)
    body=engine.execute({'operation':'configuration','client_id':first['client_id']})['configuration']
    assert first['client_id']==create(engine,end=end)['client_id']
    assert len(engine.rows())==len(engine.backend.peers)==1
    private=body.split('PrivateKey = ')[1].splitlines()[0]
    assert private.encode() not in engine.store.path.read_bytes()
    assert 'secret' not in first and 'public_key' not in first
    with pytest.raises(Fault,match='identity_conflict'):create(engine,end=stamp(now()+timedelta(days=4)))

def test_lost_native_response_reuses_keys(engine):
    end=stamp(now()+timedelta(days=3)); engine.backend.lost=True
    with pytest.raises(Fault):create(engine,end=end)
    key=engine.rows()[0]['public_key']
    assert create(engine,end=end)['status']=='active'
    assert engine.backend.peers=={key}

def test_renewal_keeps_keys_and_stale_replay_does_not_shorten(engine):
    first=create(engine); before=engine.rows()[0]['secret']
    cmd={'operation':'renew','client_id':first['client_id'],'idempotency_key':'renew-1','expires_at':stamp(now()+timedelta(days=30))}
    engine.execute(cmd); end=stamp(now()+timedelta(days=60))
    engine.execute({**cmd,'idempotency_key':'renew-2','expires_at':end})
    assert engine.execute(cmd)['expires_at']==end and engine.rows()[0]['secret']==before
    with pytest.raises(Fault,match='operation_conflict'):engine.execute({**cmd,'expires_at':end})

def test_expiry_without_http_api_and_restart(engine,monkeypatch):
    start=now(); first=create(engine,end=stamp(start+timedelta(seconds=20)))
    monkeypatch.setattr(domain,'now',lambda:start+timedelta(seconds=21))
    engine.reconcile(); assert not engine.backend.peers
    engine.backend.epoch='boot-2';engine.reconcile();assert not engine.backend.peers
    with pytest.raises(Fault) as caught:engine.execute({'operation':'configuration','client_id':first['client_id']})
    assert caught.value.status==410

def test_disable_survives_renewal_and_reboot(engine):
    first=create(engine); engine.execute({'operation':'disable','client_id':first['client_id']})
    engine.execute({'operation':'renew','client_id':first['client_id'],'idempotency_key':'r1','expires_at':stamp(now()+timedelta(days=30))})
    engine.backend.epoch='boot-2'; engine.reconcile(); assert not engine.backend.peers
    assert engine.execute({'operation':'get','client_id':first['client_id']})['status']=='disabled'

def test_missing_requires_explicit_owned_replacement(engine):
    first=create(engine); old=engine.rows()[0]['public_key'];engine.backend.peers.clear()
    assert engine.execute({'operation':'get','client_id':first['client_id']})['status']=='conflict'
    assert not engine.backend.peers
    cmd={'operation':'replace','client_id':first['client_id'],'idempotency_key':'replace-1','expires_at':first['expires_at'],'expected_external_id':'vpn_test'}
    with pytest.raises(Fault,match='replacement_not_started'):engine.execute({**cmd,'allow_create':False})
    with pytest.raises(Fault,match='replacement_ownership_conflict'):engine.execute({**cmd,'expected_external_id':'someone_else'})
    assert engine.execute(cmd)['replacement_status']=='completed'
    assert old not in engine.backend.peers and len(engine.backend.peers)==1
    assert engine.execute({**cmd,'allow_create':False})['client_id']==first['client_id']

def test_foreign_peer_not_adopted_or_deleted(engine):
    create(engine);engine.backend.peers.add('FOREIGN')
    with pytest.raises(Fault,match='unmanaged_peer_detected'):engine.reconcile()
    assert 'FOREIGN' in engine.backend.peers

def test_active_restored_on_empty_boot_and_allocation_unique(engine):
    create(engine,'one');create(engine,'two');expected=engine.backend.peers.copy()
    engine.backend.peers.clear();engine.backend.epoch='boot-2'
    Engine(engine.store,engine.backend).reconcile()
    assert engine.backend.peers==expected and len({r['ip'] for r in engine.rows()})==2

@pytest.mark.parametrize('body',[{'expires_at':'2029-01-01T00:00:00'},{'name':'a\nPostUp = evil'},{'expires_at':None},{'expires_at':'invalid'},{'extra':'unexpected'}])
def test_invalid_requests_never_provision(engine,body):
    client=TestClient(create_app('t'*40,engine.execute))
    response=client.post('/v1/clients',headers={'Authorization':'Bearer '+'t'*40},json={'external_id':'vpn_test','name':'Phone','expires_at':stamp(now()+timedelta(days=3)),**body})
    assert response.status_code==422 and not engine.rows()

def test_auth_no_store_and_operation_boundary(engine):
    client=TestClient(create_app('t'*40,engine.execute));headers={'Authorization':'Bearer '+'t'*40}
    assert client.get('/v1/health').status_code==401
    response=client.post('/v1/clients',headers=headers,json={'external_id':'vpn_test','name':'Phone','expires_at':stamp(now()+timedelta(days=3))})
    assert response.status_code==200 and 'no-store' in response.headers['cache-control']
    ident=response.json()['client_id']
    response=client.get('/v1/clients/'+ident+'/configuration',headers=headers)
    assert response.status_code==200 and '[Interface]' in response.text and 'no-store' in response.headers['cache-control']
    assert client.post('/v1/clients/'+ident+'/delete',headers=headers).status_code==404
    assert client.post('/v1/clients',headers=headers,json={'operation':'disable'}).status_code==422
    assert client.post('/v1/clients',headers=headers,content='x'*8193).status_code==413


def test_agent_stops_tunnel_on_unreadable_key_store(engine, tmp_path, monkeypatch):
    from app import agent
    create(engine)
    assert engine.backend.peers
    engine.store.cipher = Fernet(Fernet.generate_key())
    stopped = []
    def stop():
        stopped.append(True)
        engine.backend.peers.clear()
    monkeypatch.setattr(engine.backend, 'emergency_stop', stop, raising=False)
    # Run the actual agent loop without requiring root in the unit-test process.
    monkeypatch.setattr(agent.os, 'chown', lambda *args: None)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError, match='Expiry reconciliation failed'):
        agent.serve(engine, 'runtime/agent.sock', 0)
    assert stopped and not engine.backend.peers
    assert not (tmp_path/'runtime'/'agent.sock').exists()
    assert (tmp_path/'runtime').stat().st_mode & 0o777 == 0o750


def test_prepare_never_overwrites_keys_and_keeps_files_private(tmp_path):
    from deploy.prepare import prepare
    target = tmp_path/'initial'
    image = 'example.test/awg@sha256:'+'a'*64
    result = prepare(target, 'vpn.example.test:44537', '10.78.0.0/24', image)
    assert result['services_started'] is False
    before = {p.name: p.read_bytes() for p in target.iterdir()}
    assert len(before) == 5 and (target.stat().st_mode & 0o777) == 0o700
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in target.iterdir())
    assert '[Peer]' not in (target/'awg0.conf').read_text()
    with pytest.raises(ValueError, match='refusing to overwrite'):
        prepare(target, 'vpn.example.test:44537', '10.78.0.0/24', image)
    assert {p.name: p.read_bytes() for p in target.iterdir()} == before
