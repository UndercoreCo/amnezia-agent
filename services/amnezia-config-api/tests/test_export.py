import base64
import json
import struct
import zlib
from datetime import timedelta
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from app.backend import DockerBackend
from app.domain import Engine, Store, Fault, keys, now, stamp
from app.export import guest_profile
from app.main import create_app


def fixture():
    secret, server = keys(), keys()
    config = {'endpoint': '192.0.2.1:44537', 'listen_port': 44537, 'dns': ['1.1.1.1', '1.0.0.1'],
              'server_private_key': server['private'],
              'parameters': {'Jc':'4','Jmin':'40','Jmax':'70','S1':'32','S2':'64','S3':'0','S4':'0',
                             'H1':'10001','H2':'10002','H3':'10003','H4':'10004'}}
    row = {'name':'Undercore — проверка формата', 'ip':'10.78.0.2', 'public_key':secret['public']}
    return config, row, secret


def decode(value):
    encoded = value.removeprefix('vpn://')
    raw = base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))
    document = zlib.decompress(raw[4:])
    assert struct.unpack('>I', raw[:4])[0] == len(document)
    return json.loads(document)


@pytest.mark.parametrize("endpoint", ["192.0.2.1:44537", "vpn.example.test:44537"])
def test_guest_export_preserves_native_identity_and_excludes_admin_credentials(endpoint):
    config, row, secret = fixture()
    config["endpoint"] = endpoint
    config.update(userName='root', password='DO_NOT_EXPORT', api_key='DO_NOT_EXPORT', port=22)
    backend = DockerBackend(config)
    result = backend.amnezia(row, secret)
    data = decode(result)
    assert set(data) == {'description','hostName','dns1','dns2','containers','defaultContainer'}
    assert data['defaultContainer'] == data['containers'][0]['container'] == 'amnezia-awg'
    protocol = data['containers'][0]['awg']
    assert protocol['isThirdPartyConfig'] is True and protocol['protocol_version'] == '2'
    client = json.loads(protocol['last_config'])
    assert client['config'] == backend.configuration(row, secret)
    host, port = endpoint.rsplit(':', 1)
    assert data['hostName'] == client['hostName'] == host
    assert client['port'] == int(protocol['port']) == int(port)
    assert f'Endpoint = {endpoint}\n' in client['config']
    assert client['client_priv_key'] == secret['private'] and client['psk_key'] == secret['psk']
    assert client['client_pub_key'] == row['public_key']
    assert client['allowed_ips'] == ['0.0.0.0/0', '::/0']
    assert client['S3'] == client['S4'] == '0'
    assert client['mtu'] == '1280' and 'MTU = 1280' in client['config']
    raw = json.dumps(data)
    assert config['server_private_key'] not in raw and 'DO_NOT_EXPORT' not in raw
    assert 'server_priv_key' not in raw and 'userName' not in raw
    assert backend.amnezia(row, secret) == result


def test_unverified_protocol_generation_is_not_silently_downgraded():
    config, row, secret = fixture()
    config['parameters']['HeaderProtectionKey'] = 'test-only'
    backend = DockerBackend(config)
    with pytest.raises(Fault, match='export_version_unsupported'):
        backend.amnezia(row, secret)


def test_export_endpoint_requires_auth_and_active_access(tmp_path, monkeypatch):
    from app import domain
    config, row, secret = fixture()
    class Runtime(DockerBackend):
        peers = set()
        def snapshot(self):return 'boot-1', self.peers.copy(), {}
        def apply(self, rows):self.peers = {r['public_key'] for r,s in rows}
    engine = Engine(Store(tmp_path/'state.db', Fernet.generate_key()), Runtime(config))
    start=now()
    made=engine.execute({'operation':'create','external_id':'test-export','name':'Export','expires_at':stamp(start+timedelta(minutes=2))})
    client=TestClient(create_app('t'*40,engine.execute));path='/v1/clients/'+made['client_id']+'/amnezia'
    assert client.get(path).status_code == 401
    headers={'Authorization':'Bearer '+'t'*40}
    response=client.get(path,headers=headers)
    assert response.status_code==200 and 'no-store' in response.headers['cache-control']
    data=decode(response.text)
    assert data['description']=='Export' and 'last_config' not in response.text
    engine.execute({'operation':'disable','client_id':made['client_id']})
    assert client.get(path,headers=headers).status_code==409
    monkeypatch.setattr(domain,'now',lambda:start+timedelta(minutes=3))
    assert client.get(path,headers=headers).status_code==410
