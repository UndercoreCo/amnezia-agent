"""Exercise HTTP -> real agent engine -> synthetic kernel without host access."""
import sys
import copy
from pathlib import Path
from datetime import timedelta
from fastapi.testclient import TestClient
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'contracts'))
from check import assert_response, fingerprint, load, signatures
from test_engine import engine, Kernel
from app.main import create_app
from app.domain import Command, now, stamp


def test_health_extension_preserves_the_reviewed_v1_wire_contract():
    """Removing only the four v2 capability fields must reproduce the v1 contract."""
    previous = copy.deepcopy(load('amnezia'))
    lease = previous['components']['schemas']['ControlLease']
    for field in ('supported_versions', 'fresh', 'offline_until', 'max_offline_seconds'):
        lease['properties'].pop(field)
        lease['required'].remove(field)
    assert signatures(previous)['GET /v1/health'] == (
        '8db9a419bfa99eab9497bf798cdb66009e786d695a87d776e714023d290b11cc'
    )

def test_actual_http_agent_responses_follow_the_contract(engine):
    engine.backend.amnezia = lambda row, secret: 'vpn://SYNTHETIC_TEST_ONLY'
    with TestClient(create_app('t' * 40, engine.execute, server_id='contract-node')) as client:
        headers = {'Authorization': 'Bearer ' + 't' * 40}
        def checked(method, canonical, actual=None, body=None, authenticated=True):
            response = client.request(method, actual or canonical, headers=headers if authenticated else {}, json=body)
            assert_response('amnezia', method, canonical, response)
            return response
        body = {'external_id':'contract-test', 'name':'Contract phone', 'expires_at':stamp(now() + timedelta(days=3))}
        made = checked('POST', '/v1/clients', body=body)
        assert made.status_code == 200
        cid = made.json()['client_id']
        checked('POST', '/v1/clients', body=body)
        checked('GET', '/v1/health')
        checked('GET', '/v1/clients')
        for suffix in ('', '/configuration', '/amnezia', '/connection'):
            assert checked('GET', '/v1/clients/{client_id}' + suffix, '/v1/clients/' + cid + suffix).status_code == 200
        for operation in ('disable','enable'):
            assert checked('POST', '/v1/clients/{client_id}/' + operation, '/v1/clients/' + cid + '/' + operation).status_code == 200
        renewal = {'expires_at':stamp(now()+timedelta(days=4)), 'idempotency_key':'contract-renew'}
        assert checked('POST', '/v1/clients/{client_id}/renew', '/v1/clients/' + cid + '/renew', renewal).status_code == 200
        engine.backend.peers.clear()  # Simulate lost peer in the same kernel epoch.
        replacement = {**renewal, 'idempotency_key':'contract-replace', 'expected_external_id':body['external_id']}
        assert checked('POST', '/v1/clients/{client_id}/replace', '/v1/clients/' + cid + '/replace', replacement).status_code == 200
        assert checked('POST', '/v1/clients/{client_id}/replace', '/v1/clients/' + cid + '/replace', {**replacement, 'allow_create':False}).status_code == 200
        assert checked('GET', '/v1/clients', authenticated=False).status_code == 401
        assert checked('POST', '/v1/clients', body={'unsupported':True}).status_code == 422


def test_command_field_constraints_match_offline_specification():
    command = Command.model_json_schema()
    published = load('amnezia')['components']['schemas']
    for model in ('CreateClient', 'RenewClient', 'ReplaceClient'):
        schema = published[model]
        for field, value in command['properties'].items():
            if field in ('operation', 'client_id'):
                continue
            if field in schema['required']:
                value = next((candidate for candidate in value.get('anyOf', []) if candidate.get('type') != 'null'), value)
            assert fingerprint(value) == fingerprint(schema['properties'][field]), field
        assert schema['additionalProperties'] is False
