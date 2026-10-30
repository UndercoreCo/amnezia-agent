"""HTTP requests must be rejected before crossing the privileged agent boundary."""
import secrets

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def boundary():
    calls = []
    token = secrets.token_urlsafe(32)

    def transport(command):
        calls.append(command)
        return {'status': 'ok'}

    return TestClient(create_app(token, transport)), token, calls


@pytest.mark.parametrize('variant', ['missing', 'wrong', 'duplicate', 'duplicate_reversed', 'oversized'])
def test_authentication_rejects_request_before_agent(boundary, variant):
    client, token, calls = boundary
    headers = {
        'missing': [],
        'wrong': [('Authorization', 'Bearer invalid')],
        'duplicate': [('Authorization', 'Bearer ' + token), ('Authorization', 'Bearer invalid')],
        'duplicate_reversed': [('Authorization', 'Bearer invalid'), ('Authorization', 'Bearer ' + token)],
        'oversized': [('Authorization', 'Bearer ' + 'x' * 8192)],
    }[variant]
    response = client.get('/v1/health', headers=headers)
    assert response.status_code == 401
    assert response.json() == {'detail': 'unauthorized'}
    assert 'no-store' in response.headers['cache-control']
    assert token not in response.text
    assert calls == []


@pytest.mark.parametrize('body, status', [
    ('{', 422), ('[]', 422), ('null', 422),
    ('{"operation":"disable"}', 422),
    ('{"client_id":"wgapi_' + 'a' * 32 + '"}', 422),
    ('x' * 8193, 413),
])
def test_invalid_body_never_reaches_agent(boundary, body, status):
    client, token, calls = boundary
    response = client.post('/v1/clients', headers={'Authorization': 'Bearer ' + token}, content=body)
    assert response.status_code == status
    assert 'no-store' in response.headers['cache-control']
    assert calls == []


def test_agent_exception_is_sanitized_and_not_cached():
    secret = secrets.token_urlsafe(32)

    def failed_transport(command):
        raise RuntimeError(secret)

    client = TestClient(create_app(secret, failed_transport))
    response = client.get('/v1/health', headers={'Authorization': 'Bearer ' + secret})
    assert response.status_code == 503
    assert response.json() == {'detail': 'agent_unavailable'}
    assert secret not in response.text
    assert 'no-store' in response.headers['cache-control']


def test_single_valid_header_reaches_agent_once(boundary):
    client, token, calls = boundary
    response = client.get('/v1/health', headers={'Authorization': 'Bearer ' + token})
    assert response.status_code == 200
    assert len(calls) == 1 and calls[0]['operation'] == 'health'
