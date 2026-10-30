"""Regression tests for safe diagnostics, isolated from real VPNs."""
import asyncio
import json
import logging

import httpx
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.diagnostics import DiagnosticFastAPI, ID_PATTERN, LOGGER, STATE_KEY, RequestDiagnostics, adopt_authenticated_id, new_id

VALID = "req_01J00000000000000000000000"


def entries(caplog):
    return [json.loads(record.message) for record in caplog.records if record.name == LOGGER.name]


@pytest.mark.parametrize("candidate", ["arbitrary", "req_" + "Z" * 26, VALID + "x", "x" * 8192, "req_" + "a" * 26])
def test_invalid_or_duplicate_header_never_becomes_a_log_id(caplog, candidate):
    caplog.set_level(logging.INFO, logger=LOGGER.name)
    app = DiagnosticFastAPI(diagnostic_service="test")

    @app.get("/v1/health")
    def health(request: Request):
        adopt_authenticated_id(request.scope)
        return {"ok": True}

    client = TestClient(app)
    for headers in ({"X-Request-ID": candidate}, [("X-Request-ID", VALID), ("X-Request-ID", VALID)]):
        response = client.get("/v1/health", headers=headers)
        assert ID_PATTERN.fullmatch(response.headers["x-request-id"])
        assert response.headers["x-request-id"] != candidate
        assert response.headers["x-request-id"] != VALID
        assert entries(caplog)[-1]["request_id"] == response.headers["x-request-id"]


def test_unhandled_500_has_trace_and_no_exception_or_query_in_diagnostics(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER.name)
    app = DiagnosticFastAPI(diagnostic_service="test")

    @app.get("/v1/clients/{client_id}")
    def failure(request: Request, client_id: str):
        adopt_authenticated_id(request.scope)
        raise RuntimeError("SYNTHETIC_EXCEPTION_SECRET")

    response = TestClient(app, raise_server_exceptions=False).get(
        "/v1/clients/SYNTHETIC_CLIENT_SECRET?key=SYNTHETIC_QUERY_SECRET", headers={"X-Request-ID": VALID})
    assert response.status_code == 500
    assert response.headers["x-request-id"] == VALID
    event = entries(caplog)[-1]
    assert event["status"] == 500 and event["outcome"] == "internal_error" and event["operation"] == "get"
    assert "SECRET" not in json.dumps(event)


def test_parallel_requests_and_disconnect_are_isolated(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER.name)
    app = DiagnosticFastAPI(diagnostic_service="test")

    @app.get("/v1/health")
    async def health(request: Request):
        adopt_authenticated_id(request.scope)
        await asyncio.sleep(0.001)
        return {"ok": True}

    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test") as client:
            ids = [new_id() for _ in range(20)]
            responses = await asyncio.gather(*(client.get("/v1/health", headers={"X-Request-ID": id}) for id in ids))
            assert [response.headers["x-request-id"] for response in responses] == ids
            return set(ids)

    ids = asyncio.run(scenario())
    assert {entry["request_id"] for entry in entries(caplog)} == ids

    async def disconnected(scope, receive, send):
        assert (await receive())["type"] == "http.disconnect"

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        raise AssertionError("Disconnected request must not respond")

    scope = {"type": "http", "method": "POST", "path": "/v1/clients/SYNTHETIC_SECRET/replace", "headers": []}
    asyncio.run(RequestDiagnostics(disconnected, "test")(scope, receive, send))
    event = entries(caplog)[-1]
    assert event["status"] is None and event["outcome"] == "incomplete" and event["operation"] == "replace"
    assert ID_PATTERN.fullmatch(scope["state"][STATE_KEY])


def test_failed_logging_sink_does_not_change_response(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("SYNTHETIC_LOG_SECRET")

    monkeypatch.setattr(LOGGER, "info", broken)
    app = DiagnosticFastAPI(diagnostic_service="test")

    @app.get("/v1/health")
    def health():
        return {"ok": True}

    response = TestClient(app).get("/v1/health")
    assert response.status_code == 200
    assert ID_PATTERN.fullmatch(response.headers["x-request-id"])

from test_http_boundary import boundary
from app.main import create_app


def test_real_awg_authentication_body_errors_and_agent_boundary_keep_trace(boundary, caplog):
    caplog.set_level(logging.INFO, logger=LOGGER.name)
    client, token, calls = boundary
    auth = {"Authorization": "Bearer " + token, "X-Request-ID": VALID}
    accepted = client.get("/v1/health", headers=auth)
    assert accepted.status_code == 200 and accepted.headers["x-request-id"] == VALID
    rejected = client.get("/v1/health", headers={"X-Request-ID": VALID})
    assert rejected.status_code == 401 and rejected.headers["x-request-id"] != VALID
    invalid = client.post("/v1/clients", headers=auth, json={"operation": "disable", "name": "SYNTHETIC_NAME_SECRET"})
    assert invalid.status_code == 422 and invalid.headers["x-request-id"] == VALID
    oversized = client.post("/v1/clients", headers=auth, content="x" * 8193)
    assert oversized.status_code == 413 and oversized.headers["x-request-id"] == VALID
    assert len(calls) == 1 and calls[0]["operation"] == "health"
    assert STATE_KEY not in calls[0] and "X-Request-ID" not in calls[0]
    assert token not in json.dumps(entries(caplog))
    assert "SYNTHETIC_NAME_SECRET" not in json.dumps(entries(caplog))


def test_awg_export_and_agent_failure_keep_headers_and_do_not_log_configuration(caplog):
    caplog.set_level(logging.INFO, logger=LOGGER.name)
    token = "x" * 40

    def transport(command):
        if command['operation'] == 'configuration':
            return {'configuration': '[Interface]\nPrivateKey = SYNTHETIC_CONFIG_SECRET\n[Peer]'}
        raise RuntimeError('SYNTHETIC_AGENT_SECRET')

    client = TestClient(create_app(token, transport))
    auth = {"Authorization": "Bearer " + token, "X-Request-ID": VALID}
    exported = client.get('/v1/clients/wgapi_' + 'a' * 32 + '/configuration', headers=auth)
    assert exported.status_code == 200 and exported.headers['x-request-id'] == VALID
    assert 'no-store' in exported.headers['cache-control']
    failure = client.get('/v1/health', headers=auth)
    assert failure.status_code == 503 and failure.headers['x-request-id'] == VALID
    assert entries(caplog)[-1]['outcome'] == 'unavailable'
    assert 'SECRET' not in json.dumps(entries(caplog))
