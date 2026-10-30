"""Unprivileged, authenticated HTTP facade. Never mounts Docker socket or key DB."""
import hmac
import json
import os
import re
import socket
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool

from .domain import Command, Fault
from .control_lease import LeaseCommand
from .diagnostics import DiagnosticFastAPI, adopt_authenticated_id
from pydantic import ValidationError


def rpc(command):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(30)
        sock.connect('/run/amnezia-config-api/agent.sock')
        sock.sendall(json.dumps(command).encode() + b'\n')
        data = bytearray()
        while not data.endswith(b'\n'):
            chunk = sock.recv(65536)
            if not chunk or len(data) + len(chunk) > 4 * 1024 * 1024:
                raise Fault('agent_unavailable', 503)
            data.extend(chunk)
    response = json.loads(data)
    if not response.get('ok'):
        raise Fault(response.get('detail', 'agent_unavailable'), response.get('status', 503))
    return response['data']


def create_app(token=None, transport=rpc, server_id=None):
    server_id = server_id or os.environ.get('AWG_API_SERVER_ID')
    if server_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', server_id):
        raise ValueError('invalid server identity')
    if token is None:
        token = Path(os.environ.get('AWG_API_TOKEN_FILE', '/etc/amnezia-config-api/http.token')).read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', token):
        raise ValueError('invalid API token')
    application = DiagnosticFastAPI(diagnostic_service='amnezia-config-api', title='Amnezia Config API', version='1.1.2', docs_url=None, redoc_url=None, openapi_url=None)

    @application.middleware('http')
    async def guard(request, call_next):
        authorization = request.headers.getlist('authorization')
        if len(authorization) != 1 or not hmac.compare_digest(authorization[0].encode(), ('Bearer ' + token).encode()):
            response = JSONResponse({'detail': 'unauthorized'}, status_code=401)
        else:
            adopt_authenticated_id(request.scope)
            response = await call_next(request)
        response.headers.update({'Cache-Control': 'private, no-store, max-age=0', 'Pragma': 'no-cache', 'X-Content-Type-Options': 'nosniff'})
        return response

    async def invoke(operation, request=None, client_id=None):
        payload = {}
        try:
            if request is not None:
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > 8192:
                        raise Fault('request_too_large', 413)
                if body:
                    payload = json.loads(body)
                    if not isinstance(payload, dict):
                        raise Fault('invalid_request', 422)
            if 'operation' in payload or 'client_id' in payload:
                raise Fault('invalid_request', 422)
            command = (LeaseCommand if operation == 'control_lease' else Command).model_validate({**payload, 'operation': operation, 'client_id': client_id})
            if operation in ('connection', 'usage') and server_id is None:
                raise Fault('server_identity_unconfigured', 503)
            result = await run_in_threadpool(transport, command.model_dump())
            if operation in ('health', 'connection', 'usage') and server_id is not None:
                result = {**result, 'server_id': server_id}
            if operation in ('configuration', 'amnezia'):
                return PlainTextResponse(result['configuration'])
            return JSONResponse(result)
        except Fault as error:
            return JSONResponse({'detail': error.code}, status_code=error.status)
        except (ValueError, ValidationError):
            return JSONResponse({'detail': 'invalid_request'}, status_code=422)
        except Exception:
            return JSONResponse({'detail': 'agent_unavailable'}, status_code=503)

    @application.get('/v1/health')
    async def health():
        return await invoke('health')

    @application.post('/v1/control-lease')
    async def control_lease(request: Request):
        return await invoke('control_lease', request)

    @application.get('/v1/clients')
    async def listing():
        return await invoke('list')

    @application.post('/v1/clients')
    async def create(request: Request):
        return await invoke('create', request)

    @application.get('/v1/clients/{client_id}')
    async def get(client_id: str):
        return await invoke('get', client_id=client_id)

    @application.get('/v1/clients/{client_id}/connection')
    async def connection(client_id: str):
        return await invoke('connection', client_id=client_id)

    @application.get('/v1/clients/{client_id}/usage')
    async def usage(client_id: str):
        return await invoke('usage', client_id=client_id)

    @application.get('/v1/clients/{client_id}/configuration')
    async def configuration(client_id: str):
        return await invoke('configuration', client_id=client_id)

    @application.get('/v1/clients/{client_id}/amnezia')
    async def amnezia(client_id: str):
        return await invoke('amnezia', client_id=client_id)

    @application.post('/v1/clients/{client_id}/{operation}')
    async def mutate(client_id: str, operation: str, request: Request):
        if operation not in {'renew', 'replace', 'disable', 'enable'}:
            return JSONResponse({'detail': 'not_found'}, status_code=404)
        return await invoke(operation, request, client_id)

    return application
