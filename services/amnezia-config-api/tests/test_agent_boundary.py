"""Privileged local requests must not delay expiry indefinitely or choose host actions."""
import json
import socket
import struct
from types import SimpleNamespace

import pytest
from app import agent
from app.domain import Fault


class Connection:
    def __init__(self, chunks, advance=None):
        self.chunks = iter(chunks)
        self.timeouts = []
        self.advance = advance

    def settimeout(self, seconds):
        self.timeouts.append(seconds)

    def recv(self, count):
        if self.advance:
            self.advance()
        chunk = next(self.chunks, b'')
        assert len(chunk) <= count
        return chunk


def test_slow_drip_cannot_reset_total_request_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(agent.time, 'monotonic', lambda: clock[0])
    def advance():
        clock[0] += 0.8
    connection = Connection([b'{', b' ', b' ', b'"operation":"health"}\n'], advance)
    with pytest.raises(Fault, match='invalid_request'):
        agent.read_request(connection)
    assert connection.timeouts == pytest.approx([2, 1.2, 0.4])


@pytest.mark.parametrize('body', [b'', b'{}\n{}\n', b'{}\ntrailing', b'x' * (agent.MAX_REQUEST + 1)])
def test_invalid_or_oversized_frame_rejected(body):
    chunks = [body[i:i+4096] for i in range(0, len(body), 4096)]
    with pytest.raises(Fault, match='invalid_request'):
        agent.read_request(Connection(chunks))


def test_bounded_valid_request_retains_durable_fields():
    request = {'operation': 'replace', 'idempotency_key': 'existing-operation', 'allow_create': False}
    assert agent.read_request(Connection([json.dumps(request).encode() + b'\n'])) == request


@pytest.mark.parametrize('uid,allowed', [(0, True), (1234, True), (2345, False)])
def test_kernel_peer_uid_required_even_if_socket_group_allows_access(monkeypatch, uid, allowed):
    monkeypatch.setattr(socket, 'SO_PEERCRED', 17, raising=False)
    connection = SimpleNamespace(getsockopt=lambda *args: struct.pack('3i', 7, uid, 4567))
    if allowed:
        agent.authorize_peer(connection, 1234)
    else:
        with pytest.raises(Fault, match='unauthorized'):
            agent.authorize_peer(connection, 1234)


def test_local_control_cannot_choose_arbitrary_docker_or_host_operation():
    from app.domain import Command
    from pydantic import ValidationError
    for request in [{'operation': 'exec', 'command': 'anything'},
                    {'operation': 'health', 'container': 'another-container'},
                    {'operation': 'disable', 'socket': '/run/docker.sock'}]:
        with pytest.raises(ValidationError):
            Command.model_validate(request)
