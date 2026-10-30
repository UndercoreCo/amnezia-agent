"""Privilege boundary, failure recovery and expiry with the real domain engine."""
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError
from app import runtime, backend
from app.domain import Engine, Store, Fault, keys, now, stamp
from app.runtime import Executor
from app.runtime_client import RuntimeBackend
from test_export import fixture


class Kernel(backend.DockerBackend):
    def __init__(self):
        config, _, _ = fixture()
        config['network'] = '10.78.0.0/24'
        super().__init__(config)
        self.peers, self.stops, self.applies = set(), 0, 0
        self.epoch = 'boot-1'

    def snapshot(self):
        return self.epoch, self.peers.copy(), {}

    def apply(self, rows):
        self.applies += 1
        self.peers = {row['public_key'] for row, _ in rows}

    def emergency_stop(self):
        self.stops += 1
        self.peers.clear()


def peer(ip='10.78.0.2', seconds=60):
    secret = keys()
    return {'public_key': secret['public'], 'psk': secret['psk'], 'ip': ip,
            'expires_at': stamp(now() + timedelta(seconds=seconds))}


@pytest.fixture
def executor():
    return Executor(Kernel())


@pytest.mark.parametrize('payload', [
    {'operation': 'exec', 'args': ['sh']},
    {'operation': 'start'},
    {'operation': 'snapshot', 'container': 'foreign'},
    {'operation': 'stop', 'host': 'unix:///another.sock'},
    {'operation': 'apply', 'config': '[Interface]\nPostUp=bad'},
    {'operation': 'apply'}, {'operation': 'snapshot', 'peers': []},
    {'operation': 'apply', 'peers': [{'private_key': 'not allowed'}]},
])
def test_rejected_command_does_not_reach_native(executor, payload):
    with pytest.raises((Fault, ValidationError)):
        executor.execute(payload)
    assert executor.backend.applies == executor.backend.stops == 0


@pytest.mark.parametrize('overrides', [
    {'ip': '10.78.0.1'}, {'ip': '10.78.0.0'}, {'ip': '10.78.0.255'},
    {'ip': '10.79.0.2'}, {'ip': '::1'}, {'ip': '10.78.0.2/32'},
    {'ip': '10.78.0.2\nPostUp=bad'}, {'public_key': 'x\n[Peer]'},
    {'psk': 'A'*43+'='}, {'expires_at': '2020-01-01T00:00:00Z'},
])
def test_peer_validation_prevents_injection_and_pool_escape(executor, overrides):
    with pytest.raises((Fault, ValueError)):
        executor.execute({'operation': 'apply', 'peers': [{**peer(), **overrides}]})
    assert executor.backend.applies == 0


def test_duplicate_address_or_key_is_rejected(executor):
    first = peer()
    for second in (peer(), {**first, 'ip': '10.78.0.3'}):
        with pytest.raises(Fault, match='invalid_peer'):
            executor.execute({'operation': 'apply', 'peers': [first, second]})
    assert executor.backend.applies == 0


def test_state_backend_only_receives_public_node_settings(executor):
    bridge = RuntimeBackend(executor.execute)
    assert set(bridge.config) == {'endpoint', 'dns', 'parameters', 'network', 'server_public_key'}
    assert executor.backend.config['server_private_key'] not in json.dumps(bridge.config)
    _, row, secret = fixture()
    assert bridge.configuration(row, secret) == executor.backend.configuration(row, secret)
    assert bridge.amnezia(row, secret) == executor.backend.amnezia(row, secret)


def test_runtime_expiry_without_state_agent_preserves_other_peer(executor, monkeypatch):
    start = now()
    first, second = peer(seconds=2), peer(ip='10.78.0.3', seconds=60)
    executor.execute({'operation': 'apply', 'peers': [first, second]})
    monkeypatch.setattr(runtime, 'now', lambda: start + timedelta(seconds=3))
    executor.tick()
    assert executor.backend.peers == {second['public_key']}
    assert executor.backend.stops == 0


def test_read_traffic_cannot_keep_expiry_lease_alive():
    clock = [0.0]
    executor = Executor(Kernel(), lambda: clock[0])
    executor.execute({'operation': 'apply', 'peers': [peer(seconds=300)]})
    clock[0] = 89
    executor.execute({'operation': 'snapshot'})
    executor.execute({'operation': 'metadata'})
    clock[0] = 90
    with pytest.raises(Fault, match='runtime_stopped'):
        executor.tick()
    assert not executor.backend.peers and executor.backend.stops == 1
    with pytest.raises(Fault, match='runtime_stopped'):
        executor.execute({'operation': 'apply', 'peers': []})


def test_stop_failure_is_latched(executor, monkeypatch):
    def fail(): raise Fault('vpn_unavailable', 503)
    monkeypatch.setattr(executor.backend, 'emergency_stop', fail)
    with pytest.raises(Fault): executor.execute({'operation': 'stop'})
    assert executor.stopped
    with pytest.raises(Fault): executor.execute({'operation': 'apply', 'peers': []})
    assert executor.backend.applies == 0


def test_lost_runtime_reply_and_state_restart_keep_durable_identity(executor, tmp_path):
    lost = [True]
    def transport(command):
        result = executor.execute(command)
        if command['operation'] == 'apply' and command['peers'] and lost[0]:
            lost[0] = False
            raise Fault('runtime_unavailable', 503)
        return result
    store = Store(tmp_path/'state.db', Fernet.generate_key())
    engine = Engine(store, RuntimeBackend(transport))
    command = {'operation': 'create', 'external_id': 'test', 'name': 'Test',
               'expires_at': stamp(now() + timedelta(days=1))}
    with pytest.raises(Fault): engine.execute(command)
    key, client_id = engine.rows()[0]['public_key'], engine.rows()[0]['client_id']
    restarted = Engine(store, RuntimeBackend(executor.execute))
    assert restarted.execute(command)['client_id'] == client_id
    assert executor.backend.peers == {key}
    restarted.execute({'operation': 'disable', 'client_id': client_id})
    assert not executor.backend.peers
    executor.backend.epoch = 'boot-2'
    restarted.reconcile()
    assert not executor.backend.peers


def test_docker_binary_host_environment_and_target_are_fixed(monkeypatch):
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs)); return SimpleNamespace(returncode=0, stdout='')
    monkeypatch.setattr(backend.subprocess, 'run', run)
    monkeypatch.setenv('DOCKER_HOST', 'tcp://foreign:2375')
    native = Kernel()
    # This test isolates command construction; native readback is exercised separately.
    monkeypatch.setattr(native, 'snapshot', lambda: setattr(native, '_observed_projection', None))
    backend.DockerBackend.apply(native, [({'public_key': keys()['public'], 'ip': '10.78.0.2'}, {'psk': keys()['psk']})])
    backend.DockerBackend.emergency_stop(native)
    assert all(argv[:3] == ['/usr/bin/docker', '--host', 'unix:///run/docker.sock'] for argv, _ in calls)
    assert calls[0][0][3:] == ['exec', '-i', 'undercore-awg-api', 'awg', 'syncconf', 'awg0', '/dev/stdin']
    assert calls[1][0][3:] == ['stop', '--time', '2', 'undercore-awg-api']
    assert all('DOCKER_HOST' not in kwargs['env'] and not kwargs.get('shell') for _, kwargs in calls)
