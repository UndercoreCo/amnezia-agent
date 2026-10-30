"""Unchanged native state is read, drift is repaired, health cannot grant time."""
import json
from datetime import timedelta
import pytest
from cryptography.fernet import Fernet
from app.backend import DockerBackend
from app.domain import Engine, Store, Fault, keys, now, stamp
from app.runtime import Executor
from app.runtime_client import RuntimeBackend
from test_export import fixture
from test_runtime_boundary import Kernel, peer


class Native(DockerBackend):
    """Model Docker output (not the reconciliation decision)."""
    def __init__(self):
        config, self.row, self.secret = fixture()
        config['network'] = '10.78.0.0/24'
        super().__init__(config)
        self.configuration_text = '[Interface]\nListenPort = 44537\nDisableCookies = off\nRandomTrailers = off\n'
        self.epoch = 'boot-1'
        self.calls = []
        self.restart_during_read = False

    def run(self, args, data=None, **kwargs):
        self.calls.append(args)
        if args[0] == 'inspect':
            return json.dumps([{'Id': self.epoch, 'Config': {'Labels': dict([self.MANAGED_LABEL])},
                                'State': {'Running': True, 'StartedAt': self.epoch}}])
        if args[:2] == ['exec', '-i']:
            self.configuration_text = '\n'.join(l for l in data.splitlines() if not l.startswith('PrivateKey'))
            self.configuration_text = self.configuration_text.replace('[Peer]\n', '[Peer]\nEndpoint = 192.0.2.10:50000\n')
            self.configuration_text = self.configuration_text.replace('[Interface]\n', '[Interface]\nDisableCookies = off\nRandomTrailers = off\n')
            return ''
        if args[0] == 'exec':
            # No private server key leaves the script in production.
            assert 'dump' not in args and 'sed' in args[4]
            peers = [dict(v)['publickey'] for kind, v in self.projection(self.configuration_text) if kind == '[Peer]']
            if self.restart_during_read: self.epoch = 'boot-2'
            return (self.server_public_key + '\n\n--HANDSHAKES--\n'
                    + ''.join(k+'\t0\n' for k in peers) + '--CONFIG--\n' + self.configuration_text)
        raise AssertionError(args)

    @property
    def writes(self):
        return sum(a[:2] == ['exec', '-i'] for a in self.calls)


def test_unchanged_apply_skips_write_but_reads_native_identity_and_settings():
    backend = Native()
    rows = [(backend.row, backend.secret)]
    backend.apply(rows)
    assert backend.writes == 1
    backend.calls.clear()
    for _ in range(10): backend.apply(rows)
    assert backend.writes == 0
    assert sum(a[0] == 'exec' for a in backend.calls) == 10
    assert sum(a[0] == 'inspect' for a in backend.calls) == 20


@pytest.mark.parametrize('drift', ['psk', 'ip', 'port', 'parameter', 'removed', 'restart'])
def test_actual_drift_is_repaired_without_trusting_previous_apply(drift):
    backend = Native(); rows = [(backend.row, backend.secret)]; backend.apply(rows)
    expected = backend.projection(backend.configuration_text)
    if drift == 'psk': backend.configuration_text = backend.configuration_text.replace(backend.secret['psk'], keys()['psk'])
    elif drift == 'ip': backend.configuration_text = backend.configuration_text.replace('10.78.0.2/32', '10.78.0.3/32')
    elif drift == 'port': backend.configuration_text = backend.configuration_text.replace('44537', '44538')
    elif drift == 'parameter': backend.configuration_text = backend.configuration_text.replace('Jc = 4', 'Jc = 6')
    else:
        backend.configuration_text = '[Interface]\nListenPort = 44537\n'
        if drift == 'restart': backend.epoch = 'boot-2'
    backend.apply(rows)
    assert backend.writes == 2
    assert backend.projection(backend.configuration_text) == expected


def test_restart_during_snapshot_fails_without_write():
    backend = Native(); backend.restart_during_read = True
    with pytest.raises(Fault, match='native_snapshot_changed'): backend.apply([])
    assert backend.writes == 0


def test_health_never_applies_or_renews_runtime_watchdog(tmp_path):
    clock = [0.0]; kernel = Kernel(); executor = Executor(kernel, lambda: clock[0])
    engine = Engine(Store(tmp_path/'state.db', Fernet.generate_key()), RuntimeBackend(executor.execute))
    engine.reconcile(); before = kernel.applies
    for tick in range(1,90):
        clock[0] = tick
        assert engine.execute({'operation':'health'})['status'] == 'ok'
    assert kernel.applies == before
    clock[0] = 90
    with pytest.raises(Fault, match='runtime_stopped'): engine.execute({'operation':'health'})
    assert kernel.stops == 1


def test_unchanged_native_apply_still_updates_independent_expiry_and_watchdog():
    clock = [0.0]; backend = Native(); executor = Executor(backend, lambda: clock[0])
    p = {**peer(seconds=300), 'public_key':backend.row['public_key'], 'psk':backend.secret['psk']}
    executor.execute({'operation':'apply','peers':[p]}); writes = backend.writes
    clock[0] = 80
    extended = {**p, 'expires_at':stamp(now()+timedelta(seconds=400))}
    executor.execute({'operation':'apply','peers':[extended]})
    assert backend.writes == writes
    assert executor.peers[0].expires_at == extended['expires_at']
    clock[0] = 100; executor.tick()  # Fresh successful reconciliation keeps executor alive.
    assert not executor.stopped


def test_malformed_configuration_is_not_equal_to_empty_state():
    with pytest.raises(Fault, match='native_snapshot_invalid'):
        DockerBackend.projection('garbage')


def test_observed_peer_endpoint_is_not_desired_state():
    backend = Native(); rows = [(backend.row, backend.secret)]
    backend.apply(rows)
    backend.configuration_text = backend.configuration_text.replace('192.0.2.10:50000', '192.0.2.11:60000')
    backend.apply(rows)
    assert backend.writes == 1


def test_snapshot_rpc_never_exposes_native_psk_or_server_key():
    backend = Native(); backend.apply([(backend.row, backend.secret)])
    executor = Executor(backend)
    result = json.dumps(executor.execute({'operation':'snapshot'}))
    assert backend.secret['psk'] not in result
    assert backend.config['server_private_key'] not in result
    assert backend.row['public_key'] in result
