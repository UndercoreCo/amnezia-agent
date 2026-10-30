"""State/runtime integration at deadline boundaries, with deterministic clocks."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet

from app import domain, runtime, control_lease
from app.domain import Engine, Store, Fault, stamp
from app.runtime_client import RuntimeBackend
from test_runtime_boundary import Kernel


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    class Clock:
        seconds = 0
        def now(self):
            return datetime(2026, 10, 30, tzinfo=timezone.utc) + timedelta(seconds=self.seconds)
    clock = Clock()
    for module in (domain, runtime, control_lease):
        monkeypatch.setattr(module, 'now', clock.now)
    kernel = Kernel()
    executor = runtime.Executor(kernel, lambda: clock.seconds)
    hook = {'stage': None, 'after_apply': False}
    apply = kernel.apply
    def native_apply(rows):
        apply(rows)
        if hook['stage'] == 'during_apply':
            hook['stage'] = None
            clock.seconds = 25
    monkeypatch.setattr(kernel, 'apply', native_apply)
    def transport(command):
        op = command['operation']
        if hook['stage'] == 'before_validation' and op == 'apply':
            hook['stage'] = None
            clock.seconds = 25
        if hook['stage'] == 'before_readback' and op == 'snapshot' and hook['after_apply']:
            hook['stage'] = None
            clock.seconds = 25
        result = executor.execute(command)
        if op == 'apply':
            hook['after_apply'] = True
        if hook['stage'] == 'after_readback' and op == 'snapshot' and hook['after_apply']:
            hook['stage'] = None
            clock.seconds = 25
        return result
    engine = Engine(Store(tmp_path/'state.db', Fernet.generate_key()), RuntimeBackend(transport))
    engine.control_lease.clock = lambda: clock.seconds
    def create(name, seconds):
        return engine.execute({'operation': 'create', 'external_id': name, 'name': name,
                               'expires_at': stamp(clock.now()+timedelta(seconds=seconds))})
    create('long', 600)
    create('short', 20)
    hook['after_apply'] = False
    return engine, executor, clock, hook


@pytest.mark.parametrize('stage', ['before_validation', 'during_apply', 'before_readback', 'after_readback'])
def test_expiry_during_reconcile_preserves_live_peer_and_keys(boundary, stage):
    engine, executor, clock, hook = boundary
    before = {r['client_id']: (r['public_key'], r['secret']) for r in engine.rows()}
    long = next(r for r in engine.rows() if r['external_id'] == 'long')
    hook['stage'] = stage
    engine.reconcile()
    assert executor.backend.peers == {long['public_key']}
    assert executor.backend.stops == 0
    assert {r['client_id']: (r['public_key'], r['secret']) for r in engine.rows()} == before
    assert all(r['phase'] == 'ready' for r in engine.rows())
    engine.reconcile()
    assert executor.backend.peers == {long['public_key']}


def test_offline_deadline_crossed_during_initial_snapshot_is_not_identity_conflict(boundary):
    engine, executor, clock, hook = boundary
    engine.execute({'operation': 'control_lease', 'version': 2, 'controller_id': 'ctl_'+'a'*32,
                    'sequence': 1, 'valid_until': stamp(clock.now()+timedelta(seconds=5)),
                    'offline_until': stamp(clock.now()+timedelta(seconds=10))})
    snapshot = engine.backend.snapshot
    def crossing_snapshot():
        clock.seconds = 11
        return snapshot()
    engine.backend.snapshot = crossing_snapshot
    engine.reconcile()
    assert not executor.backend.peers
    assert all(r['phase'] == 'ready' for r in engine.rows())
    engine.backend.snapshot = snapshot
    engine.execute({'operation': 'control_lease', 'version': 2, 'controller_id': 'ctl_'+'a'*32,
                    'sequence': 2, 'valid_until': stamp(clock.now()+timedelta(seconds=5)),
                    'offline_until': stamp(clock.now()+timedelta(seconds=10))})
    assert len(executor.backend.peers) == 2


@pytest.mark.parametrize('change', ['drop_live', 'epoch', 'foreign'])
def test_expiry_does_not_hide_unrelated_native_failure(boundary, change):
    engine, executor, clock, hook = boundary
    snapshot = engine.backend.snapshot
    apply = engine.backend.apply
    armed = [False]
    def apply_then_arm(rows):
        apply(rows)
        armed[0] = True
    def broken_readback():
        if armed[0]:
            clock.seconds = 25
            executor.tick()
            if change == 'epoch':
                executor.backend.epoch = 'another-boot'
            elif change == 'foreign':
                executor.backend.peers.add('foreign')
            else:
                executor.backend.peers.clear()
        return snapshot()
    engine.backend.apply = apply_then_arm
    engine.backend.snapshot = broken_readback
    with pytest.raises(Fault):
        engine.reconcile()


def test_invalid_peer_without_expiry_is_not_retried(boundary):
    engine, executor, clock, hook = boundary
    calls = []
    def reject(rows):
        calls.append(True)
        raise Fault('invalid_peer', 422)
    engine.backend.apply = reject
    with pytest.raises(Fault, match='invalid_peer'):
        engine.reconcile()
    assert len(calls) == 1


def test_periodic_agent_sweep_does_not_stop_live_peers_at_expiry(boundary, tmp_path, monkeypatch):
    from app import agent
    engine, executor, clock, hook = boundary
    hook['stage'] = 'during_apply'
    monkeypatch.setattr(agent.os, 'chown', lambda *args: None)
    monkeypatch.setattr(agent.time, 'monotonic', lambda: 1000.0)
    long = next(r['public_key'] for r in engine.rows() if r['external_id'] == 'long')
    class Finished(Exception):
        pass
    def ready():
        assert executor.backend.peers == {long}
        assert executor.backend.stops == 0
        raise Finished()
    with pytest.raises(Finished):
        agent.serve(engine, tmp_path/'ipc/agent.sock', 0, ready)
    assert executor.backend.stops == 1  # Only test shutdown, not expiry.


def test_cleanup_failure_preserves_safe_primary_diagnostic(tmp_path, monkeypatch, caplog):
    from types import SimpleNamespace
    from app import agent
    stops = []
    def reconcile():
        raise Fault('apply_unconfirmed', 503)
    def stop():
        stops.append(True)
        raise ValueError('DO_NOT_LOG_PRIVATE_KEY')
    monkeypatch.setattr(agent.os, 'chown', lambda *args: None)
    monkeypatch.setattr(agent.time, 'monotonic', lambda: 1000.0)
    engine = SimpleNamespace(reconcile=reconcile, backend=SimpleNamespace(emergency_stop=stop))
    with pytest.raises(RuntimeError, match='Expiry reconciliation failed'):
        agent.serve(engine, tmp_path/'ipc/agent.sock', 0)
    assert stops == [True]
    assert 'code=apply_unconfirmed' in caplog.text
    assert 'emergency_stop_failed code=unexpected_error' in caplog.text
    assert 'DO_NOT_LOG_PRIVATE_KEY' not in caplog.text
    assert not (tmp_path/'ipc/agent.sock').exists()


def test_retry_budget_is_bounded_for_continuously_crossing_deadlines(boundary):
    engine, executor, clock, hook = boundary
    # Force readback always to land beyond another member's deadline. Even this
    # adversarial backend cannot cause unbounded work or a false success.
    calls = []
    def racing_apply(rows):
        calls.append(True)
        clock.seconds = 25 if len(calls) == 1 else 601
        raise Fault('invalid_peer', 422)
    engine.backend.apply = racing_apply
    with pytest.raises(Fault, match='invalid_peer'):
        engine.reconcile()
    assert len(calls) <= 3


def test_expiry_cannot_hide_a_different_apply_error(boundary):
    engine, executor, clock, hook = boundary
    def lost_reply(rows):
        clock.seconds = 25
        raise Fault('runtime_unavailable', 503)
    engine.backend.apply = lost_reply
    with pytest.raises(Fault, match='runtime_unavailable'):
        engine.reconcile()
