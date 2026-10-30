from datetime import timedelta
import pytest
from app.domain import Engine, Fault, now, stamp
from test_engine import engine, create


def grant(engine, seq=1, seconds=60):
    return engine.execute({'operation':'control_lease','controller_id':'ctl_'+'a'*32,
                           'sequence':seq,'valid_until':stamp(now()+timedelta(seconds=seconds))})


def test_gate_expiry_removes_peers_without_changing_paid_expiry(engine):
    peer=create(engine)
    assert grant(engine)['active']
    engine.control_lease.deadline=0
    engine.reconcile()
    assert not engine.backend.peers
    assert engine.get(peer['client_id'])['expires_at']==peer['expires_at']
    with pytest.raises(Fault,match='control_lease_expired'):
        engine.execute({'operation':'configuration','client_id':peer['client_id']})
    assert grant(engine,2)['active']
    assert engine.backend.peers


def test_restart_is_closed_and_old_sequence_cannot_reopen(engine):
    create(engine);response=grant(engine)
    restarted=Engine(engine.store,engine.backend)
    restarted.reconcile()
    assert not engine.backend.peers
    response2=restarted.execute({'operation':'control_lease','controller_id':'ctl_'+'a'*32,
                                 'sequence':1,'valid_until':response['valid_until']})
    assert not response2['active'] and not engine.backend.peers
    assert grant(restarted,2)['active']
    assert engine.backend.peers


def test_controller_and_deadline_limits(engine):
    grant(engine)
    with pytest.raises(Fault,match='controller_conflict'):
        engine.execute({'operation':'control_lease','controller_id':'ctl_'+'b'*32,
                        'sequence':2,'valid_until':stamp(now()+timedelta(seconds=60))})
    with pytest.raises(Fault,match='invalid_control_lease'):grant(engine,2,180)


def test_wall_clock_rollback_never_rearms_expired_gate(engine, monkeypatch):
    create(engine);grant(engine)
    engine.control_lease.deadline=0
    monkeypatch.setattr('app.control_lease.now',lambda: now()-timedelta(days=1))
    engine.reconcile()
    assert not engine.backend.peers
    assert not engine.control_lease.allowed()
