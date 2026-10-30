"""Control API outage must preserve only bounded, previously authorized service."""

from datetime import timedelta
import pytest
from pydantic import ValidationError
from app import control_lease, domain
from app.domain import Engine, Fault, stamp, now
import test_engine
from test_engine import create

engine = test_engine.engine


@pytest.fixture
def clock(engine, monkeypatch):
    start = now()
    value = {"mono": 1000.0, "wall": start}
    engine.control_lease.clock = lambda: value["mono"]
    monkeypatch.setattr(control_lease, "now", lambda: value["wall"])
    monkeypatch.setattr(domain, "now", lambda: value["wall"])
    return value


def grant(engine, clock, sequence=1, offline=600):
    body = {
        "operation": "control_lease",
        "controller_id": "ctl_" + "a" * 32,
        "sequence": sequence,
        "valid_until": stamp(clock["wall"] + timedelta(seconds=90)),
        "version": 2,
        "offline_until": stamp(clock["wall"] + timedelta(seconds=offline)),
    }
    engine.execute(body)
    return body


def advance(clock, seconds):
    clock["mono"] += seconds
    clock["wall"] += timedelta(seconds=seconds)


def test_outage_serves_existing_peer_until_permission_ends(engine, clock):
    peer = create(engine)
    grant(engine, clock)
    keys = engine.backend.peers.copy()
    advance(clock, 91)
    for _ in range(3):
        engine.reconcile()
        assert engine.backend.peers == keys
        assert not engine.control_lease.fresh()
        assert engine.control_lease.allowed()
    assert engine.get(peer["client_id"])["expires_at"] == peer["expires_at"]
    advance(clock, 509)
    engine.reconcile()
    assert not engine.backend.peers
    assert not engine.control_lease.allowed()


@pytest.mark.parametrize("operation", ["create", "renew", "replace", "enable"])
def test_outage_rejects_new_or_extended_access_before_db_mutation(
    engine, clock, operation
):
    peer = create(engine)
    grant(engine, clock)
    advance(clock, 91)
    before = engine.rows()
    command = {"operation": operation}
    if operation != "create":
        command["client_id"] = peer["client_id"]
    with pytest.raises(Fault, match="control_lease_expired"):
        engine.execute(command)
    assert engine.rows() == before
    assert engine.backend.peers


def test_disable_during_outage_survives_fresh_grant_and_restart(engine, clock):
    peer = create(engine)
    grant(engine, clock)
    advance(clock, 91)
    engine.execute({"operation": "disable", "client_id": peer["client_id"]})
    assert not engine.backend.peers
    grant(engine, clock, sequence=2)
    assert not engine.backend.peers
    restarted = Engine(engine.store, engine.backend)
    restarted.control_lease.clock = lambda: clock["mono"]
    grant(restarted, clock, sequence=3)
    assert not restarted.backend.peers
    assert not restarted.get(peer["client_id"])["enabled"]


def test_paid_expiry_wins_and_clock_rollback_cannot_reopen(engine, clock):
    peer = create(engine, end=stamp(clock["wall"] + timedelta(seconds=150)))
    grant(engine, clock)
    advance(clock, 100)
    clock["wall"] -= timedelta(days=1)
    engine.reconcile()
    assert engine.backend.peers
    effective = engine.control_lease.effective_expiry(engine.get(peer["client_id"]))
    assert control_lease.remaining_until(effective, clock["wall"]) <= 50
    advance(clock, 50)
    engine.reconcile()
    assert not engine.backend.peers
    clock["wall"] -= timedelta(days=1)
    engine.reconcile()
    assert not engine.backend.peers


def test_permission_expiry_latches_on_wall_jump(engine, clock):
    create(engine)
    grant(engine, clock)
    clock["wall"] += timedelta(hours=1)
    engine.reconcile()
    clock["wall"] -= timedelta(hours=1)
    engine.reconcile()
    assert not engine.backend.peers
    assert not engine.control_lease.allowed()


def test_process_restart_and_same_sequence_remain_closed(engine, clock):
    create(engine)
    body = grant(engine, clock)
    restarted = Engine(engine.store, engine.backend)
    restarted.control_lease.clock = lambda: clock["mono"]
    restarted.reconcile()
    assert not restarted.backend.peers
    result = restarted.execute(body)
    assert not result["active"] and not result["fresh"]
    assert not restarted.backend.peers
    grant(restarted, clock, sequence=2)
    assert restarted.backend.peers


def test_replay_cannot_extend_deadlines_or_change_permission(engine, clock):
    create(engine)
    body = grant(engine, clock)
    original = engine.control_lease.offline_deadline
    advance(clock, 10)
    engine.execute(body)
    assert engine.control_lease.offline_deadline == original
    for change in (
        {"offline_until": stamp(clock["wall"] + timedelta(seconds=900))},
        {"version": 1, "offline_until": None},
    ):
        with pytest.raises(Fault, match="lease_sequence_conflict"):
            engine.execute({**body, **change})
    # v1 with a new sequence deliberately removes the extended permission.
    engine.execute({**body, "version": 1, "offline_until": None, "sequence": 2})
    assert engine.control_lease.describe()["offline_until"] is None
    advance(clock, 80)
    engine.reconcile()
    assert not engine.backend.peers


@pytest.mark.parametrize("offline", [30, 3601])
def test_bounds_rejected_before_recording_permission(engine, clock, offline):
    with pytest.raises(Fault, match="invalid_control_lease"):
        grant(engine, clock, offline=offline)
    assert engine.control_lease.row() is None


@pytest.mark.parametrize(
    "body", [{"version": 2}, {"version": 1, "offline_until": "2099-01-01T00:00:00Z"}]
)
def test_version_requires_explicit_matching_fields(body):
    with pytest.raises(ValidationError):
        control_lease.LeaseCommand.model_validate(
            {
                "operation": "control_lease",
                "controller_id": "ctl_" + "a" * 32,
                "sequence": 1,
                "valid_until": "2099-01-01T00:00:00Z",
                **body,
            }
        )


@pytest.mark.parametrize("version", [True, False, 2.0, "2"])
def test_version_rejects_coercion(version):
    with pytest.raises(ValidationError):
        control_lease.LeaseCommand.model_validate(
            {
                "operation": "control_lease",
                "controller_id": "ctl_" + "a" * 32,
                "sequence": 1,
                "valid_until": "2099-01-01T00:00:00Z",
                "version": version,
                "offline_until": "2099-01-01T00:01:00Z",
            }
        )


def test_http_v2_contract_and_stale_create_rejection(engine, clock):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from test_openapi_contract import assert_response

    create(engine)
    with TestClient(
        create_app("t" * 40, engine.execute, server_id="node-test")
    ) as client:
        headers = {"Authorization": "Bearer " + "t" * 40}
        payload = {
            "controller_id": "ctl_" + "a" * 32,
            "sequence": 1,
            "version": 2,
            "valid_until": stamp(clock["wall"] + timedelta(seconds=90)),
            "offline_until": stamp(clock["wall"] + timedelta(seconds=600)),
        }
        response = client.post("/v1/control-lease", headers=headers, json=payload)
        assert response.status_code == 200
        assert_response("amnezia", "POST", "/v1/control-lease", response)
        assert response.json()["offline_until"] == payload["offline_until"]
        advance(clock, 91)
        response = client.post(
            "/v1/clients",
            headers=headers,
            json={
                "external_id": "new-device",
                "name": "New",
                "expires_at": stamp(clock["wall"] + timedelta(days=1)),
            },
        )
        assert response.status_code == 503
        assert response.json()["detail"] == "control_lease_expired"
        assert len(engine.rows()) == len(engine.backend.peers) == 1


def test_failed_offline_journal_write_cannot_publish_new_permission(engine, clock):
    create(engine)
    grant(engine, clock)
    before = engine.control_lease.row()
    deadlines = (engine.control_lease.deadline, engine.control_lease.offline_deadline)
    with engine.store.db() as db:
        db.execute(
            "CREATE TRIGGER reject_permission BEFORE INSERT ON control_offline "
            "BEGIN SELECT RAISE(ABORT, 'synthetic storage failure'); END"
        )
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError, match="synthetic storage failure"):
        grant(engine, clock, sequence=2, offline=1200)
    assert engine.control_lease.row() == before
    assert (
        engine.control_lease.deadline,
        engine.control_lease.offline_deadline,
    ) == deadlines
