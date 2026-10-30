"""Single-writer Amnezia state machine. Secrets only on the VPN host."""
import base64
import ipaddress
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from pydantic import BaseModel, ConfigDict, Field, field_validator


def now():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


class Fault(Exception):
    def __init__(self, code, status=409):
        self.code, self.status = code, status
        super().__init__(code)


def expiry(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or not parsed.utcoffset() == timezone.utc.utcoffset(parsed):
            raise ValueError()
        if parsed.year > 2100:
            raise ValueError()
        return stamp(parsed)
    except (ValueError, TypeError, AttributeError):
        raise Fault('invalid_expiry', 422) from None


class Command(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    operation: str = Field(pattern=r'^(health|list|get|create|renew|enable|disable|configuration|connection|amnezia|replace|usage)$')
    client_id: str | None = Field(default=None, pattern=r'^wgapi_[a-f0-9]{32}$')
    external_id: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_-]{1,100}$')
    device_id: str = Field(default='account-v1', pattern=r'^account-v1$')
    name: str | None = Field(default=None, min_length=1, max_length=120)
    expires_at: str | None = None
    idempotency_key: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_:.+-]{1,160}$')
    expected_external_id: str | None = Field(default=None, pattern=r'^[A-Za-z0-9_-]{1,100}$')
    allow_create: bool = True

    @field_validator('name')
    @classmethod
    def safe_name(cls, value):
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('invalid name')
        return value


def keys():
    private = X25519PrivateKey.generate()
    return {
        'private': base64.b64encode(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode(),
        'public': base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
        'psk': base64.b64encode(secrets.token_bytes(32)).decode(),
    }


class Store:
    def __init__(self, path: Path, encryption_key: bytes):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path, self.cipher = path, Fernet(encryption_key)
        with self.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY, external_id TEXT NOT NULL UNIQUE, device_id TEXT NOT NULL,
                    name TEXT NOT NULL, expires_at TEXT NOT NULL, creation_expires_at TEXT NOT NULL,
                    enabled INTEGER NOT NULL, phase TEXT NOT NULL, ip TEXT NOT NULL UNIQUE,
                    public_key TEXT NOT NULL UNIQUE, secret BLOB NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_key TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL, old_public_key TEXT
                );
                CREATE TABLE IF NOT EXISTS runtime (id INTEGER PRIMARY KEY CHECK(id=1), epoch TEXT NOT NULL, public_keys TEXT NOT NULL);
            ''')
        os.chmod(path, 0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def seal(self, secret):
        return self.cipher.encrypt(json.dumps(secret).encode())

    def unseal(self, row):
        return json.loads(self.cipher.decrypt(row['secret']))


class Engine:
    """Caller holds exclusive process lock. Backend operates only the managed container."""
    def __init__(self, store, backend, network='10.78.0.0/24'):
        self.store, self.backend = store, backend
        from .control_lease import ControlLease
        self.control_lease = ControlLease(store)
        self.network = ipaddress.ip_network(network)
        if self.network.version != 4 or self.network.num_addresses > 65536 or self.network.num_addresses < 8 or not self.network.is_private:
            raise ValueError('invalid private allocation pool')

    def rows(self):
        with self.store.db() as db:
            return [dict(row) for row in db.execute('SELECT * FROM clients ORDER BY created_at, client_id')]

    def reconcile(self):
        rows = self.rows()
        epoch, actual, handshakes = self.backend.snapshot()
        # Snapshot may independently expire peers. Evaluate permission after it,
        # outside the SQLite transaction (lease reads use their own connection).
        permitted = {r['client_id'] for r in rows if self.control_lease.peer_allowed(r)}
        with self.store.db() as db:
            previous = db.execute('SELECT * FROM runtime WHERE id=1').fetchone()
            # Never adopt a manually inserted peer, even after a restart.
            known = {r['public_key'] for r in rows}
            if actual - known:
                raise Fault('unmanaged_peer_detected')
            if previous and previous['epoch'] == epoch:
                expected = set(json.loads(previous['public_keys']))
                missing = expected - actual
                for row in rows:
                    if row['public_key'] in missing and row['phase'] == 'ready' and row['enabled'] and row['expires_at'] > stamp(now()) and row['client_id'] in permitted:
                        db.execute("UPDATE clients SET phase='conflict', updated_at=? WHERE client_id=?", (stamp(now()), row['client_id']))
                        row['phase'] = 'conflict'
        from .usage import best_effort
        # Runtime enforces expiry independently, including during an apply or
        # the following readback. A deadline crossing is not native key loss.
        # Bound retries: persistent drift, epoch changes and unexpected peers
        # must still fail closed rather than loop or silently adopt state.
        for attempt in range(3):
            desired = [r for r in rows if self.control_lease.peer_allowed(r) and r['enabled'] and r['phase'] != 'conflict' and r['expires_at'] > stamp(now())]
            removing = actual - {r['public_key'] for r in desired}
            if removing:
                best_effort(self, removing)
            submitted = [({**r, 'expires_at': self.control_lease.effective_expiry(r)}, self.store.unseal(r)) for r in desired]
            try:
                self.backend.apply(submitted)
            except Fault as error:
                # The request may have been valid when sent but expired before
                # runtime validation. Only a witnessed deadline crossing can
                # retry invalid_peer; all other errors retain their semantics.
                if error.code != 'invalid_peer' or not any(r['expires_at'] <= stamp(now()) for r, _ in submitted):
                    raise
                if attempt == 2:
                    raise
                continue
            epoch_after, present, handshakes = self.backend.snapshot()
            requested = {r['public_key'] for r, _ in submitted}
            wanted = {row['public_key'] for row, (grant, _) in zip(desired, submitted)
                      if grant['expires_at'] > stamp(now()) and self.control_lease.peer_allowed(row)}
            if epoch_after != epoch or present - requested or wanted - present:
                raise Fault('apply_unconfirmed', 503)
            if present == wanted:
                break
            # Readback can itself straddle expiry. Remove only newly expired
            # peers and verify again; never extend their deadlines.
            actual = present
        else:
            raise Fault('apply_unconfirmed', 503)
        with self.store.db() as db:
            db.execute('INSERT OR REPLACE INTO runtime VALUES (1,?,?)', (epoch, json.dumps(sorted(wanted))))
            for row in desired:
                if row['public_key'] not in wanted:
                    continue
                db.execute("UPDATE clients SET phase='ready' WHERE client_id=? AND phase='pending'", (row['client_id'],))
        if wanted - actual:
            best_effort(self)
        return handshakes

    def get(self, client_id):
        with self.store.db() as db:
            row = db.execute('SELECT * FROM clients WHERE client_id=?', (client_id,)).fetchone()
        if row is None:
            raise Fault('not_found', 404)
        return dict(row)

    def view(self, row, handshakes):
        status = ('conflict' if row['phase'] == 'conflict' else 'expired' if row['expires_at'] <= stamp(now())
                  else 'disabled' if not row['enabled'] else 'active' if row['phase'] == 'ready' else 'pending')
        return {**{k: row[k] for k in ('client_id', 'external_id', 'device_id', 'name', 'expires_at', 'created_at', 'updated_at')},
                'status': status, 'last_handshake_at': handshakes.get(row['public_key']), 'connection_checked_at': stamp(now())}

    def execute(self, data):
        from .control_lease import LeaseCommand
        cmd = (LeaseCommand if data.get("operation") == "control_lease" else Command).model_validate(data)
        if cmd.operation == 'usage':
            from .usage import read
            return read(self, cmd.client_id)
        if cmd.operation == 'health':
            # Availability reads never apply settings or refresh the runtime
            # watchdog. Expiry and reconciliation remain independently scheduled.
            _, actual, _ = self.backend.snapshot()
            if actual - {row['public_key'] for row in self.rows()}:
                raise Fault('unmanaged_peer_detected')
            return {'status': 'ok', 'protocol': 'amneziawg', 'version': '1.1.2', 'formats': ['conf', 'amnezia-vpn'], 'expiry_interval_seconds': 15, 'control_lease': self.control_lease.describe()}
        # Mutations still reconcile first: never silently restore missing peers.
        handshakes = self.reconcile()
        if cmd.operation == 'control_lease':
            self.control_lease.grant(cmd.controller_id, cmd.sequence, cmd.valid_until, cmd.offline_until)
            self.reconcile()
            return self.control_lease.describe()
        if cmd.operation == 'list':
            return {'clients': [self.view(r, handshakes) for r in self.rows()]}
        if cmd.operation in ('create', 'renew', 'replace', 'enable') and not self.control_lease.fresh():
            raise Fault('control_lease_expired', 503)
        if cmd.operation == 'create':
            if not cmd.external_id or not cmd.name or not cmd.expires_at:
                raise Fault('invalid_request', 422)
            end = expiry(cmd.expires_at)
            with self.store.db() as db:
                old = db.execute('SELECT * FROM clients WHERE external_id=?', (cmd.external_id,)).fetchone()
                if old:
                    if (old['name'], old['device_id'], old['creation_expires_at']) != (cmd.name, cmd.device_id, end):
                        raise Fault('identity_conflict')
                    client_id = old['client_id']
                else:
                    if end <= stamp(now()):
                        raise Fault('expired', 410)
                    allocated = {r['ip'] for r in db.execute('SELECT ip FROM clients')}
                    address = next((str(ip) for ip in self.network.hosts() if ip != self.network.network_address + 1 and str(ip) not in allocated), None)
                    if address is None:
                        raise Fault('pool_exhausted', 503)
                    secret = keys()
                    client_id, created = 'wgapi_' + uuid.uuid4().hex, stamp(now())
                    db.execute('INSERT INTO clients VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?)',
                               (client_id, cmd.external_id, cmd.device_id, cmd.name, end, end, 'pending', address,
                                secret['public'], self.store.seal(secret), created, created))
        else:
            row = self.get(cmd.client_id)
            client_id = row['client_id']
            if cmd.operation in ('configuration', 'connection', 'amnezia'):
                if not self.control_lease.allowed():
                    raise Fault('control_lease_expired', 503)
                if row['expires_at'] <= stamp(now()) or not self.control_lease.peer_allowed(row):
                    raise Fault('expired', 410)
                if row['phase'] != 'ready' or not row['enabled']:
                    raise Fault('configuration_unavailable', 410 if cmd.operation == 'connection' else 409)
                exporter = self.backend.amnezia if cmd.operation == 'amnezia' else self.backend.configuration
                configuration = exporter(row, self.store.unseal(row))
                if cmd.operation == 'connection':
                    return {'schema_version': 1, 'status': 'ok', 'protocol': 'amneziawg',
                            'client': self.view(row, handshakes), 'configuration': configuration}
                return {'configuration': configuration}
            if cmd.operation == 'get':
                return self.view(row, handshakes)
            if cmd.operation in ('renew', 'replace'):
                if not cmd.expires_at or not cmd.idempotency_key:
                    raise Fault('invalid_request', 422)
                end = expiry(cmd.expires_at)
                with self.store.db() as db:
                    old = db.execute('SELECT * FROM operations WHERE operation_key=?', (cmd.idempotency_key,)).fetchone()
                    if old and (old['kind'], old['client_id'], old['expires_at']) != (cmd.operation, client_id, end):
                        raise Fault('operation_conflict')
                    if cmd.operation == 'replace' and cmd.expected_external_id != row['external_id']:
                        raise Fault('replacement_ownership_conflict')
                    if not old:
                        if end <= stamp(now()):
                            raise Fault('expired', 410)
                        if end < row['expires_at']:
                            raise Fault('lifetime_conflict')
                        if cmd.operation == 'replace':
                            if not cmd.allow_create:
                                raise Fault('replacement_not_started')
                            if row['phase'] != 'conflict':
                                raise Fault('replacement_peer_still_present')
                            secret = keys()
                            db.execute("UPDATE clients SET secret=?,public_key=?,phase='pending' WHERE client_id=?",
                                       (self.store.seal(secret), secret['public'], client_id))
                        elif row['phase'] == 'conflict':
                            raise Fault('identity_conflict')
                        db.execute('INSERT INTO operations VALUES (?,?,?,?,?)', (cmd.idempotency_key, cmd.operation, client_id, end, row['public_key']))
                        db.execute('UPDATE clients SET expires_at=?,updated_at=? WHERE client_id=?', (end, stamp(now()), client_id))
            elif cmd.operation in ('enable', 'disable'):
                if cmd.operation == 'enable' and (row['expires_at'] <= stamp(now()) or row['phase'] == 'conflict'):
                    raise Fault('configuration_unavailable')
                with self.store.db() as db:
                    db.execute('UPDATE clients SET enabled=?,updated_at=? WHERE client_id=?', (int(cmd.operation == 'enable'), stamp(now()), client_id))
        handshakes = self.reconcile()
        result = self.view(self.get(client_id), handshakes)
        if cmd.operation == 'replace':
            result.update(replacement_id=cmd.idempotency_key, replacement_status='completed')
        return result
