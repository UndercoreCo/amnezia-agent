"""Optional measurements, isolated from access/expiry enforcement. No billing."""
import hashlib
import json
import os
import logging
import time
import sqlite3
import uuid
from pathlib import Path
from datetime import timedelta
from .domain import Fault, now, stamp

BASIS = 'awg-transfer-v1'
MAX_BYTES = 2**63 - 1


class UsageSnapshots:
    def __init__(self, path):
        self.path = Path(path)
        with self.db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS samples (
                client_id TEXT NOT NULL, epoch TEXT PRIMARY KEY, source TEXT NOT NULL,
                sequence INTEGER NOT NULL, first_at TEXT NOT NULL, observed_at TEXT NOT NULL,
                download TEXT NOT NULL, upload TEXT NOT NULL,
                baseline_download TEXT NOT NULL, baseline_upload TEXT NOT NULL,
                final INTEGER NOT NULL DEFAULT 0)""")
            db.execute('CREATE INDEX IF NOT EXISTS samples_client ON samples(client_id, observed_at)')
        os.chmod(self.path, 0o600)

    def db(self):
        # Dedicated DB: telemetry failures cannot roll back lifecycle state.
        from contextlib import contextmanager
        @contextmanager
        def transaction():
            db = sqlite3.connect(self.path, timeout=1)
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
        return transaction()

    def capture(self, backend, rows, final_keys=()):
        epoch, counters = backend.transfer_snapshot()
        observed = stamp(now())
        with self.db() as db:
            retention = max(7, min(90, int(os.environ.get('AWG_USAGE_RETENTION_DAYS', '7'))))
            db.execute('DELETE FROM samples WHERE final=1 AND observed_at<?', (stamp(now()-timedelta(days=retention)),))
            for row in rows:
                key = row['public_key']
                previous = db.execute('SELECT * FROM samples WHERE client_id=? AND final=0 ORDER BY observed_at DESC LIMIT 1', (row['client_id'],)).fetchone()
                if key not in counters:
                    # Absence is not zero; retain the last measurement and close its epoch.
                    if previous:
                        db.execute('UPDATE samples SET final=1, sequence=sequence+1 WHERE epoch=?', (previous['epoch'],))
                    continue
                value = counters[key]
                rx, tx = value['rx'], value['tx']
                if any(type(n) is not int or not 0 <= n <= MAX_BYTES for n in (rx, tx)):
                    raise Fault('counter_invalid', 503)
                source = hashlib.sha256((epoch + ':' + value['generation'] + ':' + key).encode()).hexdigest()
                # Client directions are inverse to the server RX/TX.
                changed = previous is None or previous['source'] != source or tx < int(previous['download']) or rx < int(previous['upload'])
                if changed:
                    if previous:
                        db.execute('UPDATE samples SET final=1, sequence=sequence+1 WHERE epoch=?', (previous['epoch'],))
                    db.execute('INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                               (row['client_id'], uuid.uuid4().hex, source, 1, observed, observed,
                                str(tx), str(rx), str(tx), str(rx), int(key in final_keys)))
                else:
                    db.execute('UPDATE samples SET sequence=sequence+1, observed_at=?, download=?, upload=?, final=? WHERE epoch=?',
                               (observed, str(tx), str(rx), int(key in final_keys), previous['epoch']))

    def read(self, client_id):
        with self.db() as db:
            rows = db.execute('SELECT * FROM samples WHERE client_id=? ORDER BY first_at, epoch LIMIT 65', (client_id,)).fetchall()
        if len(rows) > 64:
            # Never silently truncate a history the caller has not acknowledged.
            raise Fault('usage_history_limit', 503)
        return [{'counter_epoch': r['epoch'], 'sequence': r['sequence'],
                 'measurement_basis': BASIS, 'observed_at': r['observed_at'],
                 'started_at': r['first_at'], 'download_bytes': r['download'],
                 'upload_bytes': r['upload'], 'baseline_download_bytes': r['baseline_download'],
                 'baseline_upload_bytes': r['baseline_upload'], 'is_final': bool(r['final']),
                 'complete': False} for r in rows]


def poll_seconds():
    try:
        return max(15, min(300, int(os.environ.get('AWG_USAGE_POLL_SECONDS', '60'))))
    except ValueError:
        return 60


def enabled():
    return os.environ.get('AWG_USAGE_ENABLED', '0') == '1'


def capture(engine, final_keys=()):
    if not enabled():
        return
    store = UsageSnapshots(engine.store.path.with_name('usage.sqlite3'))
    store.capture(engine.backend, engine.rows(), final_keys)
    engine.last_usage_capture = time.monotonic()


_last_warning = 0.0


def best_effort(engine, final_keys=()):
    try:
        capture(engine, final_keys)
    except Exception:
        # This must never trigger the lifecycle emergency-stop path.
        global _last_warning
        if time.monotonic() - _last_warning >= 60:
            logging.getLogger(__name__).warning('usage_collection_failed')
            _last_warning = time.monotonic()


def read(engine, client_id):
    if not enabled():
        raise Fault('usage_unsupported', 422)
    row = engine.get(client_id)
    interval = poll_seconds()
    if time.monotonic() - getattr(engine, 'last_usage_capture', 0) >= interval:
        capture(engine)
    samples = UsageSnapshots(engine.store.path.with_name('usage.sqlite3')).read(client_id)
    return {'schema_version': 1, 'status': 'ok', 'protocol': 'amneziawg',
            'client_id': client_id, 'external_id': row['external_id'], 'samples': samples}
