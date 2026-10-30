"""Unprivileged state agent and expiry loop; Docker lives in a separate executor."""
import fcntl
import json
import logging
import os
import re
import signal
import socket
import sys
import time
from pathlib import Path

from pydantic import ValidationError
from .runtime_client import RuntimeBackend
from .local_rpc import MAX_REQUEST, REQUEST_SECONDS, authorize_peer, read_request, notify
from .domain import Engine, Store, Fault


def failure_code(error):
    # Only program-defined fault codes; never log exception bodies or inputs.
    return error.code if isinstance(error, Fault) and re.fullmatch(r'[a-z][a-z0-9_]{0,63}', error.code) else 'unexpected_error'


def serve(engine, socket_path, group_id, ready=None, *, allowed_uid=None):
    socket_path = Path(socket_path)
    socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(socket_path.parent, os.geteuid(), group_id)
    os.chmod(socket_path.parent, 0o750)
    lock = open(str(socket_path) + '.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    socket_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(socket_path))
    os.chown(socket_path, os.geteuid(), group_id)
    os.chmod(socket_path, 0o660)
    server.listen(16)
    server.settimeout(1)
    last_sweep = 0
    last_usage = 0
    try:
        while True:
            if time.monotonic() - last_sweep >= 15:
                try:
                    engine.reconcile()
                except Exception as error:
                    logging.getLogger(__name__).error('expiry_reconciliation_failed code=%s', failure_code(error))
                    raise RuntimeError('Expiry reconciliation failed; stopping managed tunnel.') from None
                last_sweep = time.monotonic()
                if ready:
                    ready()
            from .usage import poll_seconds
            if time.monotonic() - last_usage >= poll_seconds():
                from .usage import best_effort
                best_effort(engine)
                last_usage = time.monotonic()
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(2)
                try:
                    authorize_peer(connection, allowed_uid)
                    request = read_request(connection)
                    result = {'ok': True, 'data': engine.execute(request)}
                except Fault as error:
                    result = {'ok': False, 'detail': error.code, 'status': error.status}
                except (ValueError, ValidationError, socket.timeout, ConnectionError):
                    result = {'ok': False, 'detail': 'invalid_request', 'status': 422}
                except Exception:
                    # Do not serialize exception bodies or key material.
                    result = {'ok': False, 'detail': 'agent_unavailable', 'status': 503}
                try:
                    connection.sendall(json.dumps(result).encode() + b'\n')
                except (OSError, socket.timeout):
                    pass  # Operation is durable; caller replays the same intent.
    finally:
        primary = sys.exc_info()[1]
        server.close()
        socket_path.unlink(missing_ok=True)
        try:
            engine.backend.emergency_stop()
        except Exception as error:
            logging.getLogger(__name__).error('emergency_stop_failed code=%s', failure_code(error))
            if primary is None or isinstance(primary, (SystemExit, KeyboardInterrupt)):
                raise
            # Preserve the initiating failure. The independent executor lease
            # and systemd ExecStopPost still enforce shutdown if IPC is lost.
        finally:
            lock.close()


def main():
    import grp
    import pwd
    os.umask(0o077)
    backend = RuntimeBackend()
    config = backend.config
    store = Store(Path('/var/lib/amnezia-config-api/clients.sqlite3'), Path('/etc/amnezia-config-api/encryption.key').read_bytes().strip())
    engine = Engine(store, backend, config['network'])
    def stop(*_):
        raise SystemExit()
    signal.signal(signal.SIGTERM, stop)
    serve(engine, '/run/amnezia-config-api/agent.sock', grp.getgrnam('awg-api').gr_gid, notify, allowed_uid=pwd.getpwnam('awg-api').pw_uid)


if __name__ == '__main__':
    main()
