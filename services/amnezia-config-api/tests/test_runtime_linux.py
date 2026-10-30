"""Real Linux UIDs/Unix socket boundary; run as root only in a disposable sandbox.

No Docker socket, network or production files are needed. The kernel backend is
synthetic: these tests do not claim an actual AWG tunnel/systemd acceptance.
"""
import json
import multiprocessing
import os
import socket
import sys
import time

import pytest
from app import runtime
from app.domain import Fault
from test_runtime_boundary import Kernel, peer

pytestmark = pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() != 0,
                               reason='requires isolated Linux root sandbox')


def child_request(path, uid, gid, command, result):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    try:
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(3)
            sock.connect(path)
            sock.sendall(json.dumps(command).encode() + b'\n')
            data = b''
            while not data.endswith(b'\n'):
                part = sock.recv(65536)
                if not part: break
                data += part
        result.put(json.loads(data))
    except PermissionError:
        result.put({'denied_by_filesystem': True})
    except (ConnectionResetError, BrokenPipeError):
        # Server authenticates before reading attacker bytes. Linux may reset
        # a socket closed with unread data instead of delivering the 403 frame.
        result.put({'connection_rejected': True})


def child_server(path, events, ready, lease):
    runtime.LEASE_SECONDS = lease
    class ObservedKernel(Kernel):
        def apply(self, rows):
            super().apply(rows)
            events.put(('apply', sorted(self.peers)))
        def emergency_stop(self):
            super().emergency_stop()
            events.put(('stop', []))
    try:
        runtime.serve(runtime.Executor(ObservedKernel()), path, 61001, 61001, ready.set)
    except Fault:
        pass


@pytest.fixture
def server(tmp_path):
    # pytest parents default to 0700; explicitly make only synthetic fixture reachable.
    for directory in [tmp_path, *list(tmp_path.parents)[:-1]]:
        if str(directory).startswith('/tmp/pytest-'):
            directory.chmod(0o755)
    ctx = multiprocessing.get_context('fork')
    events, ready = ctx.Queue(), ctx.Event()
    path = str(tmp_path/'runtime'/'runtime.sock')
    proc = ctx.Process(target=child_server, args=(path, events, ready, 4))
    proc.start()
    assert ready.wait(3)
    def request(uid, gid, command):
        result = ctx.Queue()
        caller = ctx.Process(target=child_request, args=(path, uid, gid, command, result))
        caller.start(); caller.join(5)
        assert caller.exitcode == 0
        return result.get(timeout=1)
    yield request, events, proc, path
    if proc.is_alive():
        try: request(0, 0, {'operation': 'stop'})
        except Exception: pass
        proc.join(4)
    if proc.is_alive(): proc.kill(); proc.join()


def test_kernel_uid_and_socket_permissions_reject_api_and_foreign_group_member(server):
    request, _, _, path = server
    assert request(61001, 61001, {'operation': 'metadata'})['ok']
    assert request(61002, 61002, {'operation': 'metadata'}) == {'denied_by_filesystem': True}
    # Even accidental membership of the privileged socket group does not authorize another UID.
    assert request(61002, 61001, {'operation': 'metadata'}) in (
        {'ok': False, 'detail': 'unauthorized', 'status': 403}, {'connection_rejected': True})
    assert request(0, 0, {'operation': 'metadata'})['ok']
    assert os.stat(path).st_mode & 0o777 == 0o660


def test_real_process_expiry_and_lease_stop_without_state_agent(server):
    request, events, proc, _ = server
    short, long = peer(seconds=1), peer(ip='10.78.0.3', seconds=60)
    assert request(61001, 61001, {'operation': 'apply', 'peers': [short, long]})['ok']
    assert set(events.get(timeout=2)[1]) == {short['public_key'], long['public_key']}
    kind, actual = events.get(timeout=3)
    assert kind == 'apply' and actual == [long['public_key']]
    proc.join(6)
    assert proc.exitcode == 0
    assert events.get(timeout=1)[0] == 'stop'


def test_state_uid_cannot_read_root_node_key_or_docker_socket(tmp_path):
    ctx = multiprocessing.get_context('fork')
    for directory in [tmp_path, *list(tmp_path.parents)[:-1]]:
        if str(directory).startswith('/tmp/pytest-'): directory.chmod(0o755)
    secret = tmp_path/'node.json'; secret.write_text('synthetic-private-key'); secret.chmod(0o600)
    docker = socket.socket(socket.AF_UNIX); path = str(tmp_path/'docker.sock')
    docker.bind(path); os.chmod(path, 0o660); docker.listen(1)
    result = ctx.Queue()
    def check():
        os.setgroups([]); os.setgid(61001); os.setuid(61001)
        denied = []
        try: secret.read_text()
        except PermissionError: denied.append('key')
        with socket.socket(socket.AF_UNIX) as sock:
            try: sock.connect(path)
            except PermissionError: denied.append('docker')
        result.put(denied)
    child = ctx.Process(target=check); child.start(); child.join(3)
    docker.close()
    assert child.exitcode == 0 and result.get(timeout=1) == ['key', 'docker']


def test_unprivileged_state_agent_serves_http_uid_through_runtime(server, tmp_path):
    from cryptography.fernet import Fernet
    from app import agent, runtime_client
    from app.domain import Engine, Store
    import signal
    request_runtime, _, _, runtime_path = server
    ctx = multiprocessing.get_context('fork')
    state = tmp_path/'state'; state.mkdir(); state.chmod(0o700); os.chown(state, 61001, 61001)
    ipc = tmp_path/'agent'; ipc.mkdir(); os.chown(ipc, 61001, 61001)
    path = str(ipc/'agent.sock'); ready = ctx.Event(); observed = ctx.Queue()
    def run_state():
        os.setgroups([61002]); os.setgid(61001); os.setuid(61001)
        runtime_client.SOCKET = runtime_path
        engine = Engine(Store(state/'clients.sqlite3', Fernet.generate_key()), runtime_client.RuntimeBackend())
        def stop(*_): raise SystemExit()
        signal.signal(signal.SIGTERM, stop)
        def report_ready():
            observed.put((os.stat(path).st_uid, os.stat(path).st_gid, os.stat(state/'clients.sqlite3').st_uid))
            ready.set()
        agent.serve(engine, path, 61002, report_ready, allowed_uid=61002)
    process = ctx.Process(target=run_state); process.start()
    try:
        assert ready.wait(3)
        result = ctx.Queue()
        caller = ctx.Process(target=child_request, args=(path, 61002, 61002, {'operation': 'health'}, result))
        caller.start(); caller.join(3)
        assert caller.exitcode == 0 and result.get(timeout=1)['ok']
        assert observed.get(timeout=1) == (61001, 61002, 61001)
    finally:
        def signal_as_owner(sig):
            os.setgroups([]); os.setgid(61001); os.setuid(61001)
            try: os.kill(process.pid, sig)
            except ProcessLookupError: pass
        killer = ctx.Process(target=signal_as_owner, args=(signal.SIGTERM,))
        killer.start(); killer.join(2); process.join(3)
        if process.is_alive():
            killer = ctx.Process(target=signal_as_owner, args=(signal.SIGKILL,))
            killer.start(); killer.join(2); process.join(2)
