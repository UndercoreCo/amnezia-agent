"""Small root executor. No HTTP, client private keys, SQL or business commands.

Only a fixed container/interface is addressable. State UID cannot send Docker
arguments, raw configuration, paths or server settings. Root/Docker remain in
this trusted process, not in the agent handling customer state and exports.
"""
import base64
import fcntl
import ipaddress
import json
import os
import signal
import socket
import time
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from .backend import DockerBackend
from .domain import Fault, expiry, now, stamp
from .local_rpc import authorize_peer, read_request, notify

MAX_FRAME = 16 * 1024 * 1024
LEASE_SECONDS = 90


class Peer(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    public_key: str
    psk: str
    ip: str
    expires_at: str

    @field_validator('public_key', 'psk')
    @classmethod
    def key(cls, value):
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
            raise ValueError('invalid key')
        return value

    @field_validator('expires_at')
    @classmethod
    def deadline(cls, value):
        return expiry(value)


class Request(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    operation: Literal['metadata', 'snapshot', 'usage', 'apply', 'stop']
    peers: list[Peer] | None = Field(default=None, max_length=65533)


class Executor:
    def __init__(self, backend, clock=time.monotonic):
        self.backend, self.clock = backend, clock
        self.network = ipaddress.ip_network(backend.config['network'], strict=True)
        if self.network.version != 4 or not self.network.is_private or not 8 <= self.network.num_addresses <= 65536:
            raise ValueError('invalid private pool')
        self.last_apply = clock()
        self.stopped = False
        self.peers = []
        self.usage_boot = uuid.uuid4().hex
        self.usage_generations = {}

    def stop(self):
        self.stopped = True  # Latch before syscall; failure must not reopen apply.
        self.backend.emergency_stop()

    def tick(self):
        # Snapshot/metadata traffic is not proof of successful state reconciliation.
        if self.stopped or self.clock() - self.last_apply >= LEASE_SECONDS:
            self.stop()
            raise Fault('runtime_stopped', 503)
        active = [peer for peer in self.peers if peer.expires_at > stamp(now())]
        if len(active) != len(self.peers):
            # Enforce deadlines even if the state process is stalled or unreachable.
            epoch, _, _ = self.backend.snapshot()
            self.backend.apply([({'public_key': peer.public_key, 'ip': peer.ip}, {'psk': peer.psk})
                                for peer in active])
            after, actual, _ = self.backend.snapshot()
            if after != epoch or actual != {peer.public_key for peer in active}:
                raise Fault('expiry_unconfirmed', 503)
            active_keys = {peer.public_key for peer in active}
            self.usage_generations = {k: v for k, v in self.usage_generations.items() if k in active_keys}
            self.peers = active

    def execute(self, payload):
        request = Request.model_validate(payload)
        if (request.operation == 'apply') != (request.peers is not None):
            raise Fault('invalid_request', 422)
        if request.operation == 'stop':
            self.stop()
            return {}
        if request.operation == 'usage':
            # A measurement neither renews the runtime lease nor reconciles peers.
            try:
                epoch, counters = self.backend.transfer_snapshot()
            except Exception:
                raise Fault('counter_invalid', 503) from None
            present = set(counters)
            self.usage_generations = {key: value for key, value in self.usage_generations.items() if key in present}
            for key, value in counters.items():
                value['generation'] = self.usage_generations.setdefault(key, uuid.uuid4().hex)
            return {'epoch': self.usage_boot + ':' + epoch, 'counters': counters}
        self.tick()
        if request.operation == 'metadata':
            config = self.backend.config
            return {**{key: config[key] for key in ('endpoint', 'dns', 'parameters', 'network')},
                    'server_public_key': self.backend.server_public_key}
        if request.operation == 'snapshot':
            epoch, peers, handshakes = self.backend.snapshot()
            return {'epoch': epoch, 'peers': sorted(peers), 'handshakes': handshakes}
        keys, addresses, rows = set(), set(), []
        for peer in request.peers:
            address = ipaddress.ip_address(peer.ip)
            if (address.version != 4 or address not in self.network or
                    int(address) <= int(self.network.network_address) + 1 or address == self.network.broadcast_address or
                    peer.ip != str(address) or peer.public_key == self.backend.server_public_key or
                    peer.public_key in keys or address in addresses or peer.expires_at <= stamp(now())):
                raise Fault('invalid_peer', 422)
            keys.add(peer.public_key)
            addresses.add(address)
            rows.append(({'public_key': peer.public_key, 'ip': peer.ip}, {'psk': peer.psk}))
        # Backend apply verifies target/identity and native settings before
        # deciding whether a write is necessary. Caller cannot select a target.
        self.backend.apply(rows)
        self.last_apply = self.clock()
        self.usage_generations = {k: v for k, v in self.usage_generations.items() if k in keys}
        self.peers = request.peers
        self.tick()  # Remove peers that expired during Docker execution.
        return {}


def serve(executor, socket_path, group_id, allowed_uid, ready=notify):
    path = Path(socket_path)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(path.parent, 0, group_id)
    os.chmod(path.parent, 0o750)
    with open(str(path) + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(path))
            os.chown(path, 0, group_id)
            os.chmod(path, 0o660)
            server.listen(8)
            server.settimeout(1)
            try:
                while True:
                    executor.tick()
                    ready()
                    try:
                        connection, _ = server.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        try:
                            authorize_peer(connection, allowed_uid)
                            payload = read_request(connection, MAX_FRAME)
                            result = {'ok': True, 'data': executor.execute(payload)}
                        except Fault as error:
                            result = {'ok': False, 'detail': error.code, 'status': error.status}
                        except (ValueError, ValidationError, OSError):
                            result = {'ok': False, 'detail': 'invalid_request', 'status': 422}
                        except Exception:
                            # Exit + ExecStopPost rather than claim a healthy privileged runtime.
                            raise RuntimeError('Runtime failed; dedicated tunnel must stop.') from None
                        try:
                            connection.settimeout(2)
                            connection.sendall(json.dumps(result).encode() + b'\n')
                        except OSError:
                            pass  # State agent readback determines the durable result.
            finally:
                path.unlink(missing_ok=True)
                executor.stop()


def main():
    import pwd
    os.umask(0o077)
    config = json.loads(Path('/etc/amnezia-config-api/node.json').read_text())
    executor = Executor(DockerBackend(config))
    identity = pwd.getpwnam('awg-agent')
    def stop(*_):
        raise SystemExit()
    signal.signal(signal.SIGTERM, stop)
    serve(executor, '/run/amnezia-config-runtime/runtime.sock', identity.pw_gid, identity.pw_uid)


if __name__ == '__main__':
    main()
