"""State-agent backend: typed local IPC, never Docker or a server private key."""
import json
import socket
from .backend import ConfigurationRenderer
from .domain import Fault

SOCKET = '/run/amnezia-config-runtime/runtime.sock'
MAX_FRAME = 16 * 1024 * 1024


def rpc(command):
    try:
        payload = json.dumps(command, separators=(',', ':')).encode() + b'\n'
        if len(payload) > MAX_FRAME:
            raise Fault('runtime_request_too_large', 503)
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(40)
            sock.connect(SOCKET)
            sock.sendall(payload)
            data = bytearray()
            while not data.endswith(b'\n'):
                chunk = sock.recv(65536)
                if not chunk or len(data) + len(chunk) > MAX_FRAME:
                    raise Fault('runtime_unavailable', 503)
                data.extend(chunk)
        response = json.loads(data)
        if not response['ok']:
            raise Fault(response['detail'], response['status'])
        return response['data']
    except (OSError, ValueError, KeyError, TypeError):
        raise Fault('runtime_unavailable', 503) from None


class RuntimeBackend(ConfigurationRenderer):
    def __init__(self, transport=rpc):
        self.transport = transport
        self.config = transport({'operation': 'metadata'})
        self.server_public_key = self.config['server_public_key']

    def snapshot(self):
        data = self.transport({'operation': 'snapshot'})
        return data['epoch'], set(data['peers']), data['handshakes']

    def transfer_snapshot(self):
        data = self.transport({'operation': 'usage'})
        return data['epoch'], data['counters']

    def apply(self, rows):
        self.transport({'operation': 'apply', 'peers': [
            {'public_key': row['public_key'], 'psk': secret['psk'], 'ip': row['ip'],
             'expires_at': row['expires_at']} for row, secret in rows]})

    def emergency_stop(self):
        self.transport({'operation': 'stop'})


if __name__ == '__main__':
    # Only fixed shutdown; no arbitrary CLI command or user-selected socket.
    rpc({'operation': 'stop'})
