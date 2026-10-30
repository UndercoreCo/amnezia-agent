"""Bounded local IPC primitives; no Docker, database or operation dispatch."""
import json
import os
import socket
import struct
import time
from .domain import Fault

MAX_REQUEST = 16384
REQUEST_SECONDS = 2

def authorize_peer(connection, allowed_uid):
    # Production is Linux. Fail closed if peer credentials cannot be verified.
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    _, uid, _ = struct.unpack('3i', credentials)
    if uid not in (0, allowed_uid):
        raise Fault('unauthorized', 403)


def read_request(connection, limit=MAX_REQUEST):
    deadline = time.monotonic() + REQUEST_SECONDS
    data = bytearray()
    while b'\n' not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Fault('invalid_request', 422)
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            raise Fault('invalid_request', 422)
        data.extend(chunk)
        if len(data) > limit:
            raise Fault('invalid_request', 422)
    if data.count(b'\n') != 1 or not data.endswith(b'\n'):
        raise Fault('invalid_request', 422)
    return json.loads(data)



def notify():
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
            notifier.connect('\0' + address[1:] if address.startswith('@') else address)
            notifier.sendall(b'READY=1\nWATCHDOG=1')
