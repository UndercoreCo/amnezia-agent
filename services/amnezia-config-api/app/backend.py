"""Privileged boundary: fixed Docker arguments, dedicated container, no caller shell."""
import base64
import ipaddress
import json
import re
import subprocess
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .domain import Fault, stamp

AWG_FIELDS = {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
              'I1', 'I2', 'I3', 'I4', 'I5', 'HeaderProtectionKey', 'ContentPaddingAddition',
              'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
              'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies'}


class ConfigurationRenderer:
    def configuration(self, row, secret):
        params = ''.join(f'{key} = {value}\n' for key, value in self.config['parameters'].items())
        return (f"[Interface]\nPrivateKey = {secret['private']}\nAddress = {row['ip']}/32\n"
                f"DNS = {', '.join(self.config['dns'])}\nMTU = 1280\n{params}\n[Peer]\nPublicKey = {self.server_public_key}\n"
                f"PresharedKey = {secret['psk']}\nEndpoint = {self.config['endpoint']}\n"
                'AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n')

    def amnezia(self, row, secret):
        from .export import guest_profile
        return guest_profile(self.config, row, secret, self.server_public_key, self.configuration(row, secret))


class DockerBackend(ConfigurationRenderer):
    CONTAINER = 'undercore-awg-api'
    INTERFACE = 'awg0'
    MANAGED_LABEL = ('ru.undercore.managed', 'amnezia-config-api')

    def __init__(self, config):
        self.config = config
        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}:\d{1,5}', config['endpoint']):
            raise ValueError('invalid endpoint')
        if not 1 <= int(config['endpoint'].rsplit(':', 1)[1]) <= 65535:
            raise ValueError('invalid port')
        for value in config['dns']:
            ipaddress.ip_address(value)
        if not config['dns'] or not isinstance(config['parameters'], dict) or not set(config['parameters']) <= AWG_FIELDS:
            raise ValueError('invalid AWG parameters')
        for value in config['parameters'].values():
            if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) < 32 for c in value):
                raise ValueError('invalid parameter')
        key = base64.b64decode(config['server_private_key'], validate=True)
        private = X25519PrivateKey.from_private_bytes(key)
        self.server_public_key = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

    def run(self, args, data=None, *, timeout=8):
        try:
            result = subprocess.run(['/usr/bin/docker', '--host', 'unix:///run/docker.sock', *args], input=data, capture_output=True, text=True, timeout=timeout, check=False,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent', 'DOCKER_CONFIG': '/nonexistent'})
        except (OSError, subprocess.TimeoutExpired):
            raise Fault('vpn_unavailable', 503) from None
        if result.returncode:
            raise Fault('vpn_unavailable', 503)
        return result.stdout

    @staticmethod
    def projection(text):
        """Compare native settings without order/format noise. Never log this value.

        Peer PSKs stay inside the privileged executor; server private keys are
        stripped inside the container before stdout crosses the boundary.
        """
        sections, current = [], None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line in ('[Interface]', '[Peer]'):
                current = {}; sections.append((line, current))
                continue
            if current is None or '=' not in line:
                raise Fault('native_snapshot_invalid', 503)
            name, value = (part.strip() for part in line.split('=', 1))
            name = name.lower()
            # Server-side peer endpoints are learned from roaming clients;
            # they are observations, not provisioned desired settings.
            if name == 'endpoint' and sections[-1][0] == '[Peer]':
                continue
            if name == 'privatekey':
                continue
            if name in current:
                raise Fault('native_snapshot_invalid', 503)
            if name == 'allowedips':
                value = ','.join(sorted(str(ipaddress.ip_network(x.strip(), strict=False))
                                        for x in value.split(',')))
            # Native showconf may include explicitly zero-valued AWG defaults.
            if name in ('disablecookies', 'randomtrailers') and value == 'off':
                continue
            if value == '0' and name not in ('listenport', 'publickey', 'presharedkey', 'allowedips'):
                continue
            current[name] = value
        return tuple(sorted((kind, tuple(sorted(values.items()))) for kind, values in sections))

    def snapshot(self):
        info = json.loads(self.run(['inspect', self.CONTAINER]))[0]
        if info['Config'].get('Labels', {}).get(self.MANAGED_LABEL[0]) != self.MANAGED_LABEL[1] or not info['State']['Running']:
            raise Fault('managed_container_unavailable', 503)
        # Fixed script/arguments, never caller-supplied shell. Three native reads
        # share one exec. Do not use `dump`: it includes the server private key.
        # Capture showconf first so a failed awg cannot be masked by the filter.
        script = ('set -eu; conf=$(awg showconf "$1"); '
                  'awg show "$1" public-key; printf "\\n--HANDSHAKES--\\n"; '
                  'awg show "$1" latest-handshakes; printf "%s\\n" "--CONFIG--"; '
                  'printf "%s\\n" "$conf" | sed "/^PrivateKey[[:space:]]*=/d"')
        raw = self.run(['exec', self.CONTAINER, 'sh', '-c', script, 'snapshot', self.INTERFACE])
        try:
            identity, rest = raw.split('\n--HANDSHAKES--\n', 1)
            times, configuration = rest.split('--CONFIG--\n', 1)
        except ValueError:
            raise Fault('native_snapshot_invalid', 503) from None
        if identity.strip() != self.server_public_key:
            raise Fault('server_identity_conflict')
        after = json.loads(self.run(['inspect', self.CONTAINER]))[0]
        if (after['Id'] != info['Id'] or after['State']['StartedAt'] != info['State']['StartedAt']
                or not after['State']['Running']):
            raise Fault('native_snapshot_changed', 503)
        projection = self.projection(configuration)
        peers = {dict(values)['publickey'] for kind, values in projection if kind == '[Peer]'}
        handshakes = {}
        for line in times.splitlines():
            key, value = line.split()
            ts = int(value)
            handshakes[key] = stamp(datetime.fromtimestamp(ts, timezone.utc)) if 0 < ts <= datetime.now(timezone.utc).timestamp() else None
        if set(handshakes) != peers:
            raise Fault('native_snapshot_changed', 503)
        self._observed_projection = projection
        return info['State']['StartedAt'], peers, handshakes

    def transfer_snapshot(self):
        # One bounded read budget: telemetry cannot starve the expiry executor.
        deadline = time.monotonic() + 2
        def read(args):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Fault('collection_timeout', 503)
            return self.run(args, timeout=remaining)
        before = json.loads(read(['inspect', self.CONTAINER]))[0]
        if before['Config'].get('Labels', {}).get(self.MANAGED_LABEL[0]) != self.MANAGED_LABEL[1] or not before['State']['Running']:
            raise Fault('managed_container_unavailable', 503)
        if read(['exec', self.CONTAINER, 'awg', 'show', self.INTERFACE, 'public-key']).strip() != self.server_public_key:
            raise Fault('server_identity_conflict')
        values = {}
        for line in read(['exec', self.CONTAINER, 'awg', 'show', self.INTERFACE, 'transfer']).splitlines():
            key, rx, tx = line.split()
            if key in values or not rx.isascii() or not tx.isascii() or not rx.isdecimal() or not tx.isdecimal():
                raise Fault('counter_invalid', 503)
            values[key] = {'rx': int(rx), 'tx': int(tx), 'generation': 'direct'}
        after = json.loads(read(['inspect', self.CONTAINER]))[0]
        if before['State']['StartedAt'] != after['State']['StartedAt'] or not after['State']['Running']:
            raise Fault('counter_invalid', 503)
        return before['State']['StartedAt'], values

    def apply(self, rows):
        config = '[Interface]\nPrivateKey = ' + self.config['server_private_key'] + '\n'
        config += 'ListenPort = ' + str(self.config['listen_port']) + '\n'
        config += ''.join(f'{key} = {value}\n' for key, value in self.config['parameters'].items())
        for row, secret in rows:
            config += f"\n[Peer]\nPublicKey = {row['public_key']}\nPresharedKey = {secret['psk']}\nAllowedIPs = {row['ip']}/32\n"
        # Verify the actual target and complete peer settings on every apply,
        # including PSK/AllowedIPs drift and container restart. This is not a
        # process-local assumption that the previous write is still present.
        self.snapshot()
        if self.projection(config) != self._observed_projection:
            self.run(['exec', '-i', self.CONTAINER, 'awg', 'syncconf', self.INTERFACE, '/dev/stdin'], config)
        self._observed_projection = None

    def emergency_stop(self):
        # Fail closed for this dedicated container only. Operator resolves before restart.
        self.run(['stop', '--time', '2', self.CONTAINER])
