"""Guest connection export compatible with AmneziaVPN 4.8/5.x import format.

Independently implements the documented Qt qCompress/base64url envelope. Only
allowlisted connection data is serialized; never a server/admin config object.
"""
import base64
import json
import struct
import zlib

from .domain import Fault

AWG2_FIELDS = {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
               'I1', 'I2', 'I3', 'I4', 'I5'}
REQUIRED = {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'}


def guest_profile(config, row, secret, server_public_key, native):
    params = config['parameters']
    if not REQUIRED <= set(params) or not set(params) <= AWG2_FIELDS:
        raise Fault('export_version_unsupported', 422)
    version = '2' if 'S3' in params and 'S4' in params else '1.5' if any(k.startswith('I') for k in params) else None
    host, port = config['endpoint'].rsplit(':', 1)
    client = {
        'config': native, 'hostName': host, 'port': int(port),
        'client_ip': row['ip'] + '/32', 'client_priv_key': secret['private'],
        'client_pub_key': row['public_key'], 'clientId': row['public_key'],
        'server_pub_key': server_public_key, 'psk_key': secret['psk'],
        'allowed_ips': ['0.0.0.0/0', '::/0'], 'persistent_keep_alive': '25',
        'mtu': '1280', **params,
    }
    protocol = {'port': str(port), 'transport_proto': 'udp', 'isThirdPartyConfig': True,
                'last_config': json.dumps(client, ensure_ascii=False, separators=(',', ':'))}
    if version:
        protocol['protocol_version'] = version
    payload = {
        'description': row['name'], 'hostName': host,
        'dns1': config['dns'][0], 'dns2': config['dns'][1] if len(config['dns']) > 1 else config['dns'][0],
        'containers': [{'container': 'amnezia-awg', 'awg': protocol}],
        'defaultContainer': 'amnezia-awg',
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    compressed = struct.pack('>I', len(raw)) + zlib.compress(raw, 8)
    return 'vpn://' + base64.urlsafe_b64encode(compressed).rstrip(b'=').decode('ascii')
