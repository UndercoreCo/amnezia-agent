"""Generate private initial files only. Does not start services or change firewall."""
import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def prepare(destination, endpoint, network, image):
    destination = Path(destination)
    if destination.exists():
        raise ValueError('Destination exists; refusing to overwrite keys.')
    if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}', image):
        raise ValueError('Pin a tested image digest.')
    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}:\d{1,5}', endpoint):
        raise ValueError('Invalid endpoint.')
    port = int(endpoint.rsplit(':', 1)[1])
    if not 1024 <= port <= 65535:
        raise ValueError('Choose an unused unprivileged UDP port.')
    subnet = ipaddress.ip_network(network)
    if subnet.version != 4 or not subnet.is_private or not 8 <= subnet.num_addresses <= 65536:
        raise ValueError('Invalid private subnet.')
    os.umask(0o077)
    destination.mkdir(mode=0o700, parents=True)
    private = X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    headers = secrets.SystemRandom().sample(range(10_000, 2**31), 4)
    parameters = {'Jc': '4', 'Jmin': '40', 'Jmax': '70', 'S1': '32', 'S2': '64', 'S3': '0', 'S4': '0',
                  **{f'H{i+1}': str(value) for i, value in enumerate(headers)}}
    config = {'endpoint': endpoint, 'listen_port': port, 'network': network,
              'dns': ['1.1.1.1', '1.0.0.1'], 'server_private_key': base64.b64encode(private).decode(), 'parameters': parameters}
    (destination/'node.json').write_text(json.dumps(config))
    (destination/'encryption.key').write_bytes(Fernet.generate_key())
    (destination/'http.token').write_text(secrets.token_urlsafe(48))
    (destination/'.env').write_text(f'AWG_IMAGE={image}\nAWG_PORT={port}\n')
    (destination/'awg0.conf').write_text('[Interface]\nAddress = '+str(subnet.network_address+1)+f'/{subnet.prefixlen}\n'
        +'PrivateKey = '+config['server_private_key']+f'\nListenPort = {port}\n'
        +''.join(f'{key} = {value}\n' for key,value in parameters.items()))
    for file in destination.iterdir():
        file.chmod(0o600)
    # The installer sets root:awg-api on the directory and read-only HTTP token.
    return {'prepared': True, 'files': 5, 'format': 'AWG-compatible conf', 'services_started': False}


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--destination', required=True)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--network', default='10.78.0.0/24')
    parser.add_argument('--image', required=True)
    args=parser.parse_args()
    print(json.dumps(prepare(args.destination,args.endpoint,args.network,args.image)))
