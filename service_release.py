"""Offline, allowlisted source bundles; no installation or service operations."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile

FORMAT = 1
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 8 * 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_ENTRIES = 200
HASH = re.compile(r'[a-f0-9]{64}')
REVISION = re.compile(r'[a-f0-9]{40}')
MODULES = {
    'wg-config-api': ('__init__', 'configuration', 'constants', 'diagnostics', 'documentation', 'expiry',
                      'main', 'middleware', 'replacement', 'retirement', 'runtime', 'schemas', 'settings', 'storage', 'upstream'),
    'amnezia-config-api': ('__init__', 'agent', 'backend', 'control_lease', 'diagnostics', 'domain', 'export', 'local_rpc', 'main', 'runtime', 'runtime_client', 'usage'),
}
TESTS = {
    'wg-config-api': ('connection', 'contract', 'diagnostics', 'openapi_contract', 'renewal', 'replacement', 'retirement'),
    'amnezia-config-api': ('agent_boundary', 'connection', 'control_lease', 'diagnostics', 'engine', 'expiry_race', 'export', 'http_boundary', 'offline_permission', 'openapi_contract', 'runtime_boundary', 'runtime_linux', 'reconciliation_cost', 'usage'),
}
EXTRAS = {'wg-config-api': ('retire_missing.py',), 'amnezia-config-api': ('deploy/prepare.py', 'deploy/amnezia-config-agent.service', 'deploy/amnezia-config-api.service', 'deploy/amnezia-config-runtime.service', 'deploy/boundary.Dockerfile')}
SHARED = ('contracts/check.py', 'contracts/requirements.lock', 'contracts/baseline-v1.json',
          'contracts/platform.openapi.json', 'contracts/wireguard.openapi.json', 'contracts/amnezia.openapi.json', 'contracts/usage-sample.schema.json',
          'docs/infrastructure/independent-releases.md')


class ReleaseError(Exception):
    """Only fixed codes are exposed by the CLI; never raw paths or exceptions."""


def files_for(component):
    if component not in MODULES:
        raise ReleaseError('invalid_component')
    base = f'services/{component}'
    return sorted([*(f'{base}/app/{name}.py' for name in MODULES[component]),
                   *(f'{base}/tests/test_{name}.py' for name in TESTS[component]),
                   f'{base}/requirements.lock', f'{base}/README.md',
                   *(f'{base}/{name}' for name in EXTRAS[component]), *SHARED])


def safe_read(path, root, limit):
    # Every source parent must be an actual directory, never a symlink out of
    # the chosen tree. O_NOFOLLOW + fstat also protects the final entry.
    relative = path.relative_to(root)
    current = root
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ReleaseError('unsafe_source')
    for part in relative.parts[:-1]:
        current = current / part
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ReleaseError('unsafe_source')
    entry = path.lstat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or entry.st_size > limit:
        raise ReleaseError('unsafe_source')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ReleaseError('unsafe_source')
        data = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        if len(data) > limit or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ReleaseError('source_changed')
        return data


def provenance(root, candidate):
    def git(*args):
        result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=20)
        if result.returncode:
            raise ReleaseError('source_unavailable')
        return result.stdout
    revision = git('rev-parse', 'HEAD').decode('ascii').strip()
    if not REVISION.fullmatch(revision):
        raise ReleaseError('invalid_revision')
    if not candidate and git('status', '--porcelain', '--untracked-files=all').strip():
        raise ReleaseError('source_not_clean')
    return revision


def build(root, component, revision, candidate, output):
    if not REVISION.fullmatch(revision):
        raise ReleaseError('invalid_revision')
    root = Path(root).absolute()
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ReleaseError('output_exists')
    # Caller chooses an existing artifact directory. Never create inside source.
    if output.parent.resolve() == root.resolve() or root.resolve() in output.parent.resolve().parents:
        raise ReleaseError('output_inside_source')
    payload = {name: safe_read(root / name, root, MAX_FILE) for name in files_for(component)}
    if not candidate:
        tree = subprocess.run(['git', '-C', str(root), 'ls-tree', '-r', revision, '--', *payload],
                              capture_output=True, timeout=20)
        if tree.returncode:
            raise ReleaseError('source_unavailable')
        expected = {}
        for line in tree.stdout.decode('ascii').splitlines():
            metadata, name = line.split('\t', 1)
            mode, kind, digest = metadata.split()
            if mode not in ('100644', '100755') or kind != 'blob':
                raise ReleaseError('unsafe_source')
            expected[name] = digest
        actual = {name: hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                  for name, data in payload.items()}
        if actual != expected:
            raise ReleaseError('source_changed')
    if sum(map(len, payload.values())) > MAX_EXPANDED // 2:
        raise ReleaseError('source_too_large')
    manifest = {'format': FORMAT, 'component': component, 'git_revision': revision,
                'source_state': 'candidate' if candidate else 'committed', 'api_version': 'v1',
                'files': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
                          for name, data in payload.items()}}
    contents = {'release.json': (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode(), **payload}
    descriptor, temporary = tempfile.mkstemp(prefix='.service-release-', dir=output.parent)
    try:
        with os.fdopen(descriptor, 'wb') as sink:
            with gzip.GzipFile(fileobj=sink, mode='wb', filename='', mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                    for name, data in contents.items():
                        member = tarfile.TarInfo(name)
                        member.size, member.mode, member.mtime = len(data), 0o644, 0
                        archive.addfile(member, io.BytesIO(data))
            sink.flush()
            os.fsync(sink.fileno())
        digest = hashlib.sha256(Path(temporary).read_bytes()).hexdigest()
        verify(Path(temporary), digest, component)
        # Atomic exclusive publication, no clobber and no partial final archive.
        os.link(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {'ok': True, 'component': component, 'git_revision': revision, 'source_state': manifest['source_state'],
            'sha256': digest, 'file_count': len(payload), 'services_started': False}


class BudgetReader:
    def __init__(self, source):
        self.source, self.total = source, 0

    def read(self, size=-1):
        remaining = MAX_EXPANDED - self.total
        if size < 0 or size > remaining:
            size = remaining + 1
        data = self.source.read(size)
        self.total += len(data)
        if self.total > MAX_EXPANDED:
            raise ReleaseError('archive_too_large')
        return data


def parse_manifest(data, component):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseError('invalid_manifest')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) != {'format', 'component', 'git_revision', 'source_state', 'api_version', 'files'}:
        raise ReleaseError('invalid_manifest')
    if type(value['format']) is not int or value['format'] != FORMAT or value['component'] != component:
        raise ReleaseError('component_mismatch')
    if not isinstance(value['git_revision'], str) or not REVISION.fullmatch(value['git_revision']):
        raise ReleaseError('invalid_manifest')
    if value['source_state'] not in ('committed', 'candidate') or value['api_version'] != 'v1':
        raise ReleaseError('invalid_manifest')
    files = value['files']
    if not isinstance(files, dict) or set(files) != set(files_for(component)):
        raise ReleaseError('file_inventory_mismatch')
    for item in files.values():
        if not isinstance(item, dict) or set(item) != {'sha256', 'size'} or not isinstance(item['sha256'], str) \
                or not HASH.fullmatch(item['sha256']) or type(item['size']) is not int or not 0 <= item['size'] <= MAX_FILE:
            raise ReleaseError('invalid_manifest')
    return value


def verify(path, expected_hash, component, require_committed=False):
    if not HASH.fullmatch(expected_hash):
        raise ReleaseError('invalid_checksum')
    files_for(component)
    path = Path(path).absolute()
    raw = safe_read(path, path.parent, MAX_ARCHIVE)
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ReleaseError('checksum_mismatch')
    seen, manifest, end = set(), None, 0
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
        expanded = BudgetReader(compressed).read()
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
        for member in archive:
            name = member.name
            if len(seen) >= MAX_ENTRIES or name in seen or not member.isreg() or member.pax_headers \
                    or member.linkname or member.mode != 0o644 or not 0 <= member.size <= MAX_FILE:
                raise ReleaseError('unsafe_archive')
            if PurePosixPath(name).as_posix() != name or name.startswith('/') or '..' in PurePosixPath(name).parts:
                raise ReleaseError('unsafe_archive')
            if not seen and name != 'release.json':
                raise ReleaseError('invalid_manifest')
            if name != 'release.json' and name not in files_for(component):
                raise ReleaseError('file_inventory_mismatch')
            # Require the builder's ordinary USTAR headers. Extended headers,
            # hidden metadata, gaps and payload after the terminator are rejected.
            expected = tarfile.TarInfo(name)
            expected.size, expected.mode, expected.mtime = member.size, 0o644, 0
            if member.offset != end or member.offset_data != end + 512 \
                    or expanded[end:end + 512] != expected.tobuf(format=tarfile.USTAR_FORMAT):
                raise ReleaseError('unsafe_archive')
            seen.add(name)
            source = archive.extractfile(member)
            if source is None:
                raise ReleaseError('unsafe_archive')
            data = source.read(MAX_FILE + 1)
            if len(data) != member.size:
                raise ReleaseError('invalid_archive')
            data_end = member.offset_data + member.size
            end = member.offset_data + ((member.size + 511) // 512) * 512
            if any(expanded[data_end:end]):
                raise ReleaseError('unsafe_archive')
            if name == 'release.json':
                manifest = parse_manifest(data, component)
                if require_committed and manifest['source_state'] != 'committed':
                    raise ReleaseError('candidate_not_release')
            elif manifest['files'][name] != {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}:
                raise ReleaseError('file_hash_mismatch')
    if len(expanded) % 512 or len(expanded) - end < 1024 or any(expanded[end:]):
        raise ReleaseError('unsafe_archive')
    if manifest is None or seen != {'release.json', *files_for(component)}:
        raise ReleaseError('file_inventory_mismatch')
    return {'ok': True, 'component': component, 'git_revision': manifest['git_revision'],
            'source_state': manifest['source_state'], 'sha256': expected_hash,
            'file_count': len(manifest['files']), 'services_started': False}


def build_checked(root, component, candidate, output):
    revision = provenance(root, candidate)
    result = build(root, component, revision, candidate, output)
    try:
        # Remove our published output on every failed final provenance check,
        # including a now-dirty checkout, not only a changed HEAD value.
        if not candidate and provenance(root, False) != revision:
            raise ReleaseError('source_changed')
    except Exception:
        Path(output).unlink(missing_ok=True)
        raise
    return result


def main():
    parser = argparse.ArgumentParser(description='Offline source bundle build/verification. Never installs services.')
    commands = parser.add_subparsers(dest='command', required=True)
    build_parser = commands.add_parser('build')
    build_parser.add_argument('--component', required=True, choices=sorted(MODULES))
    build_parser.add_argument('--output', type=Path, required=True)
    build_parser.add_argument('--candidate', action='store_true', help='Explicitly allow a local draft; production verification rejects it.')
    verify_parser = commands.add_parser('verify')
    verify_parser.add_argument('--component', required=True, choices=sorted(MODULES))
    verify_parser.add_argument('--archive', type=Path, required=True)
    verify_parser.add_argument('--sha256', required=True)
    verify_parser.add_argument('--require-committed', action='store_true')
    args = parser.parse_args()
    try:
        if args.command == 'build':
            root = Path(__file__).resolve().parents[2]
            result = build_checked(root, args.component, args.candidate, args.output)
        else:
            result = verify(args.archive, args.sha256, args.component, args.require_committed)
    except ReleaseError as error:
        result = {'ok': False, 'error': str(error)}
    except Exception:
        result = {'ok': False, 'error': 'release_unavailable'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
