"""Offline contract checks. Never fetch origins, resolve remote refs or log payloads."""
import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parent
METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}
DOC_FIELDS = {'description', 'summary', 'title', 'example', 'examples', 'externalDocs'}

def load(name):
    return json.loads((ROOT / f'{name}.openapi.json').read_text())

def resolve(value, spec):
    if isinstance(value, list):
        return [resolve(item, spec) for item in value]
    if isinstance(value, dict):
        if '$ref' in value:
            reference = value['$ref']
            if not reference.startswith('#/'):
                raise ValueError('Only local references are allowed')
            target = spec
            for part in reference[2:].split('/'):
                target = target[part.replace('~1', '/').replace('~0', '~')]
            return resolve({**target, **{k:v for k,v in value.items() if k != '$ref'}}, spec)
        return {key: resolve(item, spec) for key, item in value.items()}
    return value

def shape(value, named_map=False):
    if isinstance(value, dict):
        return {k: shape(v, named_map=k in {'properties', 'patternProperties', '$defs', 'dependentSchemas'})
                for k,v in value.items() if named_map or (k not in DOC_FIELDS and not k.startswith('x-'))}
    if isinstance(value, list):
        return [shape(v) for v in value]
    return value

def fingerprint(value):
    return hashlib.sha256(json.dumps(shape(value), sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def signatures(spec):
    result = {'security': fingerprint({'schemes': spec['components']['securitySchemes'], 'security': spec.get('security')})}
    for path, methods in spec['paths'].items():
        for method, operation in methods.items():
            if method in METHODS:
                result[method.upper() + ' ' + path] = fingerprint(resolve({**operation, 'pathParameters': methods.get('parameters', [])}, spec))
    return result

def compare(baseline, current):
    # Deliberately conservative: additive endpoints are allowed, existing wire
    # shapes need review even if a change might be backwards compatible.
    return [key for key, signature in baseline.items() if current.get(key) != signature]

def assert_response(name, method, path, response):
    spec = load(name)
    operation = spec['paths'][path][method.lower()]
    code = str(response.status_code)
    assert code in operation['responses'], f'{name} {method} {path}: undocumented HTTP {code}'
    declared = operation['responses'][code].get('content', {})
    media = response.headers.get('content-type', '').split(';')[0]
    assert media in declared, f'{name} {method} {path}: unexpected media type'
    if media == 'application/json':
        assert_schema(response.json(), declared[media]['schema'], spec, f'{name} {method} {path}')
    if name != 'platform' or media == 'application/octet-stream':
        assert 'no-store' in response.headers.get('cache-control', '')

def assert_schema(payload, schema, spec, label):
    validator = Draft202012Validator(resolve(schema, spec), format_checker=FormatChecker())
    errors = list(validator.iter_errors(payload))
    if errors:
        # Never render values; failures may concern confidential API bodies.
        error = errors[0]
        raise AssertionError(f'{label}: invalid {error.validator} at /' + '/'.join(map(str, error.absolute_path)))

def check_records(directory):
    spec = load('platform')
    seen = set()
    records = json.loads(Path(directory).joinpath('platform-responses.json').read_text())
    assert records, 'No real Laravel response captures'
    for record in records:
        path, method, status = record['path'], record['method'].lower(), str(record['status'])
        operation = spec['paths'][path][method]
        assert status in operation['responses'], f'{method} {path}: undocumented HTTP {status}'
        media = record['media']
        schema = operation['responses'][status]['content'][media]['schema']
        if media == 'application/json':
            assert_schema(record['json'], schema, spec, f'{method} {path}')
        if 200 <= int(status) < 300:
            seen.add((path, method))
        if media == 'application/octet-stream':
            assert record['noStore'] and record['attachment'] and record['nonEmpty']
    expected = {(path, method) for path, methods in spec['paths'].items() for method in methods if method in METHODS}
    assert expected <= seen, 'Missing successful Laravel captures: ' + str(sorted(expected - seen))
    print(f'Validated {len(records)} real Laravel responses, {len(seen)} operations')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--captures', help='Directory of isolated Laravel test responses')
    args = parser.parse_args()
    baseline = json.loads(ROOT.joinpath('baseline-v1.json').read_text())
    for name in ('platform', 'wireguard', 'amnezia'):
        spec = load(name)
        resolve(spec, spec)  # Reject external refs before the spec validator can resolve them.
        validate(spec)
        changes = compare(baseline[name], signatures(spec))
        if changes:
            raise SystemExit(f'{name}: contract changed; explicit compatibility/version review required: ' + ', '.join(changes))
        print(f'{name}: OpenAPI valid, v1 baseline intact')
    if args.captures:
        check_records(args.captures)

if __name__ == '__main__':
    main()
