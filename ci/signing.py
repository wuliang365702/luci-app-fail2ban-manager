"""Create signed APKs natively; require positive and negative trust tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(*command):
    return subprocess.run(command, check=True, capture_output=True, timeout=60).stdout


def patch_sdk(path):
    path = Path(path)
    source = path.read_text()
    marker = '$(STAGING_DIR_HOST)/bin/apk mkpkg \\\n'
    if source.count(marker) != 1:
        raise RuntimeError('SDK mkpkg rule changed; refusing an unreviewed signing patch')
    replacement = ('$(STAGING_DIR_HOST)/bin/apk mkpkg '
                   '$(if $(CONFIG_SIGNED_PACKAGES),--sign $(BUILD_KEY_APK_SEC),) \\\n')
    path.write_text(source.replace(marker, replacement))


def expect_rejection(apk, package, trust, label):
    result = subprocess.run([str(apk), 'verify', '--keys-dir', str(trust), str(package)],
                            capture_output=True, timeout=30)
    if result.returncode == 0:
        raise RuntimeError(label + ': verifier unexpectedly accepted the package')
    print(label + ': rejected as required', flush=True)


def trust_tests(apk, package, public_key, directory):
    trust = directory / 'trusted'
    trust.mkdir()
    (trust / 'manager.pem').write_bytes(public_key.read_bytes())
    run(str(apk), 'verify', '--keys-dir', str(trust), str(package))
    print('Correct public key: signature and content verification OK', flush=True)
    empty = directory / 'empty'
    empty.mkdir()
    expect_rejection(apk, package, empty, 'No trusted key')
    wrong = directory / 'wrong'
    wrong.mkdir()
    wrong_private = directory / 'wrong-private.pem'
    run('openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(wrong_private))
    (wrong / 'wrong.pem').write_bytes(run('openssl', 'pkey', '-in', str(wrong_private), '-pubout'))
    expect_rejection(apk, package, wrong, 'Wrong public key')
    damaged = directory / 'damaged.apk'
    data = package.read_bytes()
    damaged.write_bytes(data[:len(data) // 2])
    expect_rejection(apk, damaged, trust, 'Truncated package')
    return {'correct_key': True, 'missing_key_rejected': True,
            'wrong_key_rejected': True, 'truncated_package_rejected': True}


def prepare(sdk, public_key):
    private_key = sdk / 'private-key.pem'
    key = os.environ.get('PRIVATE_KEY', '')
    if not key:
        raise RuntimeError('No signing key supplied')
    private_key.write_text(key.rstrip() + '\n')
    private_key.chmod(0o600)
    expected = run('openssl', 'pkey', '-pubin', '-in', str(public_key), '-outform', 'DER')
    actual = run('openssl', 'pkey', '-in', str(private_key), '-pubout', '-outform', 'DER')
    if actual != expected:
        raise RuntimeError('Signing key does not match the distributed public key')
    (sdk / 'public-key.pem').write_bytes(run('openssl', 'pkey', '-in', str(private_key), '-pubout'))
    patch_sdk(sdk / 'include/package-pack.mk')
    apk = sdk / 'staging_dir/host/bin/apk'
    with tempfile.TemporaryDirectory(prefix='manager-signing-probe-') as temp:
        directory = Path(temp)
        files = directory / 'files'
        marker = files / 'usr/share/manager-signing-probe/marker'
        marker.parent.mkdir(parents=True)
        marker.write_text('Signature verification must stay enabled.\n')
        common = [str(apk), 'mkpkg', '--info', 'name:manager-signing-probe',
                  '--info', 'version:0-r1', '--info', 'arch:noarch', '--info', 'license:MIT',
                  '--files', str(files)]
        signed = directory / 'signed.apk'
        run(*common, '--sign', str(private_key), '--output', str(signed))
        trust_tests(apk, signed, public_key, directory)
        unsigned = directory / 'unsigned.apk'
        run(*common, '--output', str(unsigned))
        expect_rejection(apk, unsigned, directory / 'trusted', 'Unsigned package')
    print('Native mkpkg signing smoke tests passed before dependency compilation.', flush=True)


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def package_info(text):
    decoder = json.JSONDecoder()
    remaining = text.lstrip()
    found = []
    while remaining:
        value, offset = decoder.raw_decode(remaining)
        found.extend(item for item in objects(value)
                     if item.get('name') == 'luci-app-fail2ban-manager' and 'arch' in item)
        remaining = remaining[offset:].lstrip()
    if len(found) != 1 or found[0]['arch'] != 'noarch':
        raise RuntimeError('Expected exactly one noarch manager package metadata object')
    return found[0]


def verify(sdk, public_key, artifact_dir):
    packages = list((artifact_dir / 'bin').rglob('luci-app-fail2ban-manager-*.apk'))
    if len(packages) != 1:
        raise RuntimeError('Expected exactly one manager APK')
    package = packages[0]
    apk = sdk / 'staging_dir/host/bin/apk'
    with tempfile.TemporaryDirectory(prefix='manager-release-verify-') as temp:
        tests = trust_tests(apk, package, public_key, Path(temp))
    metadata = package_info(run(str(apk), 'adbdump', '--format', 'json', str(package)).decode())
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    public_der = run('openssl', 'pkey', '-pubin', '-in', str(public_key), '-outform', 'DER')
    report = {'package': package.name, 'architecture': metadata['arch'],
              'version': metadata['version'], 'sha256': digest,
              'public_key_der_sha256': hashlib.sha256(public_der).hexdigest(), 'tests': tests}
    (artifact_dir / 'signing-verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Release APK: all strict trust checks passed; architecture=noarch', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('prepare', 'verify'))
    parser.add_argument('--sdk', type=Path, default=Path('/builder'))
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, default=Path('/artifacts'))
    args = parser.parse_args()
    if args.mode == 'prepare':
        prepare(args.sdk, args.public_key)
    else:
        verify(args.sdk, args.public_key, args.artifacts)
