#!/usr/bin/env python3
"""Publish both native builds to an immutable R2 snapshot, the stable repository and GitHub.

status:  build, publish or complete, for the captured inputs' release tag
stage:   validate both artifacts and stage them, and each APK, in a draft GitHub release
publish: validate the draft again, sign the stable index, upload, and make the release public

GitHub and R2 carry the same APK bytes; publish refuses a draft whose copies differ. Both
carry NOTES.md (scripts/notes.py), the GitHub release's body.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zlib
from build import recipe
from inputs import ROOT, ARCHES, sha256, verify
import notes
from refresh import version

ENDPOINT = 'https://c860af766754fb92eec27bc723e6db5d.r2.cloudflarestorage.com'
BUCKET = 'werewolf'
PREFIX = 'apk/kernel/'
PUBLIC = 'https://dist.werewolf-linux.org/' + PREFIX
PACKAGES = {'linux-werewolf', 'linux-werewolf-probe'}
# GitHub refuses a release body over 125,000 characters.
BODY = 120_000
KEYNAME = '.SIGN.RSA256.werewolf-packages.rsa.pub'
TRUST = ROOT / 'release/packages.pub'


def run(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, text=True).stdout


def release(tag):
    # Only the paginated listing, with push access, includes drafts.
    result = subprocess.run(['gh', 'api', '--paginate', '--slurp',
                             'repos/' + os.environ['GITHUB_REPOSITORY'] + '/releases?per_page=100'],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr)
    matches = [item for page in json.loads(result.stdout) for item in page if item['tag_name'] == tag]
    if len(matches) > 1:
        raise ValueError('publish: several releases use tag ' + tag)
    return matches[0] if matches else None


def archive(directory, destination):
    """A tar.gz whose bytes depend only on the files, so a retry stages the same asset."""
    with destination.open('wb') as output, gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as packed:
        with tarfile.open(fileobj=packed, mode='w') as tar:
            for path in [directory] + sorted(directory.rglob('*')):
                member = tar.gettarinfo(str(path), arcname='./' + path.relative_to(directory).as_posix())
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ''
                if member.isfile():
                    with path.open('rb') as data:
                        tar.addfile(member, data)
                else:
                    tar.addfile(member)


def members(data):
    """The gzip members an APK or index is made of, each with its decompressed bytes."""
    parts = []
    while data:
        stream = zlib.decompressobj(31)
        raw = stream.decompress(data)
        if not stream.eof:
            raise ValueError('publish: truncated gzip member')
        length = len(data) - len(stream.unused_data)
        parts.append((data[:length], raw))
        data = stream.unused_data
    return parts


def contents(raw):
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        return {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}


def authenticated(path, key):
    """An APK's or index's members, once its control member's signature verifies against key."""
    parts = members(path.read_bytes())
    if len(parts) not in (2, 3):
        raise ValueError('publish: unsigned or malformed ' + path.name)
    signature = contents(parts[0][1])
    if set(signature) != {KEYNAME}:
        raise ValueError('publish: ' + path.name + ' is signed by another key')
    with tempfile.TemporaryDirectory() as directory:
        sig, control = Path(directory) / 'sig', Path(directory) / 'control'
        sig.write_bytes(signature[KEYNAME])
        control.write_bytes(parts[1][0])
        run('openssl', 'dgst', '-sha256', '-verify', str(key), '-signature', str(sig), str(control))
    return parts


def stanzas(parts):
    """An authenticated index's entries, by the APK file each names."""
    found = {}
    for stanza in contents(parts[1][1])['APKINDEX'].decode().strip().split('\n\n'):
        fields = dict(line.split(':', 1) for line in stanza.splitlines())
        found[fields['P'] + '-' + fields['V'] + '.apk'] = stanza
    return found


def validate(directory, arch, lock, source_sha):
    """Prove an artifact is one native build of the captured inputs, signed by the release key."""
    record = json.loads((directory / 'build.json').read_text())
    version = lock['version'] + '-r' + str(lock['revision'])
    if (record['build_id'], record['arch'], record['version']) != (lock['build_id'], arch, version):
        raise ValueError('publish: ' + directory.name + ' has other inputs, arch or version')
    if record['source_sha'] != source_sha:
        raise ValueError('publish: ' + directory.name + ' came from another commit')
    for name, digest in record['sha256'].items():
        path = directory / name
        if not path.resolve().is_relative_to(directory.resolve()) or sha256(path) != digest:
            raise ValueError('publish: hash mismatch: ' + name)
    found = {str(p.relative_to(directory)) for p in directory.rglob('*') if p.is_file()}
    if found != set(record['sha256']) | {'build.json'}:
        raise ValueError('publish: unrecorded or missing files in ' + directory.name)
    if (directory / 'werewolf-packages.rsa.pub').read_bytes() != TRUST.read_bytes():
        raise ValueError('publish: an ephemeral key signed ' + directory.name)
    tools = json.loads((ROOT / 'tools.lock.json').read_text())['toolchain']
    kernel = lock['version'] + ('.0' if lock['version'].count('.') == 1 else '') + '-werewolf'
    if (directory / 'linux.yaml').read_text() != recipe(lock, tools, arch):
        raise ValueError('publish: ' + directory.name + ' was built from another recipe')
    probe = (directory / 'probe.log').read_text().splitlines()
    if not probe or probe[-1] != 'probe: PASS ' + kernel or any(line.startswith('probe: FAIL') for line in probe):
        raise ValueError('publish: ' + directory.name + ' has no passing probe of ' + kernel)
    expected = {name + '-' + version + '.apk' for name in PACKAGES}
    if set(stanzas(authenticated(directory / arch / 'APKINDEX.tar.gz', TRUST))) != expected or \
            {p.name for p in (directory / arch).glob('*.apk')} != expected:
        raise ValueError('publish: ' + directory.name + ' does not hold exactly ' + ', '.join(sorted(expected)))
    for apk in (directory / arch).glob('*.apk'):
        parts = authenticated(apk, TRUST)
        info = contents(parts[1][1])['.PKGINFO'].decode()
        fields = dict(line.split(' = ', 1) for line in info.splitlines() if ' = ' in line)
        if apk.name != fields['pkgname'] + '-' + fields['pkgver'] + '.apk' or fields['arch'] != arch:
            raise ValueError('publish: ' + apk.name + ' says it is something else')
        if len(parts) != 3 or fields['datahash'] != hashlib.sha256(parts[2][0]).hexdigest():
            raise ValueError('publish: ' + apk.name + ' payload does not match its signed hash')
        if fields['pkgname'] == 'linux-werewolf':
            files = contents(parts[2][1])
            if files.get('boot/ipe.crt') != (ROOT / 'release/ipe.crt').read_bytes():
                raise ValueError('publish: ' + apk.name + ' is a test kernel: IPE trusts another certificate')
            # The notes' config is the one the kernel ships.
            if files.get('boot/config-' + kernel) != (directory / (arch + '.config')).read_bytes():
                raise ValueError('publish: ' + directory.name + ' records another config than ' + apk.name + ' ships')
    return record


def kernel_versions(names):
    return {(version(m[1]), int(m[2])) for m in map(re.compile(r'linux-werewolf-([0-9.]+)-r([0-9]+)\.apk').fullmatch,
                                                    names) if m}


def refuse_older(lock, kernels):
    ours = version(lock['version']), lock['revision']
    if kernels and max(kernels) > ours:
        theirs = max(kernels)
        raise ValueError('publish: linux-werewolf ' + lock['version'] + '-r' + str(lock['revision']) +
                         ' is older than the published ' + '.'.join(map(str, theirs[0])) + '-r' + str(theirs[1]) +
                         '; refusing to go back')


def published():
    """The kernels in the stable repository machines follow, as (version, revision)."""
    try:
        # Cloudflare, in front of R2, refuses Python's own User-Agent.
        request = urllib.request.Request(PUBLIC + ARCHES[0] + '/APKINDEX.tar.gz', headers={'User-Agent': notes.AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return set()
        raise
    with tempfile.TemporaryDirectory() as directory:
        index = Path(directory) / 'APKINDEX.tar.gz'
        index.write_bytes(data)
        names = stanzas(authenticated(index, TRUST))
    return kernel_versions(names)


def status(tag, lock):
    current = release(tag)
    complete = current is not None and 'release.json' in {a['name'] for a in current['assets']}
    if complete and not current['draft']:
        return 'complete'
    if current is not None and not current['draft']:
        raise ValueError('publish: public release ' + tag + ' has no completion manifest')
    # A new build of a published version would never reach a machine: the stable
    # repository keeps a version's first build. Nor may kernel.org walk us back.
    kernels = published()
    refuse_older(lock, kernels)
    if complete:
        return 'publish'
    ours, full = (version(lock['version']), lock['revision']), lock['version'] + '-r' + str(lock['revision'])
    for theirs in kernels:
        if theirs == ours:
            raise ValueError('publish: linux-werewolf ' + full + ' is already published, built from other inputs; '
                             'increment policy.json revision to ship this build')
    return 'build'


def asset(apk, arch):
    """An APK's name among a release's assets, which both arches' share: NAME-VERSION.ARCH.apk."""
    return apk.removesuffix('.apk') + '.' + arch + '.apk'


def stage(artifacts, assets, lock, tag):
    assets.mkdir(parents=True, exist_ok=True)
    names = []
    for arch in ARCHES:
        directory = artifacts / ('linux-werewolf-' + arch)
        validate(directory, arch, lock, os.environ['GITHUB_SHA'])
        names.append('linux-werewolf-' + arch + '.tar.gz')
        archive(directory, assets / names[-1])
        for apk in sorted((directory / arch).glob('*.apk')):
            names.append(asset(apk.name, arch))
            shutil.copyfile(apk, assets / names[-1])
    current = release(tag)
    if current is not None and not current['draft']:
        raise ValueError('publish: refusing to change public release ' + tag)
    # A resumed draft keeps the notes it was staged with, as what they draw on moves.
    if current is not None and 'NOTES.md' in {a['name'] for a in current['assets']}:
        run('gh', 'release', 'download', tag, '--pattern', 'NOTES.md', '--dir', str(assets), '--clobber')
    else:
        files = [(name, (assets / name).stat().st_size, sha256(assets / name)) for name in names]
        notes.write(assets / 'NOTES.md', lock, artifacts, files, PUBLIC, os.environ['GITHUB_REPOSITORY'],
                    os.environ['GITHUB_SHA'])
    names.append('NOTES.md')
    manifest = {'build_id': lock['build_id'], 'version': lock['version'] + '-r' + str(lock['revision']),
                'source_sha': os.environ['GITHUB_SHA'], 'run_number': int(os.environ['GITHUB_RUN_NUMBER']),
                'repository': PUBLIC + 'builds/' + lock['build_id'],
                'notes': PUBLIC + 'builds/' + lock['build_id'] + '/NOTES.md',
                'sha256': {name: sha256(assets / name) for name in sorted(names)}}
    (assets / 'SHA256SUMS').write_text(''.join(f'{d}  {n}\n' for n, d in manifest['sha256'].items()))
    (assets / 'release.json').write_text(json.dumps(manifest, indent=2) + '\n')
    body = (assets / 'NOTES.md').read_text()
    if len(body) > BODY:
        body = body[:BODY] + '\n\n… the rest is in NOTES.md, among the files.\n'
    if current is None:
        request = {'tag_name': tag, 'draft': True, 'make_latest': 'false', 'target_commitish': os.environ['GITHUB_SHA'],
                   'name': 'linux-werewolf ' + manifest['version'], 'body': body}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'release.json'
            path.write_text(json.dumps(request))
            current = json.loads(run('gh', 'api', '--method', 'POST',
                                     'repos/' + os.environ['GITHUB_REPOSITORY'] + '/releases', '--input', str(path)))
    existing = {a['name'] for a in current['assets']}
    # The manifest goes last: its presence marks a complete draft.
    for path in [assets / n for n in sorted(names)] + [assets / 'SHA256SUMS', assets / 'release.json']:
        if path.name not in existing:
            run('gh', 'release', 'upload', tag, str(path))
            continue
        with tempfile.TemporaryDirectory() as directory:
            run('gh', 'release', 'download', tag, '--pattern', path.name, '--dir', directory)
            if sha256(Path(directory) / path.name) != sha256(path):
                raise ValueError('publish: draft already holds a different ' + path.name)


def aws(*arguments):
    return subprocess.run(['aws', '--endpoint-url', ENDPOINT, '--region', 'auto', 's3api', *arguments],
                          capture_output=True, text=True)


def fetch(key, destination):
    """True if the bucket holds key, now in destination; False if it does not; anything else raises."""
    result = aws('get-object', '--bucket', BUCKET, '--key', PREFIX + key, str(destination))
    if result.returncode == 0:
        return True
    if '(NoSuchKey)' in result.stderr or '(404)' in result.stderr:
        return False
    raise RuntimeError(result.stderr)


def upload(path, key, immutable=True):
    if immutable:
        with tempfile.TemporaryDirectory() as directory:
            previous = Path(directory) / 'object'
            if fetch(key, previous):
                if sha256(previous) != sha256(path):
                    raise ValueError('publish: R2 already holds a different ' + key)
                return
    result = aws('put-object', '--bucket', BUCKET, '--key', PREFIX + key, '--body', str(path),
                 '--cache-control', 'public, max-age=31536000, immutable' if immutable else 'no-cache')
    if result.returncode:
        raise RuntimeError(result.stderr)


def merge(previous, current):
    """The stable index's entries: every published APK keeps its first build."""
    merged, added = dict(previous), []
    for name, stanza in sorted(current.items()):
        if name not in merged:
            merged[name] = stanza
            added.append(name)
        elif merged[name] != stanza:
            print('publish:', name, 'keeps its first build; increment policy.json revision to ship this one')
    return merged, added


def signed_index(entries, key):
    text = ''.join(entries[name] + '\n\n' for name in sorted(entries)).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in [('APKINDEX', text), ('DESCRIPTION', b'')]:
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(data), 0o644
            tar.addfile(item, io.BytesIO(data))
    control = gzip.compress(buffer.getvalue(), mtime=0)
    signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key)], input=control,
                               stdout=subprocess.PIPE, check=True).stdout
    item = tarfile.TarInfo(KEYNAME)
    item.size, item.mode, item.uname, item.gname = len(signature), 0o644, 'root', 'root'
    # apk reads both members as one tar stream: the signature's has no end marker.
    header = item.tobuf(tarfile.USTAR_FORMAT, tarfile.ENCODING, 'surrogateescape')
    return gzip.compress(header + signature + b'\0' * (-len(signature) % 512), mtime=0) + control


def publish(assets, lock, tag, key=ROOT / 'build/keys/werewolf-packages.rsa'):
    assets.mkdir(parents=True, exist_ok=True)
    run('gh', 'release', 'download', tag, '--dir', str(assets), '--clobber')
    manifest = json.loads((assets / 'release.json').read_text())
    names = {'linux-werewolf-' + arch + '.tar.gz': arch for arch in ARCHES}
    if manifest['build_id'] != lock['build_id'] or not re.fullmatch('[0-9a-f]{40}', manifest['source_sha']):
        raise ValueError('publish: release manifest is for other inputs')
    if not set(names) <= set(manifest['sha256']):
        raise ValueError('publish: both native architectures are required')
    for name, digest in manifest['sha256'].items():
        if sha256(assets / name) != digest:
            raise ValueError('publish: ' + name + ' does not match the release manifest')
    if 'NOTES.md' not in manifest['sha256']:
        raise ValueError('publish: the release has no notes')
    apks = set(manifest['sha256']) - set(names) - {'NOTES.md'}
    snapshot = 'builds/' + lock['build_id'] + '/'
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        roots, indexes = {}, {}
        # Validate and sign everything before the first upload.
        for name, arch in names.items():
            roots[arch] = work / arch
            with tarfile.open(assets / name) as tar:
                tar.extractall(roots[arch], filter='data')
            validate(roots[arch], arch, lock, manifest['source_sha'])
            # The release's own APKs are the ones R2 gets, byte for byte.
            for apk in (roots[arch] / arch).glob('*.apk'):
                if manifest['sha256'].get(asset(apk.name, arch)) != sha256(apk):
                    raise ValueError('publish: the release lacks ' + asset(apk.name, arch) + ' as built')
                apks.discard(asset(apk.name, arch))
            previous = {}
            published = work / (arch + '-published.tar.gz')
            if fetch(arch + '/APKINDEX.tar.gz', published):
                previous = stanzas(authenticated(published, TRUST))
            # Recheck the bucket for both arches: discovery may be old or a draft resumed.
            refuse_older(lock, kernel_versions(previous))
            merged, added = merge(previous, stanzas(authenticated(roots[arch] / arch / 'APKINDEX.tar.gz', TRUST)))
            index = work / (arch + '-APKINDEX.tar.gz')
            index.write_bytes(signed_index(merged, key))
            authenticated(index, TRUST)
            indexes[arch] = index, added
        if apks:
            raise ValueError('publish: the release holds APKs no build made: ' + ', '.join(sorted(apks)))
        for arch, root in roots.items():
            # Objects before the index that names them: readers never see a partial index.
            for apk in sorted((root / arch).glob('*.apk')):
                upload(apk, snapshot + arch + '/' + apk.name)
            upload(root / arch / 'APKINDEX.tar.gz', snapshot + arch + '/APKINDEX.tar.gz')
            upload(assets / ('linux-werewolf-' + arch + '.tar.gz'), snapshot + 'linux-werewolf-' + arch + '.tar.gz')
        upload(assets / 'NOTES.md', snapshot + 'NOTES.md')
        upload(assets / 'SHA256SUMS', snapshot + 'SHA256SUMS')
        upload(assets / 'release.json', snapshot + 'release.json')
        # The stable repository machines follow keeps every published APK; only its index is replaced.
        for arch, (index, added) in indexes.items():
            for name in added:
                upload(roots[arch] / arch / name, arch + '/' + name)
            upload(index, arch + '/APKINDEX.tar.gz', immutable=False)
    with tempfile.TemporaryDirectory() as directory:
        current = Path(directory) / 'current'
        # A run that finished late never moves the pointer back, nor becomes GitHub's latest.
        newest = not fetch('current.json', current) or \
            json.loads(current.read_text())['run_number'] <= manifest['run_number']
        if newest:
            upload(assets / 'NOTES.md', 'NOTES.md', immutable=False)
            upload(assets / 'release.json', 'current.json', immutable=False)
    # The public release marks completion, after both repositories exist.
    run('gh', 'release', 'edit', tag, '--draft=false', '--latest=' + ('true' if newest else 'false'))
    print('publish:', manifest['repository'])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['status', 'stage', 'publish'])
    parser.add_argument('--artifacts', type=Path, default=Path('artifacts'))
    parser.add_argument('--assets', type=Path, default=ROOT / 'build/release')
    args = parser.parse_args()
    lock = verify()
    tag = 'build-' + lock['build_id']
    if args.command == 'status':
        state = status(tag, lock)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('state=' + state + '\n')
        print('publish:', tag, state)
    elif args.command == 'stage':
        stage(args.artifacts, args.assets, lock, tag)
    else:
        publish(args.assets, lock, tag)


if __name__ == '__main__':
    main()
