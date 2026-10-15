#!/usr/bin/env python3
"""Capture kernel.org's newest release of the policy's moniker without maintaining a version.

It stays on the series the committed configs were made from: a new series adds options
nobody has reviewed, and its first build waits for make config. Until then, the series
we have keeps getting its point releases, and GITHUB_OUTPUT's `newer` names the new one.
`--series 7.3` captures the new one for `make config`.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request
from inputs import ROOT, INPUTS, LOCK, ARCHES, identity, policy_hashes, sha256

RELEASES = 'https://www.kernel.org/releases.json'
KEYS = ROOT / 'release/kernel.org'
# Primary key fingerprints, from https://www.kernel.org/signature.html.
SIGNERS = {'647F28654894E3BD457199BE38DBBDC86092693E': 'Greg Kroah-Hartman',
           'ABAF11C65A2970B130ABE3C479BE3E4300411886': 'Linus Torvalds'}
VERSION = re.compile(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?')


def version(text):
    return tuple(int(part) for part in text.split('.'))


def series(text):
    return '.'.join(text.split('.')[:2])


def configured_series(root=ROOT):
    """The series both committed configs were made from, as kconfig recorded it."""
    found = set()
    for arch in ARCHES:
        header = re.search(r'^# Linux/\S+ ([0-9]+\.[0-9]+)[0-9.]* Kernel Configuration$',
                           (root / 'config' / (arch + '.config')).read_text(), re.M)
        if not header:
            raise ValueError('config/' + arch + '.config names no kernel version')
        found.add(header[1])
    if len(found) != 1:
        raise ValueError('the configs come from different series: ' + ', '.join(sorted(found)))
    return found.pop()


def latest(releases, moniker, within=None):
    """The newest supported release of moniker, in series within if named."""
    candidates = [r for r in releases['releases']
                  if r['moniker'] == moniker and not r['iseol'] and VERSION.fullmatch(r['version']) and
                  (within is None or series(r['version']) == within)]
    if not candidates:
        raise ValueError('No supported ' + moniker + ' release' + (' in the ' + within + ' series' if within else '') +
                         ' on kernel.org' + ('; it has ended: run make config on the next' if within else ''))
    release = max(candidates, key=lambda r: version(r['version']))
    major = release['version'].split('.')[0]
    source = 'https://cdn.kernel.org/pub/linux/kernel/v' + major + '.x/linux-' + release['version'] + '.tar.xz'
    if release['source'] != source or release['pgp'] != source[:-3] + '.sign':
        raise ValueError('Unexpected kernel.org source or signature URL for ' + release['version'])
    if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', release['released']['isodate']):
        raise ValueError('Unexpected kernel.org release date for ' + release['version'])
    return release


def fetch(url, destination):
    partial = destination.with_name(destination.name + '.part')
    with urllib.request.urlopen(url, timeout=120) as response, partial.open('wb') as output:
        shutil.copyfileobj(response, output)
    partial.replace(destination)


def verified(tarball, signature, keys=KEYS):
    """Return the primary fingerprint that signed the uncompressed tarball, or raise."""
    with tempfile.TemporaryDirectory() as home:
        gpg = ['gpg', '--batch', '--no-autostart', '--homedir', home]
        for key in sorted(keys.glob('*.asc')):
            subprocess.run(gpg + ['--import', str(key)], check=True, capture_output=True)
        with subprocess.Popen(['xz', '-dc', str(tarball)], stdout=subprocess.PIPE) as decompress:
            result = subprocess.run(gpg + ['--status-fd', '1', '--verify', str(signature), '-'],
                                    stdin=decompress.stdout, capture_output=True, text=True)
            decompress.stdout.close()
    # VALIDSIG's last field is the primary key's fingerprint, whichever subkey signed.
    # GOODSIG means that key is neither expired nor revoked.
    # A bad signature stops gpg reading, which breaks xz's pipe: judge gpg first.
    status = result.stdout.splitlines()
    signers = [line.split()[-1] for line in status if line.startswith('[GNUPG:] VALIDSIG ')]
    good = [line for line in status if line.startswith('[GNUPG:] GOODSIG ')]
    if result.returncode or len(signers) != 1 or len(good) != 1 or signers[0] not in SIGNERS:
        raise ValueError('Kernel source is not signed by a kernel.org release signer')
    if decompress.returncode:
        raise ValueError('Kernel source tarball did not decompress completely')
    return signers[0]


def capture(release, tarball, signer, destination=INPUTS):
    policy = json.loads((ROOT / 'policy.json').read_text())
    revision = policy['revision']
    if type(revision) is not int or revision < 1:
        raise ValueError('Policy revision must be a positive integer')
    lock = {'version': release['version'], 'moniker': release['moniker'],
            'released': release['released']['isodate'], 'source': release['source'],
            'sha256': sha256(tarball), 'signer': signer, 'revision': revision,
            'policy_sha256': policy_hashes()}
    lock['build_id'] = identity(lock)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / LOCK).write_text(json.dumps(lock, indent=2) + '\n')
    return lock


def unpack(lock, cache):
    """Extract the captured release's source for make config, if its bytes still match the lock."""
    tarball = cache / lock['source'].rsplit('/', 1)[1]
    tree = cache / ('linux-' + lock['version'])
    if tree.is_dir():
        return tree
    if not tarball.is_file() or sha256(tarball) != lock['sha256']:
        raise SystemExit('refresh: ' + tarball.name + ' is missing or not the locked release; run make refresh')
    subprocess.run(['tar', '-xJf', str(tarball), '-C', str(cache)], check=True)
    return tree


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--releases', type=Path, help='saved releases.json, for offline use')
    parser.add_argument('--cache', type=Path, default=ROOT / 'build/source', help='where tarballs are kept')
    parser.add_argument('--unpack', action='store_true', help='only extract the captured release')
    parser.add_argument('--series', help='capture this series, not the configs\' own: the move to a new one')
    args = parser.parse_args()
    if args.unpack:
        # Editing the lists changes the policy hashes; the source needs only its own.
        print('refresh: source in', unpack(json.loads((INPUTS / LOCK).read_text()), args.cache))
        return
    if args.releases:
        releases = json.loads(args.releases.read_text())
    else:
        with urllib.request.urlopen(RELEASES, timeout=60) as response:
            releases = json.load(response)
    moniker = json.loads((ROOT / 'policy.json').read_text())['moniker']
    current = args.series or configured_series()
    release = latest(releases, moniker, current)
    newest = latest(releases, moniker)
    if version(series(newest['version'])) > version(current):
        print('refresh: kernel.org\'s newest', moniker, 'series is', series(newest['version']) + '; staying on',
              current, 'until make config moves the lists to it', flush=True)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
                output.write('newer=' + series(newest['version']) + '\n')
    args.cache.mkdir(parents=True, exist_ok=True)
    tarball = args.cache / release['source'].rsplit('/', 1)[1]
    signature = args.cache / release['pgp'].rsplit('/', 1)[1]
    if not tarball.is_file():
        print('refresh: downloading', release['source'], flush=True)
        fetch(release['source'], tarball)
    fetch(release['pgp'], signature)
    signer = verified(tarball, signature)
    lock = capture(release, tarball, signer)
    print('refresh: Linux', lock['version'], '(' + moniker + ', released', lock['released'] + ')',
          'signed by', SIGNERS[signer], 'build', lock['build_id'])


if __name__ == '__main__':
    main()
