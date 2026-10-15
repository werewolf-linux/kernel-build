import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build
import inputs
import refresh


def entry(moniker, version, eol=False):
    major = version.split('.')[0]
    source = f'https://cdn.kernel.org/pub/linux/kernel/v{major}.x/linux-{version}.tar.xz'
    return {'moniker': moniker, 'version': version, 'iseol': eol, 'source': source,
            'pgp': source[:-3] + '.sign', 'released': {'isodate': '2026-10-15'}}


class Latest(unittest.TestCase):
    def test_highest_supported_release_of_the_moniker(self):
        releases = {'releases': [entry('mainline', '7.3-rc7'), entry('stable', '7.2.9'), entry('stable', '7.2.11'),
                                 entry('stable', '7.10.1', eol=True), entry('longterm', '6.18.57')]}
        self.assertEqual('7.2.11', refresh.latest(releases, 'stable')['version'])
        self.assertEqual('6.18.57', refresh.latest(releases, 'longterm')['version'])

    def test_numeric_not_textual_order(self):
        releases = {'releases': [entry('stable', '7.2.9'), entry('stable', '7.10.0')]}
        self.assertEqual('7.10.0', refresh.latest(releases, 'stable')['version'])

    def test_a_new_series_waits_while_ours_is_supported(self):
        releases = {'releases': [entry('stable', '7.2.12'), entry('stable', '7.3.1'), entry('stable', '7.3')]}
        self.assertEqual('7.2.12', refresh.latest(releases, 'stable', '7.2')['version'])
        self.assertEqual('7.3.1', refresh.latest(releases, 'stable')['version'])
        ended = {'releases': [entry('stable', '7.2.20', eol=True), entry('stable', '7.3.4')]}
        with self.assertRaisesRegex(ValueError, 'ended: run make config'):
            refresh.latest(ended, 'stable', '7.2')

    def test_the_series_is_the_one_the_configs_were_made_from(self):
        self.assertRegex(refresh.configured_series(), r'^[0-9]+\.[0-9]+$')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config').mkdir()
            (root / 'config/x86_64.config').write_text('#\n# Linux/x86 7.2.11 Kernel Configuration\n')
            (root / 'config/aarch64.config').write_text('#\n# Linux/arm64 7.3.1 Kernel Configuration\n')
            with self.assertRaisesRegex(ValueError, 'different series'):
                refresh.configured_series(root)
            (root / 'config/aarch64.config').write_text('#\n# Linux/arm64 7.2.11 Kernel Configuration\n')
            self.assertEqual('7.2', refresh.configured_series(root))

    def test_an_unexpected_date_stops(self):
        odd = entry('stable', '7.2.11')
        odd['released']['isodate'] = '2026-10-15"\nx'
        with self.assertRaisesRegex(ValueError, 'date'):
            refresh.latest({'releases': [odd]}, 'stable')

    def test_no_release_or_an_unexpected_url_stops(self):
        with self.assertRaises(ValueError):
            refresh.latest({'releases': [entry('mainline', '7.3-rc7')]}, 'stable')
        moved = entry('stable', '7.2.11')
        moved['source'] = 'https://example.invalid/linux-7.2.11.tar.xz'
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            refresh.latest({'releases': [moved]}, 'stable')


class Signature(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        cls.tarball = root / 'linux.tar.xz'
        subprocess.run(['sh', '-c', 'printf "kernel source" | xz > "$0"', str(cls.tarball)], check=True)
        cls.keys, cls.fingerprints = root / 'keys', {}
        cls.keys.mkdir()
        for name in ('release', 'stranger'):
            home = root / name
            home.mkdir(mode=0o700)
            gpg = ['gpg', '--batch', '--homedir', str(home)]
            subprocess.run(gpg + ['--passphrase', '', '--quick-gen-key', name + '@example.invalid',
                                  'ed25519', 'sign', '1d'],
                           check=True, capture_output=True)
            listing = subprocess.run(gpg + ['--with-colons', '--list-keys'], check=True, capture_output=True,
                                     text=True).stdout
            cls.fingerprints[name] = next(l.split(':')[9] for l in listing.splitlines() if l.startswith('fpr:'))
            plain = subprocess.run(['xz', '-dc', str(cls.tarball)], check=True, capture_output=True).stdout
            signature = root / (name + '.sign')
            subprocess.run(gpg + ['--detach-sign', '--armor', '--output', str(signature), '-'], input=plain,
                           check=True, capture_output=True)
            public = subprocess.run(gpg + ['--armor', '--export'], check=True, capture_output=True).stdout
            (cls.keys / (name + '.asc')).write_bytes(public)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def sign(self, name):
        return Path(self.directory.name) / (name + '.sign')

    def test_a_listed_signer_is_accepted(self):
        with patch.dict(refresh.SIGNERS, {self.fingerprints['release']: 'release'}, clear=True):
            signer = refresh.verified(self.tarball, self.sign('release'), self.keys)
            self.assertEqual(self.fingerprints['release'], signer)

    def test_a_valid_signature_from_an_unlisted_key_is_refused(self):
        with patch.dict(refresh.SIGNERS, {self.fingerprints['release']: 'release'}, clear=True), \
                self.assertRaisesRegex(ValueError, 'not signed'):
            refresh.verified(self.tarball, self.sign('stranger'), self.keys)

    def test_changed_source_is_refused(self):
        changed = Path(self.directory.name) / 'changed.tar.xz'
        subprocess.run(['sh', '-c', 'printf "kernel s0urce" | xz > "$0"', str(changed)], check=True)
        with patch.dict(refresh.SIGNERS, {self.fingerprints['release']: 'release'}, clear=True), \
                self.assertRaisesRegex(ValueError, 'not signed'):
            refresh.verified(changed, self.sign('release'), self.keys)

    def test_the_committed_keys_are_the_listed_signers(self):
        with tempfile.TemporaryDirectory() as home:
            gpg = ['gpg', '--batch', '--homedir', home]
            for key in sorted(refresh.KEYS.glob('*.asc')):
                subprocess.run(gpg + ['--import', str(key)], check=True, capture_output=True)
            listing = subprocess.run(gpg + ['--with-colons', '--list-keys'], check=True, capture_output=True,
                                     text=True).stdout
        primaries = {line.split(':')[9] for previous, line in zip([''] + listing.splitlines(), listing.splitlines())
                     if line.startswith('fpr:') and previous.startswith('pub:')}
        self.assertEqual(set(refresh.SIGNERS), primaries)


class Identity(unittest.TestCase):
    def test_bytes_and_our_files_are_the_build_but_the_date_is_not(self):
        lock = {'version': '7.2.11', 'sha256': '1' * 64, 'revision': 1,
                'policy_sha256': {'config/common.cfg': '2' * 64},
                'released': '2026-10-15', 'signer': 'A' * 40}
        first = inputs.identity(lock)
        self.assertEqual(first, inputs.identity(dict(lock, released='2026-10-16', signer='B' * 40)))
        for change in ({'sha256': '3' * 64}, {'revision': 2}, {'version': '7.2.12'},
                       {'policy_sha256': {'config/common.cfg': '4' * 64}}):
            with self.subTest(change=change):
                self.assertNotEqual(first, inputs.identity(dict(lock, **change)))

    def test_everything_the_build_reads_is_an_input(self):
        hashed = inputs.policy_hashes()
        for name in ('linux.yaml', 'tools.lock.json', 'policy.json', 'config/common.cfg', 'config/deny.cfg',
                     'config/x86_64.config', 'boot/probe.c', 'release/ipe.crt', 'scripts/build.py'):
            with self.subTest(name=name):
                self.assertIn(name, hashed)
        for name in build.CONTEXT:
            with self.subTest(context=name):
                self.assertTrue(any(path == name or path.startswith(name + '/') for path in hashed))
        for name in ('tests/test_refresh.py', 'scripts/publish.py', '.github/workflows/refresh.yml', 'README.md'):
            with self.subTest(outside=name):
                self.assertNotIn(name, hashed)

    def test_a_changed_policy_file_needs_a_new_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'policy.json').write_text('{"revision": 1}')
            lock = {'version': '7.2.11', 'sha256': '1' * 64, 'revision': 1, 'policy_sha256': inputs.policy_hashes(root)}
            lock['build_id'] = inputs.identity(lock)
            (root / inputs.LOCK).write_text(json.dumps(lock))
            inputs.verify(root, root)
            (root / 'policy.json').write_text('{"revision": 2}')
            with self.assertRaisesRegex(ValueError, 'refresh'):
                inputs.verify(root, root)


if __name__ == '__main__':
    unittest.main()
