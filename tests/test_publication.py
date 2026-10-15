import contextlib
import gzip
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import publish

LOCK = {'build_id': 'b' * 64, 'version': '7.2.11', 'revision': 1, 'sha256': 'a' * 64, 'released': '2026-10-15'}


def member(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as tar:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
    return gzip.compress(buffer.getvalue())


class Keys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        cls.private, cls.public = root / 'key', root / 'key.pub'
        subprocess.run(['openssl', 'genrsa', '-out', str(cls.private), '2048'], check=True, capture_output=True)
        subprocess.run(['openssl', 'rsa', '-in', str(cls.private), '-pubout', '-out', str(cls.public)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def signed(self, control):
        signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.private)], input=control,
                                   check=True, capture_output=True).stdout
        return member({publish.KEYNAME: signature}) + control


class Authentication(Keys):
    def test_a_signed_index_verifies_and_tampering_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / 'APKINDEX.tar.gz'
            control = member({'APKINDEX': b'P:linux-werewolf\n'})
            index.write_bytes(self.signed(control))
            self.assertEqual(2, len(publish.authenticated(index, self.public)))
            index.write_bytes(self.signed(control)[:-len(control)] + member({'APKINDEX': b'P:attacker\n'}))
            with self.assertRaises(subprocess.CalledProcessError):
                publish.authenticated(index, self.public)
            index.write_bytes(control)
            with self.assertRaisesRegex(ValueError, 'unsigned'):
                publish.authenticated(index, self.public)

    def test_the_stable_index_keeps_every_first_build(self):
        stanza = lambda version, checksum: f'C:{checksum}\nP:linux-werewolf\nV:{version}\nA:aarch64'
        previous = {'linux-werewolf-7.2.10-r1.apk': stanza('7.2.10-r1', 'old')}
        current = {'linux-werewolf-7.2.10-r1.apk': stanza('7.2.10-r1', 'rebuilt'),
                   'linux-werewolf-7.2.11-r1.apk': stanza('7.2.11-r1', 'new')}
        with contextlib.redirect_stdout(io.StringIO()) as log:
            merged, added = publish.merge(previous, current)
        self.assertIn('keeps its first build', log.getvalue())
        self.assertEqual(['linux-werewolf-7.2.11-r1.apk'], added)
        self.assertIn('C:old', merged['linux-werewolf-7.2.10-r1.apk'])
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / 'APKINDEX.tar.gz'
            index.write_bytes(publish.signed_index(merged, self.private))
            self.assertEqual(index.read_bytes(), publish.signed_index(merged, self.private))
            parts = publish.authenticated(index, self.public)
            self.assertEqual(merged, publish.stanzas(parts))
            # One tar stream across both members: no end marker after the signature.
            self.assertEqual(1024, len(parts[0][1]))


class Validation(Keys):
    def build(self, root, arch='x86_64', names=publish.PACKAGES, ipe_crt=None, verdict='PASS', config=None):
        """A signed native build as provenance.py lays it out."""
        version = LOCK['version'] + '-r1'
        directory = root / ('linux-werewolf-' + arch)
        (directory / arch).mkdir(parents=True)
        stanzas = []
        for name in sorted(names):
            files = {'boot/file': name.encode()}
            if name == 'linux-werewolf':
                files['boot/ipe.crt'] = (ROOT / 'release/ipe.crt').read_bytes() if ipe_crt is None else ipe_crt
                files['boot/config-7.2.11-werewolf'] = b'CONFIG_MODULES is not set\n'
            payload = member(files)
            info = f'pkgname = {name}\npkgver = {version}\narch = {arch}\ndatahash = '
            info += __import__('hashlib').sha256(payload).hexdigest() + '\n'
            control = self.signed(member({'.PKGINFO': info.encode()}))
            (directory / arch / f'{name}-{version}.apk').write_bytes(control + payload)
            stanzas.append(f'P:{name}\nV:{version}\nA:{arch}')
        (directory / arch / 'APKINDEX.tar.gz').write_bytes(
            self.signed(member({'APKINDEX': ('\n\n'.join(stanzas) + '\n').encode()})))
        (directory / 'werewolf-packages.rsa.pub').write_bytes(self.public.read_bytes())
        (directory / 'linux.yaml').write_text('recipe')
        (directory / (arch + '.config')).write_bytes(config if config is not None else b'CONFIG_MODULES is not set\n')
        (directory / 'probe.log').write_text(f'probe: ok no module loader\nprobe: {verdict} 7.2.11-werewolf\n')
        record = {'build_id': LOCK['build_id'], 'arch': arch, 'version': version, 'source_sha': '1' * 40,
                  'sha256': {str(p.relative_to(directory)): publish.sha256(p)
                             for p in sorted(directory.rglob('*')) if p.is_file()}}
        (directory / 'build.json').write_text(json.dumps(record))
        return directory

    def validate(self, directory, arch='x86_64', source='1' * 40):
        with patch.object(publish, 'TRUST', self.public), patch.object(publish, 'recipe', return_value='recipe'):
            return publish.validate(directory, arch, LOCK, source)

    def test_a_complete_signed_build_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual('x86_64', self.validate(self.build(Path(directory)))['arch'])

    def test_wrong_commit_arch_extra_file_or_missing_package_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            built = self.build(root)
            with self.assertRaisesRegex(ValueError, 'another commit'):
                self.validate(built, source='2' * 40)
            with self.assertRaisesRegex(ValueError, 'other inputs'):
                self.validate(built, arch='aarch64')
            (built / 'extra').write_text('x')
            with self.assertRaisesRegex(ValueError, 'unrecorded'):
                self.validate(built)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'exactly'):
                self.validate(self.build(Path(directory), names={'linux-werewolf'}))

    def test_a_recorded_config_must_be_the_one_shipped(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'another config'):
                self.validate(self.build(Path(directory), config=b'CONFIG_MODULES=y\n'))

    def test_a_build_without_a_passing_probe_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'no passing probe'):
                self.validate(self.build(Path(directory), verdict='FAIL'))

    def test_a_test_kernel_trusting_another_ipe_certificate_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'test kernel'):
                self.validate(self.build(Path(directory), ipe_crt=b'disposable certificate'))

    def test_a_build_signed_by_an_ephemeral_key_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            built = self.build(Path(directory))
            with patch.object(publish, 'TRUST', ROOT / 'release/packages.pub'), \
                    patch.object(publish, 'recipe', return_value='recipe'), \
                    self.assertRaisesRegex(ValueError, 'ephemeral'):
                publish.validate(built, 'x86_64', LOCK, '1' * 40)


class Publication(Validation):
    def draft(self, root):
        """A staged draft's assets: each arch's archive and APKs, SHA256SUMS and release.json."""
        assets = root / 'assets'
        assets.mkdir()
        names = []
        for arch in publish.ARCHES:
            built = self.build(root / 'artifacts', arch)
            names.append('linux-werewolf-' + arch + '.tar.gz')
            publish.archive(built, assets / names[-1])
            for apk in (built / arch).glob('*.apk'):
                names.append(publish.asset(apk.name, arch))
                (assets / names[-1]).write_bytes(apk.read_bytes())
        (assets / 'NOTES.md').write_text('# notes\n')
        self.manifest(assets, names + ['NOTES.md'])
        return assets

    def manifest(self, assets, names):
        digests = {name: publish.sha256(assets / name) for name in sorted(names)}
        (assets / 'SHA256SUMS').write_text(''.join(f'{d}  {n}\n' for n, d in digests.items()))
        (assets / 'release.json').write_text(json.dumps({
            'build_id': LOCK['build_id'], 'source_sha': '1' * 40, 'run_number': 7,
            'repository': 'r', 'sha256': digests}))

    def publish(self, assets):
        uploaded = {}
        with patch.object(publish, 'TRUST', self.public), patch.object(publish, 'recipe', return_value='recipe'), \
                patch.object(publish, 'run', return_value=''), patch.object(publish, 'fetch', return_value=False), \
                patch.object(publish, 'upload', side_effect=lambda path, key, immutable=True:
                             uploaded.setdefault(key, Path(path).read_bytes())):
            publish.publish(assets, LOCK, 'build-x', key=self.private)
        return uploaded

    def test_the_stable_repository_lists_its_kernels(self):
        with tempfile.TemporaryDirectory() as directory:
            index = (self.build(Path(directory)) / 'x86_64/APKINDEX.tar.gz').read_bytes()
        with patch.object(publish, 'TRUST', self.public), \
                patch.object(publish.urllib.request, 'urlopen', return_value=io.BytesIO(index)) as opened:
            self.assertEqual({((7, 2, 11), 1)}, publish.published())
        self.assertEqual(publish.notes.AGENT, opened.call_args[0][0].get_header('User-agent'))
        missing = publish.urllib.error.HTTPError('u', 404, 'Not Found', {}, None)
        with patch.object(publish.urllib.request, 'urlopen', side_effect=missing):
            self.assertEqual(set(), publish.published())

    def test_github_and_r2_carry_the_same_apks(self):
        with tempfile.TemporaryDirectory() as directory:
            assets = self.draft(Path(directory))
            uploaded = self.publish(assets)
            name = 'linux-werewolf-' + LOCK['version'] + '-r1.apk'
            for arch in publish.ARCHES:
                github = (assets / publish.asset(name, arch)).read_bytes()
                self.assertEqual(github, uploaded[arch + '/' + name])
                self.assertEqual(github, uploaded['builds/' + LOCK['build_id'] + '/' + arch + '/' + name])
            self.assertEqual(b'# notes\n', uploaded['builds/' + LOCK['build_id'] + '/NOTES.md'])
            self.assertEqual(b'# notes\n', uploaded['NOTES.md'])

    def test_a_release_whose_apks_differ_or_are_extra_fails(self):
        for change, error in [('differ', 'lacks'), ('extra', 'no build made')]:
            with self.subTest(change), tempfile.TemporaryDirectory() as directory:
                assets = self.draft(Path(directory))
                names = json.loads((assets / 'release.json').read_text())['sha256']
                if change == 'differ':
                    (assets / publish.asset('linux-werewolf-7.2.11-r1.apk', 'x86_64')).write_bytes(b'other')
                else:
                    (assets / 'stray-1-r0.x86_64.apk').write_bytes(b'stray')
                    names = {**names, 'stray-1-r0.x86_64.apk': ''}
                self.manifest(assets, names)
                with self.assertRaisesRegex(ValueError, error):
                    self.publish(assets)


class Release(unittest.TestCase):
    def test_draft_lookup_paginates_and_keeps_api_errors(self):
        draft = {'tag_name': 'build-x', 'draft': True, 'assets': []}
        response = subprocess.CompletedProcess([], 0, json.dumps([[{'tag_name': 'other'}], [draft]]), '')
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'example/repo'}):
            with patch.object(subprocess, 'run', return_value=response) as api:
                self.assertEqual(draft, publish.release('build-x'))
                self.assertIn('--paginate', api.call_args.args[0])
            response.returncode, response.stderr = 1, 'HTTP 403: Forbidden'
            with patch.object(subprocess, 'run', return_value=response), self.assertRaises(RuntimeError):
                publish.release('build-x')

    def test_status_reuses_only_complete_drafts(self):
        cases = [(None, 'build'), ({'draft': True, 'assets': []}, 'build'),
                 ({'draft': True, 'assets': [{'name': 'release.json'}]}, 'publish'),
                 ({'draft': False, 'assets': [{'name': 'release.json'}]}, 'complete')]
        for current, state in cases:
            with self.subTest(state=state), patch.object(publish, 'release', return_value=current), \
                    patch.object(publish, 'published', return_value=set()):
                self.assertEqual(state, publish.status('build-x', LOCK))
        public_without_manifest = {'draft': False, 'assets': []}
        with patch.object(publish, 'release', return_value=public_without_manifest), self.assertRaises(ValueError):
            publish.status('build-x', LOCK)

    def test_a_published_version_is_never_rebuilt_nor_walked_back(self):
        for kernels, error in [({((7, 2, 10), 1)}, None), ({((7, 2, 11), 1)}, 'increment policy.json revision'),
                               ({((7, 2, 12), 1)}, 'refusing to go back'), ({((7, 2, 11), 2)}, 'refusing to go back')]:
            with self.subTest(kernels=kernels), patch.object(publish, 'release', return_value=None), \
                    patch.object(publish, 'published', return_value=kernels):
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        publish.status('build-x', LOCK)
                else:
                    self.assertEqual('build', publish.status('build-x', LOCK))

    def test_archives_do_not_depend_on_extraction_times(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'packages').mkdir()
            (root / 'packages/linux.apk').write_bytes(b'signed')
            publish.archive(root / 'packages', root / 'first.tar.gz')
            os.utime(root / 'packages/linux.apk', (42, 42))
            publish.archive(root / 'packages', root / 'second.tar.gz')
            self.assertEqual((root / 'first.tar.gz').read_bytes(), (root / 'second.tar.gz').read_bytes())

    def test_a_partial_stage_resumes_without_a_second_draft_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for arch in publish.ARCHES:
                (root / 'artifacts' / ('linux-werewolf-' + arch)).mkdir(parents=True)
                (root / 'artifacts' / ('linux-werewolf-' + arch) / arch).mkdir()
                (root / 'artifacts' / ('linux-werewolf-' + arch) / arch / 'a-1-r1.apk').write_bytes(arch.encode())
            current, uploaded, calls, fail = None, {}, [], [True]

            def run(*args):
                nonlocal current
                calls.append(args)
                if args[:3] == ('gh', 'api', '--method'):
                    request = json.loads(Path(args[-1]).read_text())
                    self.assertTrue(request['draft'])
                    self.assertEqual('# notes\n', request['body'])
                    current = {'draft': True, 'assets': []}
                    return json.dumps(current)
                if args[:3] == ('gh', 'release', 'upload'):
                    path = Path(args[-1])
                    if path.name == 'linux-werewolf-aarch64.tar.gz' and fail[0]:
                        fail[0] = False
                        raise RuntimeError('transient upload failure')
                    uploaded[path.name] = path.read_bytes()
                    current['assets'].append({'name': path.name})
                elif args[:3] == ('gh', 'release', 'download'):
                    name = args[args.index('--pattern') + 1]
                    (Path(args[args.index('--dir') + 1]) / name).write_bytes(uploaded[name])
                return ''
            environment = {'GITHUB_REPOSITORY': 'example/repo', 'GITHUB_SHA': '1' * 40, 'GITHUB_RUN_NUMBER': '7'}
            with patch.dict(os.environ, environment), patch.object(publish, 'validate'), \
                    patch.object(publish.notes, 'write', lambda path, *args: path.write_text('# notes\n')), \
                    patch.object(publish, 'release', side_effect=lambda tag: current), \
                    patch.object(publish, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'transient'):
                    publish.stage(root / 'artifacts', root / 'assets', LOCK, 'build-x')
                self.assertNotIn('release.json', uploaded)
                publish.stage(root / 'artifacts', root / 'assets', LOCK, 'build-x')
                self.assertEqual(1, sum(args[:3] == ('gh', 'api', '--method') for args in calls))
                self.assertEqual('release.json', Path(calls[-1][-1]).name)
                # Each arch's APKs are assets of their own, named apart, and in the manifest.
                self.assertEqual(b'aarch64', uploaded['a-1-r1.aarch64.apk'])
                self.assertEqual(b'x86_64', uploaded['a-1-r1.x86_64.apk'])
                self.assertIn('a-1-r1.x86_64.apk', json.loads(uploaded['release.json'])['sha256'])
                uploaded['linux-werewolf-x86_64.tar.gz'] = b'conflicting bytes'
                with self.assertRaisesRegex(ValueError, 'different'):
                    publish.stage(root / 'artifacts', root / 'assets', LOCK, 'build-x')


class Bucket(unittest.TestCase):
    def test_an_existing_object_must_match_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'object'
            path.write_bytes(b'new')

            def holding(data):
                def fetch(key, destination):
                    destination.write_bytes(data)
                    return True
                return fetch
            with patch.object(publish, 'fetch', holding(b'old')), patch.object(publish, 'aws') as aws:
                with self.assertRaisesRegex(ValueError, 'different'):
                    publish.upload(path, 'builds/x/a.apk')
                aws.assert_not_called()
            with patch.object(publish, 'fetch', holding(b'new')), patch.object(publish, 'aws') as aws:
                publish.upload(path, 'builds/x/a.apk')
                aws.assert_not_called()
            with patch.object(publish, 'fetch', return_value=False), patch.object(publish, 'aws') as aws:
                aws.return_value.returncode = 0
                publish.upload(path, 'builds/x/a.apk')
                aws.assert_called_once()

    def test_an_authorization_error_is_not_an_absent_object(self):
        failure = subprocess.CompletedProcess([], 1, '', 'An error occurred (AccessDenied)')
        with patch.object(publish, 'aws', return_value=failure), self.assertRaises(RuntimeError):
            publish.fetch('x86_64/APKINDEX.tar.gz', Path('/nonexistent'))


if __name__ == '__main__':
    unittest.main()
