import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import notes

LOCK = {'build_id': 'b' * 64, 'version': '7.2.11', 'revision': 1, 'released': '2026-10-15', 'moniker': 'stable',
        'signer': '647F28654894E3BD457199BE38DBBDC86092693E'}
PREVIOUS = {'build_id': 'a' * 64, 'version': '7.2.9-r1', 'source_sha': '1' * 40}


def record(cve, branch, fixed, title='net: fix'):
    versions = [{'version': '0', 'lessThan': '5.15', 'status': 'unaffected', 'versionType': 'semver'},
                {'version': fixed, 'lessThanOrEqual': branch + '.*', 'status': 'unaffected', 'versionType': 'semver'}]
    return {'cveMetadata': {'cveId': cve}, 'containers': {'cna': {'title': title, 'affected': [{'versions': versions}]}}}


def vulns(*records):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
        for item in records:
            data = json.dumps(item).encode()
            member = tarfile.TarInfo('vulns-master/cve/published/2026/' + item['cveMetadata']['cveId'] + '.json')
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


class Versions(unittest.TestCase):
    def test_notes_count_from_the_last_release_or_this_ones_predecessor(self):
        self.assertEqual('7.2.9', notes.base('7.2.11', '7.2.9'))
        self.assertEqual('7.2.10', notes.base('7.2.11', None))
        self.assertEqual('7.2.10', notes.base('7.2.11', '7.1.40'))
        self.assertIsNone(notes.base('7.3.1', '7.2.20'))
        self.assertIsNone(notes.base('7.3', None))

    def test_changelogs_name_each_point_release_and_count_its_commits(self):
        with patch.object(notes, 'fetch', return_value=b'commit 1\nx\ncommit 2\n'):
            found = notes.changelogs('7.2.11', '7.2.9')
        self.assertEqual(['7.2.10', '7.2.11'], [name for name, _, _ in found])
        self.assertEqual('https://cdn.kernel.org/pub/linux/kernel/v7.x/ChangeLog-7.2.11', found[1][1])
        self.assertEqual(2, found[1][2])
        self.assertEqual([], notes.changelogs('7.3', None))
        with patch.object(notes, 'fetch', side_effect=OSError('offline')):
            self.assertEqual([('7.2.11', notes.changelogs('7.2.11', None)[0][1], None)],
                             notes.changelogs('7.2.11', None))


class Security(unittest.TestCase):
    def test_only_fixes_on_this_branch_after_the_last_release(self):
        archive = vulns(record('CVE-2026-1', '7.2', '7.2.10', 'net: a'), record('CVE-2026-2', '7.2', '7.2.11'),
                        record('CVE-2026-3', '7.2', '7.2.9'), record('CVE-2026-4', '7.1', '7.1.50'),
                        record('CVE-2026-5', '7.2', '7.2.12'), record('CVE-2026-6', '7.2', '7.2.x'))
        self.assertEqual([('CVE-2026-1', '7.2.10', 'net: a'), ('CVE-2026-2', '7.2.11', 'net: fix')],
                         notes.cves('7.2.11', '7.2.9', archive))


class Render(unittest.TestCase):
    def data(self, **changes):
        probe = ['probe: ok no module loader', 'probe: PASS 7.2.11-werewolf']
        config = '# CONFIG_A is not set\nCONFIG_B=y\nCONFIG_CC_VERSION_TEXT="clang 22"\n'
        data = {'lock': LOCK, 'previous': PREVIOUS, 'since': '7.2.9', 'same': False,
                'public': 'https://dist.example/apk/kernel/', 'repository': 'werewolf-linux/kernel-build',
                'sha': '2' * 40, 'files': [('linux-werewolf-x86_64.tar.gz', 10, 'c' * 64)],
                'changelogs': [('7.2.10', 'https://cdn/ChangeLog-7.2.10', 300), ('7.2.11', 'https://cdn/ChangeLog-7.2.11', None)],
                'cves': [('CVE-2026-1', '7.2.10', 'net: a | b')],
                'commits': [('3' * 12, 'Turn on GVE', 'https://github.com/c/3')],
                'configs': {arch: config for arch in notes.ARCHES},
                'previous_configs': {arch: config.replace('CONFIG_B=y', '# CONFIG_B is not set')
                                     .replace('clang 22', 'clang 21') for arch in notes.ARCHES},
                'probe': {arch: probe for arch in notes.ARCHES},
                'runner': {arch: {'runner': 'bubblewrap'} for arch in notes.ARCHES},
                'tools': {'melange': {'version': '0.62.1'}, 'toolchain': {'clang-22': '22.1.8-r6'}}}
        return {**data, **changes}

    def test_every_section_says_what_changed(self):
        text = notes.render(self.data())
        for expected in ['# linux-werewolf 7.2.11-r1', 'signed by Greg Kroah-Hartman', 'Follows 7.2.9-r1',
                         '- [7.2.10](https://cdn/ChangeLog-7.2.10): 300 commits', '- [7.2.11](https://cdn/ChangeLog-7.2.11)\n',
                         '| [CVE-2026-1](https://www.cve.org/CVERecord?id=CVE-2026-1) | 7.2.10 | net: a / b |',
                         '[`333333333333`](https://github.com/c/3) Turn on GVE',
                         'x86_64: 1 option.', '- `CONFIG_B`: off → y', 'x86_64: PASS 7.2.11-werewolf (bubblewrap)',
                         'Melange 0.62.1', '`clang-22` 22.1.8-r6', '| `linux-werewolf-x86_64.tar.gz` | 10 |']:
            self.assertIn(expected, text)
        # The compiler's own probes are not our configuration.
        self.assertNotIn('CC_VERSION_TEXT', text)

    def test_the_first_release_and_a_new_revision_say_so(self):
        first = notes.render(self.data(previous=None, commits=None, previous_configs=None))
        self.assertIn('The first build published', first)
        self.assertNotIn('## Configuration changes', first)
        same = notes.render(self.data(same=True, changelogs=[], cves=[],
                                      previous={**PREVIOUS, 'version': '7.2.11-r1'}))
        self.assertIn('None: the same Linux 7.2.11 as 7.2.11-r1', same)
        self.assertIn('None beyond those 7.2.11-r1 carried.', same)

    def test_a_long_config_change_is_cut_short(self):
        many = ''.join(f'CONFIG_X{i}=y\n' for i in range(notes.LISTED + 5))
        text = notes.render(self.data(configs={arch: many for arch in notes.ARCHES}))
        self.assertIn('x86_64: 65 options.', text)
        self.assertIn('and 5 more', text)


class Gather(unittest.TestCase):
    def test_an_unreachable_network_thins_the_notes_but_never_stops_them(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            for arch in notes.ARCHES:
                build = artifacts / ('linux-werewolf-' + arch)
                build.mkdir()
                (build / (arch + '.config')).write_text('CONFIG_B=y\n')
                (build / 'probe.log').write_text('probe: PASS 7.2.11-werewolf\n')
                (build / 'runner.json').write_text('{"runner": "bubblewrap"}')
                (build / 'tools.lock.json').write_text('{"melange": {"version": "0.62.1"}, "toolchain": {}}')
            with patch.object(notes, 'fetch', side_effect=OSError('network unreachable')):
                text = notes.render(notes.gather(LOCK, artifacts, [], 'https://dist.example/', 'o/r', '2' * 40))
        self.assertIn('The first build published', text)
        self.assertIn("The kernel CNA's records were unavailable: network unreachable.", text)
        self.assertIn('- [7.2.11](https://cdn.kernel.org/pub/linux/kernel/v7.x/ChangeLog-7.2.11)', text)


if __name__ == '__main__':
    unittest.main()
