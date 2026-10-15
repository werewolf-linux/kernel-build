from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import config


class Lists(unittest.TestCase):
    def write(self, text):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'list.cfg'
        path.write_text(text)
        return path

    def test_lines_comments_and_unset(self):
        path = self.write('# a comment\n## a heading\n\nCONFIG_A=y\nCONFIG_S="x y"\n# CONFIG_B is not set\n')
        self.assertEqual({'CONFIG_A': 'y', 'CONFIG_S': '"x y"', 'CONFIG_B': None}, config.options(path))

    def test_repeated_and_malformed_lines_stop(self):
        for text in ('CONFIG_A=y\nCONFIG_A=n\n', 'CONFIG_A\n', 'CONFIG_lower=y\n', ' CONFIG_A=y\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                config.options(self.write(text))

    def test_an_option_in_both_lists_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'config').mkdir()
            (root / 'config/common.cfg').write_text('CONFIG_A=y\n')
            (root / 'config/x86_64.cfg').write_text('CONFIG_A=y\n')
            with patch.object(config, 'ROOT', root), self.assertRaisesRegex(ValueError, 'CONFIG_A'):
                config.policy('x86_64')


class Holding(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / 'config').mkdir()
        (root / 'config/common.cfg').write_text('CONFIG_ON=y\nCONFIG_S="-werewolf"\n')
        (root / 'config/x86_64.cfg').write_text('CONFIG_X86=y\n')
        (root / 'config/deny.cfg').write_text('# CONFIG_MODULES is not set\n')
        patcher = patch.object(config, 'ROOT', root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_config_holding_every_line_passes(self):
        text = 'CONFIG_ON=y\nCONFIG_S="-werewolf"\nCONFIG_X86=y\nCONFIG_IMPLIED=y\n'
        self.assertEqual([], config.misses('x86_64', text))

    def test_a_missing_listed_option_fails(self):
        self.assertEqual(['CONFIG_ON=n, listed y'], config.misses('x86_64', 'CONFIG_S="-werewolf"\nCONFIG_X86=y\n'))

    def test_a_denied_option_fails_even_when_selected(self):
        failed = config.misses('x86_64', 'CONFIG_ON=y\nCONFIG_S="-werewolf"\nCONFIG_X86=y\nCONFIG_MODULES=y\n')
        self.assertEqual(['CONFIG_MODULES=y, listed n'], failed)

    def test_a_module_does_not_satisfy_a_built_in_line(self):
        self.assertTrue(config.misses('x86_64', 'CONFIG_ON=m\nCONFIG_S="-werewolf"\nCONFIG_X86=y\n'))


class Comparison(unittest.TestCase):
    def test_compiler_probes_are_not_choices(self):
        committed = 'CONFIG_CC_VERSION_TEXT="clang 23"\nCONFIG_CLANG_VERSION=230103\nCONFIG_CC_HAS_NEW=y\nCONFIG_A=y\n'
        configured = 'CONFIG_CC_VERSION_TEXT="clang 22"\nCONFIG_CLANG_VERSION=220108\nCONFIG_A=y\n'
        self.assertEqual([], config.differences(committed, configured))

    def test_host_tool_probes_are_not_choices(self):
        committed = 'CONFIG_RUSTC_LLVM_MAJOR_VERSION=23\nCONFIG_OPENSSL_SUPPORTS_ML_DSA=y\nCONFIG_CC_MS_EXTENSIONS="-x"\n'
        self.assertEqual([], config.differences(committed, 'CONFIG_CC_MS_EXTENSIONS="-y"\n'))

    def test_a_real_option_differing_is_reported(self):
        self.assertEqual(['CONFIG_KMALLOC_PARTITION_TYPED: committed y, configured n'],
                         config.differences('CONFIG_KMALLOC_PARTITION_TYPED=y\n', ''))


class Committed(unittest.TestCase):
    def test_both_committed_configs_hold_the_lists_and_the_deny_list(self):
        for arch in config.KERNEL_ARCH:
            with self.subTest(arch=arch):
                text = (ROOT / 'config' / (arch + '.config')).read_text()
                self.assertEqual([], config.misses(arch, text))
                self.assertIn('# CONFIG_MODULES is not set', text.splitlines())

    def test_the_deny_list_only_turns_options_off(self):
        self.assertTrue(all(value is None for value in config.options(ROOT / 'config/deny.cfg').values()))


if __name__ == '__main__':
    unittest.main()
