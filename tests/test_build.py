from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build

LOCK = {'version': '7.2.11', 'revision': 3, 'sha256': 'a' * 64, 'released': '2026-10-15'}
TOOLS = {'clang-22': '22.1.8-r6', 'lld-22': '22.1.8-r6', 'llvm-22': '22.1.8-r6'}


class Recipe(unittest.TestCase):
    def test_every_field_is_filled(self):
        for arch in ('x86_64', 'aarch64'):
            with self.subTest(arch=arch):
                text = build.recipe(LOCK, TOOLS, arch)
                self.assertNotRegex(text, r'@[A-Z0-9_]+@')
                self.assertIn('version: "7.2.11"', text)
                self.assertIn('epoch: 3', text)
                self.assertIn('https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-${{package.version}}.tar.xz', text)
                self.assertIn('expected-sha256: "' + 'a' * 64 + '"', text)
                self.assertIn('clang-22=22.1.8-r6', text)
                self.assertIn('qemu-system-' + arch, text)

    def test_an_unknown_field_stops(self):
        text = (ROOT / 'linux.yaml').read_text() + '# @SOMETHING_NEW@\n'
        with patch.object(Path, 'read_text', return_value=text), self.assertRaisesRegex(ValueError, 'SOMETHING_NEW'):
            build.recipe(LOCK, TOOLS, 'x86_64')

    def test_a_value_carrying_yaml_or_shell_stops(self):
        for change in ({'released': '2026-10-15"\nmalicious: x'}, {'version': '7.2.11; rm -rf /'}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'refusing'):
                build.recipe(dict(LOCK, **change), TOOLS, 'x86_64')

    def test_the_build_derives_and_checks_the_config_before_compiling(self):
        text = (ROOT / 'linux.yaml').read_text()
        self.assertLess(text.index('config.py check'), text.index('LLVM=1 -j$(nproc)'))
        # The lists over allnoconfig, for whatever release: no defaults fill gaps,
        # and make config's committed copy is not an input.
        self.assertIn('werewolf/config/common.cfg werewolf/config/${{build.arch}}.cfg', text)
        self.assertIn('KCONFIG_ALLCONFIG=$PWD/out/lists.cfg allnoconfig', text)
        self.assertNotIn('.config allnoconfig', text)
        self.assertNotIn('olddefconfig', text)

    def test_the_test_boots_the_kernel_and_requires_a_pass(self):
        text = (ROOT / 'linux.yaml').read_text()
        self.assertIn("grep -q 'probe: PASS ' boot.log", text)
        self.assertIn("! grep -q 'probe: FAIL' boot.log", text)


if __name__ == '__main__':
    unittest.main()
