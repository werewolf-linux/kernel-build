import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/setup-runner.py'
spec = importlib.util.spec_from_file_location('runner_setup', SCRIPT)
runner_setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner_setup)

TEMPLATE = '''abi <abi/5.0>,
profile bwrap /usr/bin/bwrap flags=(attach_disconnected,mediate_deleted) {
  allow capability,
  allow file rwlkm /{**,},
  allow pix /** -> &bwrap//&unpriv_bwrap,
  include if exists <local/bwrap-userns-restrict>
}
profile unpriv_bwrap flags=(attach_disconnected,mediate_deleted) {
  allow file rwlkm /{**,},
  allow pix /** -> &unpriv_bwrap,
  audit deny capability,
  include if exists <local/unpriv_bwrap>
}
'''


class RunnerProfile(unittest.TestCase):
    def test_capability_is_scoped_to_the_private_runner_child(self):
        executable = Path('/home/runner/work/project/build/tools/bwrap')
        result = runner_setup.profile(TEMPLATE, executable)
        self.assertIn('profile werewolf_kernel_bwrap "' + str(executable.resolve()) + '"', result)
        child = result.split('profile werewolf_kernel_bwrap_child flags=', 1)[1]
        self.assertIn('allow capability sys_chroot,', child)
        self.assertNotIn('allow capability,', child)
        self.assertNotIn('unconfined', result)
        self.assertNotIn('local/', result)
        self.assertNotIn('/usr/bin/bwrap', result)
        self.assertIn('audit deny capability,', TEMPLATE)

    def test_new_child_capabilities_and_unknown_profiles_fail_closed(self):
        for template in (TEMPLATE.replace('audit deny capability,', 'allow capability,'),
                         TEMPLATE.replace('audit deny capability,',
                                          'audit deny capability,\nallow capability sys_admin,'),
                         TEMPLATE.replace('audit deny capability,', ''),
                         TEMPLATE.replace('profile bwrap', 'profile new_bwrap'),
                         TEMPLATE.replace('attach_disconnected', 'unconfined')):
            with self.subTest(template=template), self.assertRaises(ValueError):
                runner_setup.profile(template, Path('/build/tools/bwrap'))

    def test_attachment_rejects_policy_metacharacters(self):
        for path in ('/build/*/bwrap', '/build/{a,b}/bwrap', '/build/"/bwrap', '/build/space name/bwrap'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner_setup.profile(TEMPLATE, Path(path))


if __name__ == '__main__':
    unittest.main()
