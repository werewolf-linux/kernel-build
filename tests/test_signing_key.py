import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/signing-key.py'


class SigningKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pkcs8 = subprocess.check_output(
            ['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
            stderr=subprocess.DEVNULL)
        cls.pkcs1 = subprocess.check_output(
            ['openssl', 'rsa', '-traditional'], input=cls.pkcs8, stderr=subprocess.DEVNULL)
        cls.public = subprocess.check_output(
            ['openssl', 'rsa', '-pubout'], input=cls.pkcs8, stderr=subprocess.DEVNULL)

    def ingest(self, root, key, public=None):
        # A copy of the script finds its repository, this temporary one, from where it is.
        for name in ('release', 'scripts'):
            (root / name).mkdir()
        shutil.copy(SCRIPT, root / 'scripts')
        (root / 'release/packages.pub').write_bytes(self.public if public is None else public)
        env = os.environ.copy()
        env['KERNEL_APK_SIGNING_KEY'] = key.decode()
        return subprocess.run([sys.executable, str(root / 'scripts' / SCRIPT.name)], env=env,
                              capture_output=True)

    def test_both_formats_produce_the_same_restricted_pkcs1_key(self):
        for key in (self.pkcs8, self.pkcs1):
            with self.subTest(format=key.splitlines()[0]):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    result = self.ingest(root, key)
                    self.assertEqual(0, result.returncode, result.stderr)
                    target = root / 'build/keys/werewolf-packages.rsa'
                    self.assertEqual(self.pkcs1, target.read_bytes())
                    self.assertEqual(0o600, target.stat().st_mode & 0o777)
                    self.assertEqual(self.public, Path(str(target) + '.pub').read_bytes())
                    self.assertNotIn(key, result.stdout + result.stderr)

    def test_wrong_trust_root_is_rejected_even_with_python_optimization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(os.environ, {'PYTHONOPTIMIZE': '1'}):
                result = self.ingest(root, self.pkcs8, b'untrusted key\n')
            self.assertNotEqual(0, result.returncode)
            self.assertIn(b'does not match the Werewolf APK trust root', result.stderr)
            self.assertFalse((root / 'build/keys/werewolf-packages.rsa').exists())

    def test_invalid_key_is_rejected_without_logging_it(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = b'invalid-private-key-sentinel\n'
            result = self.ingest(Path(directory), secret)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn(secret, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
