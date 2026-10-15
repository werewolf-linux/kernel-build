from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/install-melange.py'


class MelangeInstall(unittest.TestCase):
    def test_transient_download_errors_retry_but_http_404_stops(self):
        code = '''import io
import json
import runpy
import sys
import urllib.error
from unittest.mock import patch
script, destination, status = sys.argv[1:]
status = int(status)
error = urllib.error.HTTPError('https://example.invalid', status, 'fixture', {}, None)
sys.argv = [script, '--dest', destination]
with patch('urllib.request.urlopen', side_effect=[error, io.BytesIO(b'untrusted archive')]) as fetch, \\
     patch('time.sleep') as sleep:
    try:
        runpy.run_path(script, run_name='__main__')
    finally:
        print(json.dumps({'fetches': fetch.call_count, 'sleeps': sleep.call_count}))
'''
        for status, calls, message in [('503', 2, 'pinned SHA-256'), ('404', 1, 'HTTP Error 404')]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / 'melange'
                result = subprocess.run([sys.executable, '-O', '-c', code, str(SCRIPT), str(destination), status],
                                        capture_output=True, text=True)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(message, result.stderr)
                self.assertIn('"fetches": ' + str(calls), result.stdout)
                self.assertIn('"sleeps": ' + str(calls - 1), result.stdout)
                self.assertFalse(destination.exists())

    def test_wrong_archive_is_rejected_even_with_python_optimization(self):
        code = '''import io
import runpy
import sys
from unittest.mock import patch
script, destination = sys.argv[1:]
sys.argv = [script, '--dest', destination]
with patch('urllib.request.urlopen', return_value=io.BytesIO(b'untrusted archive')):
    runpy.run_path(script, run_name='__main__')
'''
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'melange'
            result = subprocess.run([sys.executable, '-O', '-c', code, str(SCRIPT), str(destination)],
                                    capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('does not match its pinned SHA-256', result.stderr)
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
