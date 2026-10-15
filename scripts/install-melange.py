#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser(description='Install the hash-pinned native Melange binary')
parser.add_argument('--dest', type=Path, default=Path('/usr/local/bin/melange'))
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
config = json.loads((root/'tools.lock.json').read_text())['melange']
arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
system = {'Linux': 'linux', 'Darwin': 'darwin'}[platform.system()]
filename = f"melange_{config['version']}_{system}_{arch}.tar.gz"
url = f"https://github.com/chainguard-dev/melange/releases/download/v{config['version']}/{filename}"
with tempfile.TemporaryDirectory() as directory:
    archive = Path(directory)/filename
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read()
            break
        except urllib.error.URLError as error:
            if isinstance(error, urllib.error.HTTPError) and error.code not in (429, 500, 502, 503, 504):
                raise
            if attempt == 2:
                raise
            print('install-melange: download failed; retrying', flush=True)
            time.sleep((5, 15)[attempt])
    if hashlib.sha256(data).hexdigest() != config[system+'_'+arch]:
        raise ValueError('Melange archive does not match its pinned SHA-256')
    archive.write_bytes(data)
    member = f"melange_{config['version']}_{system}_{arch}/melange"
    subprocess.run(['tar', '-xzf', str(archive), '-C', directory, '--strip-components=1', member], check=True)
    args.dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['install', '-m', '755', str(Path(directory)/'melange'), str(args.dest)], check=True)
