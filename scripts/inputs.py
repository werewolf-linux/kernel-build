"""Identify the exact upstream and downstream build inputs."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / 'build/inputs'
LOCK = 'kernel.lock.json'
ARCHES = ('x86_64', 'aarch64')
# What reaches the packages' bytes: the recipe and what it reads (build.py's CONTEXT),
# the toolchain pins and the keys. Tests, workflows, the publisher and config/ARCH.config,
# make config's copy for review, do not, so editing them builds nothing; a change here
# builds a new kernel, which needs a new revision.
POLICY_INPUTS = ['linux.yaml', 'tools.lock.json', 'policy.json', 'config/common.cfg', 'config/x86_64.cfg',
                 'config/aarch64.cfg', 'config/deny.cfg', 'boot', 'release/ipe.crt', 'release/packages.pub',
                 'scripts/build.py', 'scripts/config.py']


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def policy_hashes(root=ROOT):
    files = []
    for name in POLICY_INPUTS:
        path = root / name
        files.extend(path.rglob('*') if path.is_dir() else [path])
    return {str(p.relative_to(root)): sha256(p) for p in sorted(files)
            if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}


def identity(lock):
    # The release date and signer are provenance; the bytes and our files are the build.
    relevant = {key: lock[key] for key in ['version', 'sha256', 'revision', 'policy_sha256']}
    return hashlib.sha256(json.dumps(relevant, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify(directory=INPUTS, root=ROOT):
    lock = json.loads((directory / LOCK).read_text())
    if lock['policy_sha256'] != policy_hashes(root):
        raise ValueError('Downstream policy changed; refresh the inputs')
    if lock['build_id'] != identity(lock):
        raise ValueError('Build identity mismatch')
    return lock
