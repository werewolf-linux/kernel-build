#!/usr/bin/env python3
"""Build and test linux-werewolf with the pinned Melange, bubblewrap on Linux or QEMU elsewhere."""
import argparse
import functools
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import threading
from inputs import ROOT, sha256, verify

CONTEXT = ['config', 'boot', 'scripts', 'release/ipe.crt']


def recipe(lock, tools, arch):
    """linux.yaml with every @FIELD@ filled; refuses to leave one unfilled."""
    text = (ROOT / 'linux.yaml').read_text()
    fields = {'VERSION': lock['version'], 'MAJOR': lock['version'].split('.')[0],
              'REVISION': str(lock['revision']), 'SHA256': lock['sha256'], 'RELEASED': lock['released'],
              'ARCH': arch, 'CLANG': tools['clang-22'], 'LLD': tools['lld-22'], 'LLVM': tools['llvm-22']}
    for name, value in fields.items():
        # Values come from kernel.org and our pins; none may carry YAML or shell.
        if not re.fullmatch(r'[0-9A-Za-z._-]+', value):
            raise ValueError('build: refusing ' + name + ' value ' + repr(value))
        text = text.replace('@' + name + '@', value)
    left = re.findall(r'@[A-Z0-9_]+@', text)
    if left:
        raise ValueError('linux.yaml fields build.py does not fill: ' + ', '.join(left))
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', default=platform.machine())
    args = parser.parse_args()
    arch = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'x86_64': 'x86_64'}[args.arch]
    lock = verify()
    pins = json.loads((ROOT / 'tools.lock.json').read_text())
    melange = os.environ.get('MELANGE', 'melange')
    if 'v' + pins['melange']['version'] not in subprocess.check_output([melange, 'version'], text=True):
        raise SystemExit('build: install Melange v' + pins['melange']['version'] + ' with scripts/install-melange.py')
    build = ROOT / 'build'
    context, packages, scratch, empty = build / 'context', build / 'packages', build / 'runner', build / 'empty'
    shutil.rmtree(context, ignore_errors=True)
    for name in CONTEXT:
        source, target = ROOT / name, context / 'werewolf' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        (shutil.copytree if source.is_dir() else shutil.copyfile)(source, target)
    # A test kernel trusts a disposable certificate for IPE policies; the
    # publisher refuses any kernel that does not trust release/ipe.crt.
    if os.environ.get('IPE_CRT'):
        shutil.copyfile(os.environ['IPE_CRT'], context / 'werewolf/release/ipe.crt')
        print('build: test kernel: IPE trusts', os.environ['IPE_CRT'], 'not release/ipe.crt', flush=True)
    (build / 'linux.yaml').write_text(recipe(lock, pins['toolchain'], arch))
    for directory in (packages, scratch, empty):
        directory.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TMPDIR=str(scratch))
    runner = 'bubblewrap' if platform.system() == 'Linux' and shutil.which('bwrap') else 'qemu'
    record = {'runner': runner, 'arch': arch, 'melange_version': pins['melange']['version'],
              'ipe_cert_sha256': sha256(context / 'werewolf/release/ipe.crt')}
    if runner == 'qemu':
        # Melange's guest needs 9p and overlayfs, which our kernel leaves out.
        guest = [Path(env.get(name, '')) for name in ('QEMU_KERNEL_IMAGE', 'QEMU_BASE_INITRAMFS')]
        if not all(path.is_file() for path in guest):
            raise SystemExit('build: QEMU needs QEMU_KERNEL_IMAGE and QEMU_BASE_INITRAMFS; see README.md')
        record.update(guest_kernel_sha256=sha256(guest[0]), guest_initramfs_sha256=sha256(guest[1]))
        env['QEMU_DISKS_PATH'] = str(scratch)
        # Melange would put modules under the guest's /lib, over its loader's link.
        env.pop('QEMU_KERNEL_MODULES', None)
    common = ['--runner', runner, '--arch', arch, '--cpu', env.get('MELANGE_CPU', '4'),
              '--memory', env.get('MELANGE_MEMORY', '8Gi'), '--repository-append', 'https://packages.wolfi.dev/os',
              '--keyring-append', 'https://packages.wolfi.dev/os/wolfi-signing.rsa.pub']
    print('build: linux-werewolf', lock['version'], 'for', arch, 'with', runner, flush=True)
    subprocess.run([melange, 'build', str(build / 'linux.yaml'), '--source-dir', str(context),
                    '--namespace', 'werewolf', '--signing-key', str(build / 'keys/werewolf-packages.rsa'),
                    '--cache-dir', str(scratch / 'cache'), '--out-dir', str(packages), *common], check=True, env=env)
    # The test installs the signed packages just built. Melange resolves them on
    # this host for either runner, so the repository is on loopback.
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(packages))
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            subprocess.run([melange, 'test', str(build / 'linux.yaml'), '--source-dir', str(empty),
                            '--repository-append', f'http://127.0.0.1:{server.server_address[1]}',
                            '--keyring-append', str(build / 'keys/werewolf-packages.rsa.pub'), *common],
                           check=True, env=env)
        finally:
            server.shutdown()
    (packages / 'runner.json').write_text(json.dumps(record, indent=2) + '\n')
    print('build: linux-werewolf', lock['version'], 'built and passed its boot probe on', arch)


if __name__ == '__main__':
    main()
