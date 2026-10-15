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


def guest(build, scratch, melange, arch, env):
    """Melange's QEMU guest needs 9p and overlayfs, which our kernel leaves out:
    boot Werewolf's Alpine build kernel, its modules appended under usr/lib."""
    kernel, modules = build / 'vmlinuz', build / 'kernel/x/lib/modules'
    if not kernel.is_file() or not modules.is_dir():
        raise SystemExit(f'build: {build}: expected vmlinuz and kernel/x/lib/modules; set WEREWOLF_BUILD')
    base, image = scratch / ('base-' + arch + '.cpio'), scratch / ('guest-' + arch + '.cpio')
    subprocess.run([melange, 'initramfs', '--arch', arch, '--output', str(base)], check=True, env=env)
    names = ['lib/modules'] + [str(p.relative_to(modules.parent.parent)) for p in sorted(modules.rglob('*'))
                               if not p.is_symlink()]
    (scratch / 'modules.list').write_text('\n'.join(names) + '\n')
    with image.open('wb') as output:
        output.write(base.read_bytes())
        # Prefix usr/: replacing /lib would destroy the guest loader's symlink.
        subprocess.run(['bsdtar', '--format', 'newc', '--uid', '0', '--gid', '0', '--numeric-owner',
                        '-s', ',^lib/,usr/lib/,', '-cf', '-', '--no-recursion', '-T', str(scratch / 'modules.list')],
                       cwd=modules.parent.parent, stdout=output, check=True)
    base.unlink()
    env.update(QEMU_KERNEL_IMAGE=str(kernel), QEMU_BASE_INITRAMFS=str(image), QEMU_DISKS_PATH=str(scratch))
    env.pop('QEMU_KERNEL_MODULES', None)
    return {'guest_kernel_sha256': sha256(kernel), 'guest_initramfs_sha256': sha256(image)}


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
    (build / 'linux.yaml').write_text(recipe(lock, pins['toolchain'], arch))
    for directory in (packages, scratch, empty):
        directory.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TMPDIR=str(scratch))
    runner = 'bubblewrap' if platform.system() == 'Linux' and shutil.which('bwrap') else 'qemu'
    record = {'runner': runner, 'arch': arch, 'melange_version': pins['melange']['version']}
    if runner == 'qemu':
        record.update(guest(Path(os.environ.get('WEREWOLF_BUILD', 'unset')).resolve(), scratch, melange, arch, env))
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
