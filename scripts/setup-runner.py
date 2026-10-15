#!/usr/bin/env python3
"""Give the CI bubblewrap copy only the extra child capability APK bootstrap needs."""
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROFILE = Path('/etc/apparmor.d/bwrap-userns-restrict')


def profile(template, executable):
    path = str(executable.resolve())
    if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', path):
        raise ValueError('Runner path must be a literal AppArmor attachment')
    marker = 'profile unpriv_bwrap flags='
    if template.count(marker) != 1:
        raise ValueError('Review changed Ubuntu bubblewrap child profile')
    child = template.split(marker, 1)[1]
    rules = '\n'.join(line.split('#', 1)[0] for line in child.splitlines())
    if re.search(r'\bcapability\b', rules.replace('audit deny capability,', '')):
        raise ValueError('Review unexpected child capability rules')
    replacements = [
        ('profile bwrap /usr/bin/bwrap', 'profile werewolf_kernel_bwrap "' + path + '"'),
        ('&bwrap//&unpriv_bwrap', '&werewolf_kernel_bwrap//&werewolf_kernel_bwrap_child'),
        (marker, 'profile werewolf_kernel_bwrap_child flags='),
        ('&unpriv_bwrap', '&werewolf_kernel_bwrap_child'),
        ('audit deny capability,', 'allow capability sys_chroot,'),
        ('include if exists <local/bwrap-userns-restrict>', ''),
        ('include if exists <local/unpriv_bwrap>', ''),
    ]
    for before, after in replacements:
        if template.count(before) != 1:
            raise ValueError('Review changed Ubuntu bubblewrap profile: ' + before)
        template = template.replace(before, after)
    if 'unconfined' in template:
        raise ValueError('Refusing an unconfined runner profile')
    return template


def main():
    if os.geteuid() != 0:
        raise ValueError('Load the CI runner profile as root')
    executable = ROOT / 'build/tools/bwrap'
    policy = profile(PROFILE.read_text(), executable)
    executable.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile('/usr/bin/bwrap', executable)
    executable.chmod(0o755)
    target = executable.with_suffix('.apparmor')
    target.write_text(policy)
    subprocess.run(['/usr/sbin/apparmor_parser', '--replace', str(target)], check=True, timeout=30)
    print('setup-runner: loaded a private bubblewrap profile with child sys_chroot')


if __name__ == '__main__':
    main()
