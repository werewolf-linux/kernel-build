#!/usr/bin/env python3
"""Write the APK signing key for Melange, keeping it out of arguments, logs and the build context.

With KERNEL_APK_SIGNING_KEY set, it must be the key release/packages.pub trusts.
Without it, an ephemeral key signs packages no machine trusts.
"""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
key = ROOT / 'build/keys/werewolf-packages.rsa'
public = key.with_name(key.name + '.pub')
value = os.environ.pop('KERNEL_APK_SIGNING_KEY', '')
key.parent.mkdir(parents=True, exist_ok=True)
if value:
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        # Melange requires PKCS#1; OpenSSL 3 writes PKCS#8.
        subprocess.run(['openssl', 'rsa', '-traditional', '-passin', 'pass:'], input=value, text=True,
                       stdout=output, stderr=subprocess.PIPE, check=True)
    with public.open('wb') as output:
        subprocess.run(['openssl', 'rsa', '-in', str(key), '-pubout'], stdout=output,
                       stderr=subprocess.DEVNULL, check=True)
    if public.read_bytes() != (ROOT / 'release/packages.pub').read_bytes():
        key.unlink()
        raise SystemExit('signing-key: key does not match the Werewolf APK trust root, release/packages.pub')
    print('signing-key: wrote the release key')
elif key.is_file() and public.is_file():
    key.chmod(0o600)
    print('signing-key: using the existing key')
else:
    subprocess.run([os.environ.get('MELANGE', 'melange'), 'keygen', str(key)], check=True)
    key.chmod(0o600)
    print('signing-key: ephemeral key; its packages are not a release')
