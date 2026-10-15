#!/usr/bin/env python3
"""Verify the captured inputs, the committed configs and the recipe before a build."""
import json
import re
from build import recipe
from config import misses
from inputs import ROOT, ARCHES, verify
from refresh import SIGNERS


def main():
    lock = verify()
    if not re.fullmatch(r'[0-9]+\.[0-9]+(\.[0-9]+)?', lock['version']) or \
            not re.fullmatch('[0-9a-f]{64}', lock['sha256']) or lock['signer'] not in SIGNERS:
        raise SystemExit('verify: malformed or unsigned kernel lock')
    tools = json.loads((ROOT / 'tools.lock.json').read_text())['toolchain']
    for arch in ARCHES:
        failed = misses(arch, (ROOT / 'config' / (arch + '.config')).read_text())
        if failed:
            raise SystemExit(f'verify: config/{arch}.config does not hold the lists; run make config:\n  ' +
                             '\n  '.join(failed))
        recipe(lock, tools, arch)
    print('verify: Linux', lock['version'], 'signed by', SIGNERS[lock['signer']] + ';',
          'both configs hold the lists; build', lock['build_id'])


if __name__ == '__main__':
    main()
