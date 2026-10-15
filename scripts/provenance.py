#!/usr/bin/env python3
"""Record a native build that passed its boot probe: inputs, configs and file hashes."""
import argparse
import json
import os
import shutil
from inputs import ROOT, INPUTS, LOCK, sha256, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['x86_64', 'aarch64'], required=True)
    args = parser.parse_args()
    lock = verify()
    packages = ROOT / 'build/packages'
    if not (packages / args.arch / 'APKINDEX.tar.gz').is_file():
        raise SystemExit('provenance: no signed package index for ' + args.arch)
    shutil.copyfile(INPUTS / LOCK, packages / LOCK)
    for name in ['tools.lock.json', 'policy.json', 'release/packages.pub', 'build/linux.yaml',
                 'config/common.cfg', 'config/deny.cfg', 'config/' + args.arch + '.cfg',
                 'config/' + args.arch + '.config']:
        shutil.copyfile(ROOT / name, packages / os.path.basename(name))
    shutil.copyfile(ROOT / 'build/keys/werewolf-packages.rsa.pub', packages / 'werewolf-packages.rsa.pub')
    record = {'build_id': lock['build_id'], 'arch': args.arch,
              'version': lock['version'] + '-r' + str(lock['revision']),
              'source_sha': os.environ['GITHUB_SHA'], 'run_id': os.environ['GITHUB_RUN_ID'],
              'sha256': {str(p.relative_to(packages)): sha256(p) for p in sorted(packages.rglob('*')) if p.is_file()}}
    (packages / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
    print('provenance: recorded', len(record['sha256']), 'files for', args.arch)


if __name__ == '__main__':
    main()
