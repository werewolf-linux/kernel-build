#!/usr/bin/env python3
"""Make each full kernel config from our explicit option list, and prove it holds.

generate: allnoconfig with config/common.cfg and config/ARCH.cfg forced on, so an
          option nobody named is off; writes config/ARCH.config, for review. The build
          derives its own the same way, for the release it builds (linux.yaml).
check:    a config holds every listed option and nothing in config/deny.cfg.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
KERNEL_ARCH = {'x86_64': 'x86', 'aarch64': 'arm64'}
SET = re.compile(r'(CONFIG_[A-Z0-9_]+)=(.+)')
UNSET = re.compile(r'# (CONFIG_[A-Z0-9_]+) is not set')
# What kconfig learned by running the build host's tools, not what we chose.
PROBE = re.compile(r'CONFIG_(CC_VERSION_TEXT|CC_MS_EXTENSIONS|(CC|AS|LD)_IS_[A-Z]+|'
                   r'(GCC|CLANG|LD|LLD|AS|PAHOLE)_VERSION|RUSTC_[A-Z0-9_]+|'
                   r'(CC|AS|LD)_(HAS|CAN)_[A-Z0-9_]+|TOOLS_SUPPORT_[A-Z0-9_]+|OPENSSL_SUPPORTS_[A-Z0-9_]+)$')


def options(path):
    """The lines of a list as {symbol: value}; None means not set."""
    found = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line or line.startswith('#') and not UNSET.fullmatch(line):
            continue
        match = SET.fullmatch(line) or UNSET.fullmatch(line)
        if not match:
            raise ValueError(f'{path.name}:{number}: not an option line: {line}')
        if match[1] in found:
            raise ValueError(f'{path.name}:{number}: {match[1]} listed twice')
        found[match[1]] = match[2] if match.re is SET else None
    return found


def policy(arch):
    """Every line config/common.cfg and config/ARCH.cfg name, merged."""
    common, own = options(ROOT / 'config/common.cfg'), options(ROOT / 'config' / (arch + '.cfg'))
    both = common.keys() & own.keys()
    if both:
        raise ValueError('listed in common.cfg and ' + arch + '.cfg: ' + ', '.join(sorted(both)))
    return common | own


def values(text):
    return {m[1]: m[2] for m in map(SET.fullmatch, text.splitlines()) if m}


def misses(arch, text):
    """What a config does that the policy forbids, one line each."""
    actual = values(text)
    wanted = policy(arch) | options(ROOT / 'config/deny.cfg')
    return [f'{symbol}={actual.get(symbol, "n")}, listed {value or "n"}'
            for symbol, value in sorted(wanted.items()) if actual.get(symbol) != value]


def generate(arch, source, make):
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        allconfig = work / 'allconfig'
        allconfig.write_text((ROOT / 'config/common.cfg').read_text() +
                             (ROOT / 'config' / (arch + '.cfg')).read_text())
        subprocess.run([make, '-s', '-C', str(source), 'O=' + str(work), 'ARCH=' + KERNEL_ARCH[arch],
                        'LLVM=1', 'KCONFIG_ALLCONFIG=' + str(allconfig), 'allnoconfig'], check=True)
        text = (work / '.config').read_text()
    failed = misses(arch, text)
    if failed:
        raise SystemExit(f'config: {arch}: {len(failed)} lines did not hold; add what they depend on:\n  ' +
                         '\n  '.join(failed))
    (ROOT / 'config' / (arch + '.config')).write_text(text)
    listed = policy(arch)
    implied = [s for s in values(text) if s not in listed]
    print(f'config: {arch}: wrote config/{arch}.config: {len(listed)} listed, {len(implied)} implied by them')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['generate', 'check'])
    parser.add_argument('--arch', choices=KERNEL_ARCH, required=True)
    parser.add_argument('--source', type=Path, help='kernel source tree, for generate')
    parser.add_argument('--make', default='make', help='GNU make 4 or later')
    parser.add_argument('config', type=Path, nargs='?', help='config to check')
    args = parser.parse_args()
    committed = ROOT / 'config' / (args.arch + '.config')
    if args.command == 'generate':
        if not args.source:
            parser.error('generate needs --source')
        generate(args.arch, args.source, args.make)
        return
    config = args.config or committed
    failed = misses(args.arch, config.read_text())
    if failed:
        raise SystemExit(f'config: {config}: {len(failed)} lines do not hold:\n  ' + '\n  '.join(failed))
    print(f'config: {config} holds all {len(policy(args.arch))} listed options and config/deny.cfg')


if __name__ == '__main__':
    main()
