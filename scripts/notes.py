"""Release notes for a linux-werewolf build: what changed upstream and here, and how it was proven.

gather() asks the network: the published release before this one, kernel.org's ChangeLogs,
the kernel CNA's CVE records and GitHub's commit comparison. Each that fails becomes a line
saying so, never a failed release: a security fix ships with thinner notes. render() is pure.
"""
import io
import json
import re
import subprocess
import tarfile
import urllib.request
from config import PROBE, values
from inputs import ARCHES
from refresh import SIGNERS

VULNS = 'https://git.kernel.org/pub/scm/linux/security/vulns.git/snapshot/vulns-master.tar.gz'
AGENT = 'kernel-build (+https://github.com/werewolf-linux/kernel-build)'
# A series change can turn on hundreds of options; the configs themselves are in the release.
LISTED = 60


def version(text):
    return tuple(int(part) for part in text.split('.'))


def series(text):
    return '.'.join(text.split('.')[:2])


def fetch(url, limit=64 << 20):
    # git.kernel.org refuses Python's own User-Agent.
    request = urllib.request.Request(url, headers={'User-Agent': AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(url + ' is larger than ' + str(limit) + ' bytes')
    return data


def base(current, previous):
    """The release the notes count from: the one published before, or this one's predecessor."""
    if previous and series(previous) == series(current) and version(previous) < version(current):
        return previous
    parts = version(current)
    return '.'.join(map(str, parts[:2] + (parts[2] - 1,))) if len(parts) == 3 and parts[2] > 1 else None


def changelogs(current, since):
    """(version, URL, commit count or None) for each point release after since, up to current."""
    if len(version(current)) < 3:
        return []
    major, minor, point = version(current)
    first = version(since)[2] + 1 if since else point
    found = []
    for number in range(first, point + 1):
        name = f'{major}.{minor}.{number}'
        url = f'https://cdn.kernel.org/pub/linux/kernel/v{major}.x/ChangeLog-{name}'
        try:
            count = sum(line.startswith(b'commit ') for line in fetch(url).splitlines())
        except (OSError, ValueError):
            count = None
        found.append((name, url, count))
    return found


def cves(current, since, archive=None):
    """(CVE, fixed in, title) the kernel CNA lists as fixed on current's branch after since."""
    branch, low, high = series(current), version(since) if since else (0,), version(current)
    data = archive if archive is not None else fetch(VULNS, 256 << 20)
    found = set()
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar:
            if not (member.isfile() and '/cve/published/' in member.name and member.name.endswith('.json')):
                continue
            record = json.load(tar.extractfile(member))
            cna = record['containers']['cna']
            for affected in cna.get('affected', []):
                for entry in affected.get('versions', []):
                    fixed = entry.get('version', '')
                    if entry.get('status') == 'unaffected' and entry.get('versionType') == 'semver' and \
                            entry.get('lessThanOrEqual') == branch + '.*' and \
                            re.fullmatch(re.escape(branch) + r'\.[0-9]+', fixed) and low < version(fixed) <= high:
                        found.add((record['cveMetadata']['cveId'], fixed, cna.get('title', '').strip()))
    return sorted(found, key=lambda item: (version(item[1]), item[0]))


def commits(repository, since_sha, sha):
    """(short hash, subject, URL) of this repository's commits after since_sha, oldest first."""
    reply = subprocess.run(['gh', 'api', f'repos/{repository}/compare/{since_sha}...{sha}'],
                           check=True, capture_output=True, text=True).stdout
    return [(c['sha'][:12], c['commit']['message'].splitlines()[0], c['html_url'])
            for c in json.loads(reply)['commits'] if len(c['parents']) == 1]


def config_changes(old, new):
    """Options on, changed and off in new compared with old, ignoring the toolchain's probes."""
    a, b = values(old), values(new)
    changed = sorted(s for s in a.keys() | b.keys() if a.get(s) != b.get(s) and not PROBE.fullmatch(s))
    return [(s, a.get(s), b.get(s)) for s in changed]


def previous_configs(public, build_id):
    """Each arch's full config from the previous release's snapshot."""
    found = {}
    for arch in ARCHES:
        data = fetch(f'{public}builds/{build_id}/linux-werewolf-{arch}.tar.gz')
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            found[arch] = tar.extractfile(arch + '.config').read().decode()
    return found


def attempt(function, *args):
    """function(*args), or the reason it failed, for a section that says so."""
    try:
        return function(*args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        return str(error).strip().splitlines()[-1] if str(error).strip() else type(error).__name__


def gather(lock, artifacts, files, public, repository, sha):
    """Everything render() needs; artifacts holds each arch's build as provenance.py records it."""
    current = attempt(lambda: json.loads(fetch(public + 'current.json')))
    previous = current if isinstance(current, dict) and current.get('build_id') != lock['build_id'] else None
    kernel = previous['version'].split('-r')[0] if previous else None
    # A new revision of the same Linux release changes only our side.
    same = kernel == lock['version']
    since = base(lock['version'], kernel)
    builds = {arch: artifacts / ('linux-werewolf-' + arch) for arch in ARCHES}
    return {
        'lock': lock, 'previous': previous, 'since': since, 'public': public, 'repository': repository,
        'sha': sha, 'files': files,
        'same': same,
        'changelogs': [] if same else changelogs(lock['version'], since),
        'cves': [] if same else attempt(cves, lock['version'], since),
        'commits': attempt(commits, repository, previous['source_sha'], sha) if previous else None,
        'configs': {arch: (builds[arch] / (arch + '.config')).read_text() for arch in ARCHES},
        'previous_configs': attempt(previous_configs, public, previous['build_id']) if previous else None,
        'probe': {arch: (builds[arch] / 'probe.log').read_text().splitlines() for arch in ARCHES},
        'runner': {arch: json.loads((builds[arch] / 'runner.json').read_text()) for arch in ARCHES},
        'tools': json.loads((builds[ARCHES[0]] / 'tools.lock.json').read_text()),
    }


def render(data):
    lock, previous, public = data['lock'], data['previous'], data['public']
    full = lock['version'] + '-r' + str(lock['revision'])
    snapshot = public + 'builds/' + lock['build_id'] + '/'
    out = [f'# linux-werewolf {full}', '',
           f'Linux {lock["version"]} from kernel.org\'s `{lock.get("moniker", "stable")}` series, released '
           f'{lock["released"]} and signed by {SIGNERS.get(lock["signer"], lock["signer"])}, built for werewolf '
           f'on {" and ".join(ARCHES)}. Both kernels booted the probe below before anything was published.', '']
    if previous:
        out += [f'Follows {previous["version"]}. Machines that follow `{public}` take it with their next update.', '']
    else:
        out += [f'The first build published to `{public}`.', '']

    out += ['## Upstream changes', '']
    if data['same']:
        out.append(f'None: the same Linux {lock["version"]} as {previous["version"]}; this revision changes '
                   'only werewolf\'s build.')
    elif not data['changelogs']:
        out += [f'Linux {lock["version"]} opens the {series(lock["version"])} series: '
                f'[kernelnewbies](https://kernelnewbies.org/Linux_{series(lock["version"]).replace(".", "_")}).']
    for name, url, count in data['changelogs']:
        out.append(f'- [{name}]({url})' + (f': {count} commits' if count is not None else ''))
    out.append('')

    out += ['## Security fixes', '']
    found = data['cves']
    if data['same']:
        out.append(f'None beyond those {previous["version"]} carried.')
    elif isinstance(found, str):
        out.append(f'The kernel CNA\'s records were unavailable: {found}.')
    elif not found:
        out.append('The kernel CNA lists no CVE fixed in these releases yet.')
    else:
        out += ['| CVE | Fixed in | Title |', '| --- | --- | --- |']
        out += [f'| [{cve}](https://www.cve.org/CVERecord?id={cve}) | {fixed} | {title.replace("|", "/")} |'
                for cve, fixed, title in found]
    out += ['', 'As the kernel CNA\'s records stood at publication; it assigns CVEs days to weeks after a '
            'fix, and some name code werewolf\'s kernel does not build.', '']

    if previous:
        out += ['## Changes in kernel-build', '']
        found = data['commits']
        if isinstance(found, str):
            out.append(f'The commit comparison was unavailable: {found}.')
        elif not found:
            out.append('None: the same lists, toolchain and recipe.')
        else:
            out += [f'- [`{short}`]({url}) {subject}' for short, subject, url in found]
        out.append('')

        out += ['## Configuration changes', '']
        old = data['previous_configs']
        if isinstance(old, str):
            out += [f'The previous configs were unavailable: {old}.', '']
        else:
            for arch in ARCHES:
                changes = config_changes(old[arch], data['configs'][arch])
                if not changes:
                    out += [f'{arch}: none.', '']
                    continue
                out += [f'{arch}: {len(changes)} option{"" if len(changes) == 1 else "s"}.', '']
                out += [f'- `{s}`: {a or "off"} → {b or "off"}' for s, a, b in changes[:LISTED]]
                if len(changes) > LISTED:
                    out.append(f'- and {len(changes) - LISTED} more; each arch\'s full config is in its tarball')
                out.append('')

    out += ['## Proof', '']
    for arch in ARCHES:
        verdict = data['probe'][arch][-1] if data['probe'][arch] else 'probe: no record'
        out.append(f'<details><summary>{arch}: {verdict.removeprefix("probe: ")} '
                   f'({data["runner"][arch]["runner"]})</summary>')
        out += ['', '```', *data['probe'][arch], '```', '', '</details>', '']
    tools = data['tools']
    out += [f'Built from [`{data["sha"][:12]}`](https://github.com/{data["repository"]}/commit/{data["sha"]}) '
            f'with Melange {tools["melange"]["version"]} and Wolfi\'s ' +
            ', '.join(f'`{name}` {pin}' for name, pin in sorted(tools['toolchain'].items())) +
            f'; policy revision {lock["revision"]}; build `{lock["build_id"]}`.', '']

    out += ['## Files', '', f'Snapshot: `{snapshot}`. Every APK is signed by werewolf\'s package key, '
            '`release/packages.pub`.', '', '| File | Bytes | SHA-256 |', '| --- | ---: | --- |']
    out += [f'| `{name}` | {size} | `{digest}` |' for name, size, digest in data['files']]
    return '\n'.join(out) + '\n'


def write(path, lock, artifacts, files, public, repository, sha):
    path.write_text(render(gather(lock, artifacts, files, public, repository, sha)))
