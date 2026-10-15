# linux-werewolf

## Summary

The kernel werewolf virtual machines boot: kernel.org's newest `stable` release, built
with exactly the options in [config/](config/) and nothing else, published as signed
APKs for x86_64 and aarch64 within hours of each release.

## Background

Alpine's `linux-virt` enables 2,572 options on x86_64; werewolf forms need under 40%
of them. [werewolf's design][design] explains the choices: no loadable modules, no
io_uring, BPF, netfilter, user namespaces or 32-bit ABIs; Clang 22 for kCFI; lockdown
and IPE from the first instruction; throughput tuned with PostgreSQL as the yardstick.

## Goals

- Every option that is on is named in a list, with the hypervisor or form that needs it.
- Every option nobody named is off, including those a new kernel series adds.
- Each build boots under QEMU and proves its promises before it is published.
- Releases follow kernel.org without a version kept in this tree.

## Non-Goals

- Hardware, Xen, VMware, accelerated-networking VFs or GPUs.
- Kernel patches beyond IPE's anonymous-memory rule, left to `PR_SET_MDWE`.

## Detailed design

| Path | What it holds |
| --- | --- |
| `config/common.cfg`, `config/ARCH.cfg` | every option on, grouped by who needs it |
| `config/deny.cfg` | options that must stay off whatever selects them |
| `config/ARCH.config` | the full config `make config` derives, for review; not an input |
| `linux.yaml` | the Melange recipe; `scripts/build.py` fills its `@` fields |
| `boot/probe.c` | the boot test: the only process of a QEMU boot |
| `release/` | kernel.org's signing keys, werewolf's APK and IPE certificates |

`make refresh` reads kernel.org's `releases.json`, takes the newest `stable` release, a
new series' as readily as a point release, verifies its signature against the committed
keys of Greg Kroah-Hartman and Linus Torvalds, and locks its SHA-256 with hashes of the
files that reach the packages in `build/inputs/kernel.lock.json`. `policy.json` names
the moniker (`stable` or `longterm`) and a revision, the package's `-rN`. A change to
those files builds a new kernel of the same version, which needs a new revision: the
stable repository keeps each version's first build, so CI refuses to build it again.

`make config` runs `allnoconfig` with the lists forced on, so nothing unnamed is on,
then fails unless every list line and `deny.cfg` hold. A line that does not hold names
an option whose dependencies must be listed too; so does a new series renaming one.
It needs clang 22 or later, `ld.lld` and GNU make 4 (`gmake` on macOS).
`make check` proves both committed configs still hold the lists, and runs the tests.

`make build` builds with the pinned Melange and Wolfi's pinned clang-22. The recipe
derives the config from the lists as `make config` does, for whatever release it builds,
so each option a new series adds starts off, and stops if a list line or `deny.cfg` no
longer holds. It packages `linux-werewolf` (`boot/vmlinuz-werewolf`, the config,
`kernel-package` and the IPE certificate) and `linux-werewolf-probe`, the probe as an
initramfs. The package test boots the kernel with the probe as PID 1 and requires a
`PASS` line: release `-werewolf`, no module loader, lockdown `confidentiality`, exactly
the LSMs werewolf names, Landlock ABI 10, no io_uring, BPF, kexec or user namespaces,
IPE enforcing and refusing any key but werewolf's.

On Linux with bubblewrap the build uses the runner werewolf CI uses. On macOS Melange
boots a guest kernel with 9p and overlayfs, which ours lacks. Melange's
`QEMU_KERNEL_IMAGE` and `QEMU_BASE_INITRAMFS` name it; werewolf's howl makes one from
Alpine's linux-virt for any Melange build on macOS:

    QEMU_KERNEL_IMAGE=../werewolf/build/vendor/melange-guest-aarch64.vmlinuz \
    QEMU_BASE_INITRAMFS=../werewolf/build/vendor/melange-guest-aarch64.cpio make build

`IPE_CRT=test.crt make build` builds a test kernel whose IPE trusts `test.crt` in place
of `release/ipe.crt`; werewolf's `tools/test-kernel` builds its IPE tests' kernels so.
`scripts/publish.py` refuses a test kernel.

GitHub Actions checks kernel.org hourly. A release whose inputs are unpublished builds
natively on x86_64 and aarch64; both must boot the probe before
[scripts/publish.py](scripts/publish.py) stages a draft release, then publishes to R2
`apk/kernel/`: an immutable snapshot `builds/<input-hash>/` and the stable repository
`https://dist.werewolf-linux.org/apk/kernel` machines follow. The GitHub release carries
each APK too, as `NAME-VERSION.ARCH.apk`, the same bytes R2 serves. Every published APK
is kept; only the index is re-signed, after the previous one verifies. The release key
is werewolf's `WEREWOLF_PACKAGES_KEY`; `release/packages.pub` must match it. Each
release's notes, the GitHub release's body and `NOTES.md` in its snapshot, list the
upstream ChangeLogs, the CVEs the kernel CNA says it fixes, our commits and config
changes since the last release, and both probe transcripts
([scripts/notes.py](scripts/notes.py)).

## Drawbacks

A new series, every nine to ten weeks, ships before anyone reviews it: only what the
lists name is on, and its notes list every option that changed, but a series that
renames an option we list stops releases until the list follows. A driver or protocol a
form newly needs waits for a list line and a release.

## Alternatives Considered

- Merging the lists over Alpine's config: what is on would be Alpine's defaults plus
  `olddefconfig`'s choices, readable only by diffing.
- Modules for rarely needed drivers: a loader, signing and policy for 2 MB of text.
- GCC: no kCFI before GCC 17.

## Security Considerations

kernel.org's tarball is trusted only after a committed signer's signature verifies;
the build fetches the same bytes by hash. The signing key reaches only the signing
step, never the build. Publication validates both native builds, every APK signature
and payload hash, and the recipe each was built from, before the first upload.
Nothing published is replaced.

## Reliability Considerations

Drift fails closed: a list line a new release no longer honours, the deny list, or the
boot probe. A failed build leaves the previous release in place; a complete draft
lets publication resume without rebuilding. Machines keep the previous kernel.

[design]: https://github.com/werewolf-linux/werewolf/blob/main/docs/design/custom-kernel.md
