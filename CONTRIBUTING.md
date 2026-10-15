# Contributing

Thanks for helping. This page gets you from a clone to a tested change.

## Set up

You need Python 3, OpenSSL, GnuPG and xz. To change a list you also need clang 22 or
later, `ld.lld` and GNU make 4 (`brew install llvm lld make` on macOS).

```sh
make refresh    # capture kernel.org's newest stable release of our series
make check      # both configs hold the lists; every unit test, in seconds
make config     # after editing config/*.cfg: derive both full configs again
make build      # build, sign and boot the kernel with Melange
```

## Change an option

1. Add or remove one line in `config/common.cfg` or `config/ARCH.cfg`, with a comment
   naming the form, hypervisor or attack that decides it.
2. `make config`. A line that does not hold names an option whose dependencies you
   must list too.
3. Read the diff of `config/ARCH.config`: it is everything your line implied.
4. `make refresh check verify`, then `make build` if you can.

An option that must never come back goes in `config/deny.cfg` as well.

## Style

- **Code, as Theo de Raadt would write it:** simple, reliable, efficient and secure. A
  script does one job, trusts nothing it has not verified, and fails closed.
- **Comments, as Rob Pike would write them:** concise, and only where the code can't say
  why.
- **Documentation, as Wietse Venema would write it:** clear and short. The README stays
  within 100 lines, on werewolf's [design doc template][template].

And in practice:

- No Python packages: the standard library, OpenSSL, GnuPG, tar and Melange.
- Every log line starts with the script's name.
- Keep lines within 120 columns in code and 88 in documentation; tables are exempt.

## Commits and pull requests

Commit subjects are `area: what changed`, in the imperative: `config: drop VSOCKETS`.
The body says why. CI builds and boots both architectures on every pull request.

## Security

Please don't open public issues for vulnerabilities; see werewolf's
[SECURITY.md](https://github.com/werewolf-linux/werewolf/blob/main/SECURITY.md).

[template]: https://github.com/werewolf-linux/werewolf/blob/main/docs/design/TEMPLATE.md
