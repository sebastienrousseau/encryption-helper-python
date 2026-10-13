<!-- SPDX-License-Identifier: Apache-2.0 -->

# Development

Setup and day-to-day commands. For conventions and review expectations see
[CONTRIBUTING.md](./CONTRIBUTING.md); for design see
[ARCHITECTURE.md](./ARCHITECTURE.md).

## Setup

Requires Python 3.10+ and [Poetry](https://python-poetry.org/). With
[mise](https://mise.jdx.dev/) the toolchain is pinned for you:

```bash
mise install
make install
```

`make install` also installs the git hooks. One of them is
`detect-private-key`, which is the last thing between a stray test key and a
public commit.

## Commands

```bash
make check      # lint + types + tests + security. Everything CI runs
make test       # pytest with the 95% branch-coverage gate
make lint       # ruff check and format --check
make fmt        # apply formatting and safe fixes
make types      # mypy --strict
make security   # bandit
make fuzz       # 50k iterations, no fuzzing engine required
make bench      # indicative timings, not a gate
make examples   # run every example
make sbom       # CycloneDX SBOM
make verify     # full release-candidate gate in a clean environment
```

`make help` lists them all.

## Layout

```text
encryption_helper/     the package
  cli/                 the only layer that prints or configures logging
  errors.py            the exception hierarchy
  _io.py               permissions, atomicity, rollback
  keys/                generate, serialize, load, store, fingerprint
  crypto/              envelope (encryption), signing
tests/                 560 tests, 100% statement and branch coverage
benches/               dependency-free timings
fuzz/                  parser fuzz targets, plus Atheris entry points
examples/              runnable, executed by CI
scripts/               release audit tooling
```

## Test layout

| File | Covers |
| ---- | ------ |
| `tests/keys/`, `tests/crypto/` | Unit behaviour per module |
| `tests/test_cli*.py` | The command surface, including subprocess tests |
| `tests/test_security_regressions.py` | Secret-leakage invariants, at every log level |
| `tests/test_release_candidate.py` | Failure injection at every write stage, aliasing, passphrase semantics |
| `tests/test_documentation_accuracy.py` | The README against the implementation |

Two rules that matter more than coverage:

1. **Never mock the code under test.** Mocks inject failures — an `OSError`
   from a syscall — they do not replace the thing being asserted on. Version
   0.0.1 shipped a completely broken write path beneath a 97% coverage figure
   because its tests mocked the broken function out.
2. **Security properties need a negative test.** Tampering must be *rejected*,
   not merely round-trip correctly.

## Verifying a release candidate

```bash
./scripts/verify-release-candidate.sh --expect <sha>
```

Records provenance, refuses a dirty tree, builds from a pristine `git archive`
of that exact commit, installs only the wheel into a fresh virtualenv, and
asserts the package under test is that wheel rather than the working tree.

```bash
./scripts/compare_wheel_payload.py <ref-a> <ref-b>
```

Proves two commits ship byte-identical executable code.

## Gotchas

- **Never leave an editable install pointing elsewhere.** It silently makes a
  green test run meaningless. The verification script asserts against this
  because it has happened.
- Scratch space defaults to `build/`, not `$TMPDIR` — `/tmp` is a small tmpfs
  on many systems. Override with `RC_WORKDIR`.
- The audit scripts locate the repository from their own path, not the working
  directory, and refuse to run outside it.
