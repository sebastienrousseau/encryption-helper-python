# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — Unreleased

This release is a rewrite. It fixes vulnerabilities that exposed private key
material in 0.0.1, and replaces the public API.

> [!WARNING]
> **Rotate every key generated with 0.0.1.** See
> [SECURITY-ADVISORY-0001](./docs/SECURITY-ADVISORY-0001.md).

### Security

- **Private keys are no longer world-readable.** They are created with `O_EXCL`
  at mode `0600` inside a `0700` directory, independent of the process umask.
  0.0.1 used a plain `open()`, producing mode `0644`.
- **Private keys are no longer printed to stdout or written to the debug log.**
  0.0.1 did both on every run, placing key material in terminal scrollback, CI
  job logs and any log-shipping pipeline. The CLI now reports the file path and
  a SHA-256 fingerprint instead.
- **Private keys can be encrypted at rest** with a passphrase supplied via
  `--passphrase-env` or `--passphrase-file`. A passphrase is never accepted as a
  command-line value, because `argv` is world-readable through `/proc`.
- **Existing keys are no longer silently destroyed.** Overwriting requires
  `--force`, and the previous key is backed up to a timestamped `0600` sibling.
- **Writes are atomic**, so an interrupted run cannot leave a truncated key.
- **Writing through a symbolic link is refused.**
- Error messages never contain key material, passphrases, or plaintext, and do
  not distinguish a wrong passphrase from a corrupt file.

### Added

- Hybrid encryption (`encrypt` / `decrypt`): AES-256-GCM under a random content
  key wrapped with RSA-OAEP-SHA256, in a versioned, authenticated container.
  Data of any size can be encrypted.
- Signing and verification (`sign` / `verify` / `is_valid_signature`) over
  RSA-PSS, Ed25519 and ECDSA.
- Ed25519 and ECDSA (P-256, P-384, P-521) key generation.
- Key loading with PEM/DER/OpenSSH auto-detection.
- OpenSSH-compatible SHA-256 fingerprints, cross-validated against
  `ssh-keygen -lf` in the test suite.
- Format conversion between PEM, DER and OpenSSH.
- A real command-line interface: `keygen`, `encrypt`, `decrypt`, `sign`,
  `verify`, `fingerprint`, `convert`, with `--version`, `--json`, verbosity
  flags and documented exit codes. 0.0.1 accepted no arguments at all.
- A typed exception hierarchy rooted at `EncryptionHelperError`.
- `py.typed`, so downstream consumers receive type information.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`, `SUPPORT.md`, issue
  and pull request templates.

### Changed

- **Breaking:** `generate_rsa_key()` is removed. Use `generate_rsa()`, which
  returns a key object and performs no I/O, printing or logging. Serialising
  and writing are separate, explicit steps (`encode_private_key`,
  `write_key_pair`).
- **Breaking:** the `Context` singleton is removed. The library now uses a
  standard module logger with a `NullHandler` and configures nothing; the host
  application owns logging configuration.
- **Breaking:** keys are no longer written to a hardcoded `keys/pem/` directory
  relative to the process working directory. Use `--out-dir`.
- Default RSA key size raised from 2048 to 3072 bits. Sizes below 2048 are
  rejected.
- Minimum Python raised to 3.10; 3.8 and 3.9 are end-of-life. Tested on 3.10
  through 3.14, across Linux, macOS and Windows.
- Packaging migrated to PEP 621. The version is declared in exactly one place
  and read via `importlib.metadata`; it was previously duplicated across
  `__init__.py`, `pyproject.toml` and `setup.py`.
- `SECURITY.md` replaced — it was the unedited GitHub template, claiming
  supported versions `5.1.x` and `4.0.x` for a `0.0.1` project.
- README corrected: it documented the private key format as PKCS#1, but the
  code emits, and always emitted, PKCS#8.

### Removed

- `encryption_helper.utils.io`, `encryption_helper.utils.checks` and
  `encryption_helper.common.strings`. None were used by the package.
  `write_text_in_binary_mode()` was also **unconditionally broken**: its
  validator rejected any non-`str` argument, so every call with the documented
  `bytes` payload raised `Exception("One or more arguments are empty")`. The
  test suite could not detect this because it mocked the validator out.
- `setup.py` — it duplicated and contradicted `pyproject.toml`.
- `requirements.txt` — a hand-maintained export that could drift from the lock
  file CI installed from.
- The committed `keys/` directory, which encouraged storing real private keys
  inside a git working tree.

### Fixed

- `public_key_suffix` was `"public_key.pem"` while the code wrote
  `"public-key.pem"`, and a test asserted the wrong one.
- Log calls no longer use eager f-string interpolation.
- Generic `raise Exception(...)` and `except Exception` replaced with typed
  errors.

### Internal

- Test suite rewritten: 250+ tests, 98% branch coverage, gated at 95% in CI.
  Mocks are used only to inject failures, never to replace the code under test.
  Adds property-based tests, tamper tests, real-filesystem permission
  assertions, and subprocess tests of the installed console script.
- `.pylintrc` (which began with `disable=all`, making the reported 10.00/10
  score meaningless) and `.flake8` (which ignored `F401`/`F403` and excluded
  tests) replaced with a single Ruff configuration applied to source and tests
  alike.
- `mypy --strict` passes with no ignores.
- CI consolidated into one hardened pipeline: least-privilege tokens, all
  actions pinned to commit SHAs, concurrency cancellation, job timeouts, and a
  15-way OS/Python test matrix. Bandit — configured but never executed by any
  workflow in 0.0.1 — now runs and blocks on findings. CodeQL, dependency
  review, `pip-audit` and OpenSSF Scorecard added.
- Release workflow publishes to PyPI via Trusted Publishing with build
  provenance attestation.

## [0.0.1] — 2024-07-27

### Added

- Initial release: RSA-2048 key pair generation to `keys/pem/`.

> [!CAUTION]
> This version is withdrawn. It exposed private key material. See
> [SECURITY-ADVISORY-0001](./docs/SECURITY-ADVISORY-0001.md).

[Unreleased]: https://github.com/hsbc/encryption-helper-python/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hsbc/encryption-helper-python/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/hsbc/encryption-helper-python/releases/tag/v0.0.1
