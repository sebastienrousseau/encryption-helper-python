# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Segmented (streaming) encryption**, `aead_id` 2. Encryption previously
  held the whole payload in memory at roughly four times its size, so a 5 GB
  file was impossible and the CLI refused anything over 64 MiB. Memory is now
  bounded by the segment size: measured flat at ~30 MB from 5 MB to 5 GB,
  sustaining ~1.5 GB/s.

  The framing is **Tink's STREAM**, not a new construction: a 12-byte nonce
  of 7-byte random prefix, 4-byte segment counter and 1-byte final flag.
  Together these prevent nonce reuse, reordering, segment dropping and
  truncation. Truncation resistance is the property naive chunked AEADs lose,
  and it is tested explicitly along with reordering, duplication and
  single-byte tampering.

  `encrypt_stream()` and `decrypt_stream()` are the library API. The CLI
  streams by default and reads either mode, dispatching on the header, so a
  one-shot container produced by `encrypt()` still decrypts.
- `--segment-size` to tune the segment, bounded to 4 KiB..64 MiB.
- `--progress`, reporting bytes, percentage, rate and ETA on stderr while
  streaming. Throttled to five updates a second: at 1.5 GB/s with 256 KiB
  segments there are roughly 6,000 callbacks a second, and printing each
  would cost more than the encryption. Measured overhead is nil. The total is
  omitted when reading from a pipe rather than guessed, and `--quiet`
  suppresses it. The library takes a callback and never prints, so `cli.py`
  remains the only module that writes to a terminal.
- The CLI commits streamed output atomically: it writes to a temporary file in
  the destination directory and renames on success, so a failed decryption
  never leaves a partial plaintext.

- **Post-quantum cryptography.** ML-KEM-768 and ML-KEM-1024 (FIPS 203) for
  encryption, ML-DSA-44/65/87 (FIPS 204) for signing. NIST IR 8547 deprecates
  RSA and the elliptic curves from 2030 and disallows them from 2035; every
  algorithm this package previously offered was on that list. No new
  dependency was needed -- both are in `cryptography` 46+.
- **X25519** ephemeral-static encryption, as `age` and HPKE do, and **Ed448**
  signing.
- Three new container mechanisms alongside RSA-OAEP: `kem_id` 2 (ML-KEM-768),
  3 (ML-KEM-1024) and 4 (X25519+HKDF-SHA256). The header already carried a
  mechanism byte and rejected unknown values, so this is additive --
  `kem_id` 1 containers still decrypt. The identifier is mixed into the HKDF
  `info`, so one shared secret cannot derive the same content key under two
  labels.
- `encryption-helper capabilities` reporting every algorithm, whether it can
  encrypt or sign, and its NIST IR 8547 horizon. `--json` gives the same for a
  cryptographic inventory.
- A notice at generation time when a quantum-vulnerable algorithm is chosen,
  naming the dates and the post-quantum alternative. A notice, not a refusal:
  RSA and the curves remain correct and widely interoperable.
- `--level` for ML-KEM and ML-DSA parameter sets.
- `--max-size` on the data commands, defaulting to 64 MiB. Encryption is not
  streamed and peak memory is roughly four times the payload, so oversized
  input is refused rather than risking an out-of-memory kill mid-write.
- CycloneDX SBOM generation in CI and attached to releases. This was listed in
  the original plan and in a commit message, and had never been implemented.
- `ARCHITECTURE.md`, `DEVELOPMENT.md`, `ROADMAP.md`, `RELEASING.md`,
  `GOVERNANCE.md`, `MAINTAINERS.md`, `CITATION.cff`, `Makefile`, `.mise.toml`,
  `MANIFEST.in` and markdown linting.

### Changed

- `__version__` is resolved lazily on first access. `importlib.metadata` costs
  ~9.5 ms per process to import and was paid by every caller whether or not
  they asked for the version.
- `--max-size` now applies only where input must be buffered -- reading a
  one-shot container, or from a pipe. File streaming is unbounded.
- README restyled, with a contents index, badge strip and operational
  sections.
- Fingerprints for ML-KEM, ML-DSA, X25519 and Ed448 are taken over DER
  SubjectPublicKeyInfo under a distinct `SHA256-SPKI:` prefix, because those
  key types have no OpenSSH encoding. RSA, Ed25519 and ECDSA still match
  `ssh-keygen -lf` byte for byte. The prefixes differ deliberately: digests
  over different encodings must never look comparable.
- Error classification is now principled. A key that can never decrypt
  (Ed25519, Ed448, ECDSA, ML-DSA) raises `InvalidArgumentError` -- a
  programming mistake. A key that could decrypt but does not match the
  container raises `DecryptionError`, because that is indistinguishable from a
  tampered header.
- `cryptography` is pinned to `>=46.0.0,<51.0.0`. The previous unbounded
  `>=43.0.0` spanned two years of releases, including ones with known CVEs,
  and predated ML-KEM.
- Post-quantum key sizes are reported as "Parameter set", not "Key size":
  calling ML-KEM-768 "768 bits" would simply be wrong.

### Fixed

- `--out /dev/null` failed with "already exists", and the atomic-commit path
  would have renamed a temporary file over the device node. Character
  devices, fifos and sockets are now written through directly, with no
  existence guard and no rename. Found while testing `--progress` against a
  discarded output.
- `--json` with `--out -` interleaved a JSON report and binary output on one
  stream, leaving neither parseable. The report now moves to stderr when
  stdout carries the command's output. Previously documented as a known issue.

### Deliberately not done

- **Hybrid X25519+ML-KEM.** A composite KEM needs a composite key container,
  and inventing one without external cryptographic review would be exactly the
  false confidence this work is meant to avoid. ML-KEM alone is FIPS-approved
  and satisfies the horizon. Tracked in `ROADMAP.md`.
- **Streaming encryption.** The chunked-AEAD design is specified in
  `ROADMAP.md`; frame counters and truncation resistance are where such
  designs fail, so it needs test vectors and review rather than a quick
  implementation. `--max-size` is the interim guard.

- `examples/` -- four runnable, CI-executed examples covering key generation
  and storage, hybrid encryption, signing, and loading and format conversion.
- `benches/bench_crypto.py` -- dependency-free benchmarks for generation,
  encryption, signing, serialisation and storage. Indicative timings, not a
  regression gate.
- `fuzz/` -- fuzz targets for `decrypt()` and the key loaders, with a
  standalone runner needing no fuzzing engine plus optional Atheris entry
  points. Both harnesses were themselves mutation-tested: planting a defect is
  detected within two iterations, with a reproducible seed.
- `scripts/compare_wheel_payload.py` -- release-audit tooling that proves two
  commits ship byte-identical executable code, by building both from pristine
  `git archive` exports and comparing every wheel member under
  `encryption_helper/`. Turns the one-time candidate-isolation check into
  reproducible evidence. Deliberately not part of normal CI.
- `scripts/verify-release-candidate.sh --expect <sha>` -- refuses to produce a
  provenance record for a commit other than the one named, so a record cannot
  silently describe the wrong commit after a merge.
- `tests/test_documentation_accuracy.py` -- asserts the README matches the
  implementation: every documented flag and subcommand exists, exit codes and
  error tables match the code, the stated key sizes and curves are accepted,
  cryptographic claims match the constructions used, licence declarations
  agree, and every relative link resolves.

### Changed

- Test coverage is now 100% of statements and branches, gated at 95%.

### Fixed

- README documented `KeyWriteError` and `KeyReadError` in a single combined
  table row, so neither was individually described.


## [0.0.2] — Unreleased

This release is a rewrite. It hardens how private keys are stored and handled,
replaces the public API, and adds encryption, signing, format conversion and a
real command-line interface.

0.0.1 printed and logged generated keys by design, which is reasonable for
interactive local use. The defaults below are stricter, so the same tool is
safe to use on shared machines and in CI without changing how you call it.

### Security hardening

- **Private keys are written owner-only.** They are created with `O_EXCL` at
  mode `0600` inside a `0700` directory, independent of the process umask.
  0.0.1 used a plain `open()`, which honours the umask and so typically
  produced `0644` — readable by other local accounts. `0600` matches what
  `ssh-keygen` does.
- **Key material is no longer printed or logged by default.** 0.0.1 printed
  both keys to the console and logged them at DEBUG, both documented features.
  That suits interactive use, but it also puts key material into terminal
  scrollback, CI job logs and log-shipping pipelines. The CLI now reports the
  file path and a SHA-256 fingerprint; pass `--show-public` for the public key
  on stdout.
- **Private keys can be encrypted at rest** with a passphrase supplied via
  `--passphrase-env` or `--passphrase-file`. A passphrase is never accepted as a
  command-line value, because `argv` is world-readable through `/proc`.
- **Existing keys are no longer silently destroyed.** Overwriting requires
  `--force`, and the previous key is backed up to a timestamped `0600` sibling.
- **Writes are atomic**, so an interrupted run cannot leave a truncated key.
- **Writing through a symbolic link is refused.**
- Error messages never contain key material, passphrases, or plaintext, and do
  not distinguish a wrong passphrase from a corrupt file.
- **An unencrypted private key is no longer the default.** A passphrase is
  prompted for without echo when a terminal is present; otherwise the run fails
  unless `--passphrase-env`, `--passphrase-file` or an explicit
  `--no-passphrase` is given.
- **Key pairs are validated before they are written.** The serialised halves are
  parsed back and compared, so a mismatched pair cannot reach the disk.
- **A partial write is rolled back.** If the public key cannot be written, the
  private key just written is removed, or restored from its backup. A private
  key whose public counterpart is missing or stale never survives.
- Both destinations are checked before anything is written, so the common
  "file already exists" conflict is caught before any file is touched.
- `~` in `--out-dir` is expanded and relative paths are resolved. Previously
  `--out-dir ~/keys` created a directory literally named `~`.
- Unexpected exception text is logged rather than printed, so it cannot spill
  paths or values into a terminal.
- The user is warned when key material is about to be written inside a git
  working tree.
- **A write that fails after backing up its target now restores the backup.**
  Previously a failed replacement renamed the old file aside and left nothing
  at the destination: the bytes survived, but the pair was incomplete. The
  original permission bits are restored too, not just the contents.
- Destination aliasing is rejected: a symlinked destination, a hard-linked
  private/public pair, and a private key path with more than one hard link
  (where the old key would stay readable under the other name).
- `--passphrase-env` rejects a whitespace-only value, matching the interactive
  prompt, and never echoes a rejected value.
- `--passphrase-file` has pinned semantics: exactly one trailing newline is
  removed and nothing else, so a passphrase may begin or end with a space or
  contain internal newlines.
- Custody warnings moved to stderr, so they survive stdout being redirected or
  parsed as JSON, while `--quiet` still silences them for automation.
- **`--passphrase-env`, `--passphrase-file` and `--no-passphrase` are mutually
  exclusive at the parser level.** Previously `--no-passphrase
  --passphrase-file secret.txt` was accepted, silently discarded the supplied
  passphrase, and wrote an **unencrypted** key.
- `--passphrase-file` is capped at 64 KiB, checked before the file is read, so
  pointing it at a log or a disk image fails as the mistake it is rather than
  consuming memory.
- All three passphrase sources converge on a single conversion point. Text
  sources are UTF-8 encoded there; a file stays byte-exact, so a non-UTF-8
  secret works and no decode step exists to raise `UnicodeDecodeError`.
- A group- or world-readable passphrase file produces a warning on POSIX. It is
  deliberately not a refusal, and is skipped on Windows rather than pretending
  Unix mode bits describe an ACL.
- The resolved passphrase is never written back to the argparse namespace, so
  a future `logger.debug("args=%r", args)` cannot leak it. Pinned by test.

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
- `KeyPairValidationError` for a pair that fails its pre-write self-check.
- `NOTICE`, and an SPDX `Apache-2.0` header on every source file.
- `CONTRIBUTING.md`, `CODE-OF-CONDUCT.md`, `CODEOWNERS`, `SUPPORT.md`, issue
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
- Default RSA key size raised from 2048 to 3072 bits. `--key-size` is now an
  allowlist of 2048, 3072 and 4096 rather than a lower bound: the underlying
  library accepts many sizes that clear the minimum but interoperate poorly.
- `write_key_pair()` returns a frozen `KeyGenerationResult` carrying paths,
  algorithm, key size, fingerprint and encryption status — and no secret, so a
  caller cannot log one by accident.
- Minimum Python raised to 3.10; 3.8 and 3.9 are end-of-life. Tested on 3.10
  through 3.14, across Linux, macOS and Windows.
- Packaging migrated to PEP 621. The version is declared in exactly one place
  and read via `importlib.metadata`; it was previously duplicated across
  `__init__.py`, `pyproject.toml` and `setup.py`.
- `SECURITY.md` replaced — it was the unedited GitHub template, claiming
  supported versions `5.1.x` and `4.0.x` for a `0.0.1` project.
- Licence metadata corrected to **Apache-2.0**, matching the `LICENSE` file.
  `pyproject.toml`, `setup.py` and the README previously all declared MIT while
  the repository shipped Apache-2.0.
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
- CI fails on committed private key material, on a missing SPDX header, and if
  the built wheel does not install and round-trip in a clean environment.
- A dedicated `tests/test_security_regressions.py` asserts, across every log
  level, that neither private key material nor passphrases reach stdout,
  stderr, logs or exception messages.
- `tests/test_release_candidate.py` injects failures at every write stage --
  before private creation, after creation, after backup, during public
  creation and replacement, and during rollback itself -- and asserts the
  directory always holds a complete old pair, a complete new pair, or no pair.
  Each safeguard was mutation-tested: reverting it makes the corresponding
  test fail.
- Doctests now run as part of the suite (`--doctest-modules`). They were not
  executed before, which is how a set of corrupted docstring examples --
  containing literal newlines instead of escapes -- came to ship.

## [0.0.1] — 2024-07-27

### Added

- Initial release: RSA-2048 key pair generation to `keys/pem/`.

[Unreleased]: https://github.com/hsbc/encryption-helper-python/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/hsbc/encryption-helper-python/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/hsbc/encryption-helper-python/releases/tag/v0.0.1
