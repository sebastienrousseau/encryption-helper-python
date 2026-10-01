<!-- SPDX-License-Identifier: Apache-2.0 -->

<p align="center">
  <img src="./assets/banner.jpg" alt="Encryption Helper banner" width="640" />
</p>

<h1 align="center">Encryption Helper</h1>

<p align="center">
  Generate, protect and use asymmetric keys — including post-quantum ML-KEM and ML-DSA.
</p>

<p align="center">
  <a href="https://github.com/hsbc/encryption-helper-python/actions/workflows/ci.yml"><img src="https://github.com/hsbc/encryption-helper-python/actions/workflows/ci.yml/badge.svg?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://pypi.org/project/encryption-helper/"><img src="https://img.shields.io/pypi/v/encryption-helper?style=for-the-badge&color=fc8d62&logo=python" alt="Registry" /></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/hsbc/encryption-helper-python"><img src="https://img.shields.io/ossf-scorecard/github.com/hsbc/encryption-helper-python?style=for-the-badge&label=OpenSSF%20Scorecard&logo=openssf" alt="OpenSSF Scorecard" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=for-the-badge" alt="License: Apache-2.0" /></a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-93450a.svg?style=for-the-badge&logo=python" alt="Python 3.10 or newer" />
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen.svg?style=for-the-badge" alt="Coverage 100%" />
  <img src="https://img.shields.io/badge/types-mypy%20strict-blue.svg?style=for-the-badge" alt="mypy strict" />
</p>

---

## Contents

**Getting started**

- [Why this exists](#why-this-exists) — the problem it solves, and the 2035 deadline
- [Installation](#installation) — pip, Poetry, from source
- [Quick start](#quick-start) — generate, encrypt, sign in three commands

**Command line**

- [Commands](#commands) — `keygen`, `encrypt`, `decrypt`, `sign`, `verify`, `fingerprint`, `convert`, `capabilities`
- [Algorithms](#algorithms) — what to pick, and what expires when
- [Passphrases](#passphrases) — source semantics, pinned
- [Global options and exit codes](#global-options-and-exit-codes)

**Library reference**

- [Library usage](#library-usage) — the three-step API
- [Errors](#errors) — the typed hierarchy

**Operational**

- [Security](#security) — guarantees, cryptographic choices, threat model
- [Performance](#performance) — measured costs and memory behaviour
- [Development](#development) — tests, fuzzing, benchmarks, examples
- [Stability](#stability) — versioning and what may change
- [License](#license)

**Project**

- [ARCHITECTURE.md](./ARCHITECTURE.md) — dependency direction, invariants, container format
- [DEVELOPMENT.md](./DEVELOPMENT.md) — setup, commands, test layout
- [ROADMAP.md](./ROADMAP.md) — what is planned, and what deliberately is not
- [RELEASING.md](./RELEASING.md) — the release and provenance procedure
- [GOVERNANCE.md](./GOVERNANCE.md) · [MAINTAINERS.md](./MAINTAINERS.md) · [SECURITY.md](./SECURITY.md)

---

## Why this exists

`openssl genrsa` prints your private key to the terminal and writes files at
whatever the umask allows. That is fine for interactive use and awkward
everywhere else — shared machines, CI runners, containers.

This package does the same job with defaults that survive those environments,
a typed Python API, and the post-quantum algorithms.

> [!IMPORTANT]
> **RSA and the elliptic curves have a deadline.** NIST IR 8547 deprecates
> RSA-2048 and P-256 from **2030** and disallows RSA-3072 and P-384 from
> **2035**. A key you generate today for a long-lived credential outlives both
> dates. For that material use `--algorithm mlkem` (encryption) or
> `--algorithm mldsa` (signing), which are FIPS 203 and FIPS 204.
>
> Run `encryption-helper capabilities` to see where you stand.

---

## Installation

Requires **Python 3.10 or later**.

```bash
pip install encryption-helper
```

<details>
<summary>Poetry, or from source</summary>

```bash
poetry add encryption-helper

# or from a checkout
git clone https://github.com/hsbc/encryption-helper-python.git
cd encryption-helper-python
pip install .
```

</details>

---

## Quick start

```bash
# A post-quantum encryption key. You will be prompted for a passphrase.
encryption-helper keygen --algorithm mlkem --out-dir ./secrets --name service

# Encrypt something to it.
encryption-helper encrypt --public-key secrets/service.pub.pem \
  --in report.pdf --out report.pdf.enc

# And back.
encryption-helper decrypt --private-key secrets/service.pem \
  --in report.pdf.enc --out report.pdf
```

The private key is **never printed**. You get a path and a fingerprint:

```text
MLKEM key pair generated successfully.
Algorithm:     mlkem
Parameter set: 768
Private key:   secrets/service.pem
Public key:    secrets/service.pub.pem
Fingerprint:   SHA256-SPKI:47Py83clVv0VJfgERnQafgXjGYB4Ck7nwz2wnWOda6E
Encrypted:     yes
```

---

## Commands

| Command | Purpose |
| ------- | ------- |
| `encryption-helper keygen` | Generate a key pair and store it owner-only |
| `encryption-helper encrypt` | Encrypt data to a public key |
| `encryption-helper decrypt` | Decrypt with a private key |
| `encryption-helper sign` | Sign data |
| `encryption-helper verify` | Verify a signature |
| `encryption-helper fingerprint` | Print a public key fingerprint |
| `encryption-helper convert` | Convert between PEM, DER and OpenSSH |
| `encryption-helper capabilities` | List algorithms and their deprecation horizon |

### keygen

```bash
encryption-helper keygen --algorithm mlkem --level 1024 --out-dir ./secrets
encryption-helper keygen --algorithm mldsa --level 87 --out-dir ./secrets
encryption-helper keygen --algorithm rsa --key-size 4096 --out-dir ./secrets
```

An **unencrypted private key is never the default**. In a non-interactive
context you must choose:

```bash
export KEY_PASSPHRASE='correct horse battery staple'
encryption-helper keygen --out-dir ./secrets --passphrase-env KEY_PASSPHRASE

# or, deliberately:
encryption-helper keygen --out-dir ./secrets --no-passphrase
```

Otherwise it refuses with exit `2`. An existing key is never replaced by
accident either — both destinations are checked *before* anything is written,
and `--force` backs the old files up to timestamped siblings first.

### capabilities

```console
$ encryption-helper capabilities
algorithm   encrypt  sign  post-quantum  horizon
----------------------------------------------------------
rsa             yes   yes            no  deprecated 2030, disallowed 2035
ed25519           -   yes            no  deprecated 2030, disallowed 2035
ed448             -   yes            no  deprecated 2030, disallowed 2035
ecdsa             -   yes            no  deprecated 2030, disallowed 2035
x25519          yes     -            no  deprecated 2030, disallowed 2035
mlkem           yes     -           yes  no deadline
mldsa             -   yes           yes  no deadline
```

`--json` gives the same thing machine-readably, for a cryptographic inventory.

### Pipelines

`encrypt`, `decrypt` and `sign` read stdin and write stdout by default:

```bash
pg_dump mydb | encryption-helper encrypt --public-key backup.pub.pem > dump.enc
```

With `--json`, the report moves to stderr so stdout stays pure.

---

## Algorithms

| Algorithm | Encrypt | Sign | Post-quantum | Notes |
| --------- | :-----: | :--: | :----------: | ----- |
| `mlkem` | ✅ | — | ✅ | FIPS 203. Levels 768, 1024 |
| `mldsa` | — | ✅ | ✅ | FIPS 204. Levels 44, 65, 87 |
| `rsa` | ✅ | ✅ | ❌ | 2048, 3072, 4096. Default 3072 |
| `ed25519` | — | ✅ | ❌ | Compact, fast |
| `ed448` | — | ✅ | ❌ | Higher margin than Ed25519 |
| `ecdsa` | — | ✅ | ❌ | P-256, P-384, P-521 |
| `x25519` | ✅ | — | ❌ | Ephemeral-static, as `age` does |

`--key-size` accepts `2048`, `3072` or `4096`; other values are refused rather
than silently accepted, because the underlying library allows many sizes that
interoperate poorly.

### Container format

Ciphertexts are self-describing. The header names the mechanism, so a
recipient never guesses and an old ciphertext stays readable when a new
mechanism is added:

| `kem_id` | Mechanism | Post-quantum |
| :------: | --------- | :----------: |
| 1 | RSA-OAEP-SHA256 | ❌ |
| 2 | ML-KEM-768 | ✅ |
| 3 | ML-KEM-1024 | ✅ |
| 4 | X25519 + HKDF-SHA256 | ❌ |

> [!NOTE]
> Hybrid X25519+ML-KEM is **deliberately not implemented**. A composite KEM
> needs a composite key container, and inventing one without external
> cryptographic review would be false confidence. ML-KEM alone is
> FIPS-approved and satisfies the horizon.

---

## Passphrases

| Source | Handling |
| ------ | -------- |
| interactive prompt | Asked twice, no echo. Used when no other source is given and a terminal is attached |
| `--passphrase-env VAR` | Taken verbatim. A whitespace-only value is rejected as an unset-variable accident |
| `--passphrase-file PATH` | Exactly one trailing newline (`LF` or `CRLF`) removed, nothing else. Capped at 64 KiB |
| `--no-passphrase` | Stores the key unencrypted. Required to skip protection |

These four are **mutually exclusive at the parser level** —
`--no-passphrase --passphrase-file secret.txt` is a usage error, not a
precedence puzzle.

A passphrase is never read from `argv`, which is world-readable via `/proc`.
On POSIX you are warned, not blocked, if the passphrase file is group- or
world-readable.

---

## Global options and exit codes

| Flag | Meaning |
| ---- | ------- |
| `--version` | Print the installed version |
| `-v`, `-vv` | Increase log verbosity |
| `-q`, `--quiet` | Suppress non-error output |
| `--log-level LEVEL` | Explicit level, overriding `-v`/`-q` |
| `--json` | Machine-readable output |
| `--max-size BYTES` | Refuse input above this (default 64 MiB) |

| Code | Meaning |
| ---- | ------- |
| `0` | Success |
| `1` | An error occurred |
| `2` | Usage error — bad or missing arguments |
| `3` | A destination exists and `--force` was not given |
| `4` | Decryption or signature verification failed |

---

## Library usage

Generation, serialisation and storage are separate steps, so the library works
in a service that never touches a disk.

```python
from pathlib import Path

from encryption_helper import (
    decrypt,
    encrypt,
    fingerprint_sha256,
    generate_mldsa,
    generate_mlkem,
    sign,
    verify,
    write_key_pair,
)

# Post-quantum encryption.
kem = generate_mlkem(level=768)
paths = write_key_pair(kem, Path("./secrets"), name="service")
print(paths.private_key, fingerprint_sha256(kem.public_key()))

blob = encrypt(kem.public_key(), b"database password")
assert decrypt(kem, blob) == b"database password"

# Post-quantum signing.
dsa = generate_mldsa(level=65)
verify(dsa.public_key(), sign(dsa, b"release manifest"), b"release manifest")
```

`write_key_pair` returns a frozen `KeyGenerationResult` carrying paths,
algorithm, parameter set, fingerprint and encryption status — and no secret,
so you cannot log one by accident.

---

## Errors

Everything raised deliberately derives from `EncryptionHelperError`, and no
message contains key material, passphrases or plaintext.

| Exception | Raised when |
| --------- | ----------- |
| `InvalidArgumentError` | An argument is missing, malformed, or out of range |
| `UnsupportedAlgorithmError` | The algorithm, curve, level or format is not supported |
| `KeyGenerationError` | The backend failed to generate a key |
| `KeyExistsError` | A destination exists and overwriting was not requested |
| `KeyWriteError` | Key material could not be written to disk |
| `KeyReadError` | Key material could not be read or parsed, including a wrong passphrase |
| `KeyPairValidationError` | A generated pair failed its pre-write self-check |
| `DecryptionError` | A ciphertext failed to decrypt or failed its integrity check |
| `SignatureVerificationError` | A signature did not verify |

A key that can *never* decrypt raises `InvalidArgumentError` — a programming
mistake. A key that *could* decrypt but does not match the container raises
`DecryptionError`, because that is indistinguishable from a tampered header.

---

## Security

### How your private key is protected

| Property | Behaviour |
| -------- | --------- |
| File permissions | `0600` for private keys, inside a `0700` directory. Not subject to the umask |
| Printing / logging | Private key material is never printed or logged, at any verbosity |
| At rest | Optionally encrypted with a passphrase (`BestAvailableEncryption`) |
| Plaintext keys | Never a default; requires an explicit `--no-passphrase` |
| Overwrites | Refused by default; `--force` backs up the previous key first |
| Atomicity | Temporary file plus `rename`, so an interrupted run cannot truncate a key |
| Rollback | A failed write restores what it displaced, mode included; a partial pair is undone |
| Symlinks | Writing through a symbolic link is refused |
| Destination aliasing | Hard-linked pairs, and private paths with more than one link, are refused |
| Pair integrity | Serialised keys are parsed back and matched before either file is written |
| Passphrase input | Prompted without echo, or from the environment or a file — never from `argv` |
| Path handling | `~` is expanded and relative paths resolved |
| Error text | Unexpected exception detail is logged, not printed |

### Cryptographic choices

| Purpose | Construction |
| ------- | ------------ |
| Encryption | AES-256-GCM under a content key, encapsulated by ML-KEM, RSA-OAEP-SHA256 or X25519+HKDF-SHA256 |
| Content key derivation | HKDF-SHA256, with the mechanism identifier in the `info` so the same secret cannot derive the same key under two labels |
| Private key container | **PKCS#8** (`-----BEGIN PRIVATE KEY-----`) |
| Public key container | SubjectPublicKeyInfo, or the OpenSSH single-line form |
| RSA signatures | PSS with SHA-256, salt = digest length. PKCS#1 v1.5 is not offered |
| EdDSA / ECDSA | Ed25519, Ed448 (PureEdDSA); ECDSA with SHA-256 |
| Post-quantum signatures | ML-DSA, hedged (FIPS 204) |
| Fingerprints | SHA-256 over the OpenSSH encoding where one exists, matching `ssh-keygen -lf`; otherwise over DER SPKI under a distinct `SHA256-SPKI:` prefix |

### Threat model

**This package protects key material with filesystem permissions.** That is
its entire defence at rest.

It resists another local user reading your key, key material leaking into
logs or CI output, silent destruction of a key by re-running a command, and
tampered ciphertext being accepted as authentic.

It does **not** protect against an attacker with root or your user account,
memory disclosure (keys are ordinary Python objects, not locked into RAM or
zeroed), or side channels in the underlying primitives.

> [!WARNING]
> Not a substitute for an HSM or a managed KMS. If your keys must never be
> exportable, or your threat model includes a privileged local attacker, use
> one of those instead.

**Windows:** permissions are enforced with POSIX mode bits. On Windows the
mode is advisory — NTFS uses ACLs, which `os.chmod` cannot express. Files are
still created exclusively and replaced atomically. Platform-specific tests
skip rather than assert a guarantee that does not hold.

Report vulnerabilities per [SECURITY.md](./SECURITY.md). Please do not open a
public issue.

---

## Performance

Measured on one machine; indicative, not a guarantee.

| Operation | Cost |
| --------- | ---- |
| ML-KEM-768 keygen | ~0.05 ms |
| ML-KEM-1024 keygen | ~0.08 ms |
| ML-DSA-65 keygen | ~0.13 ms |
| X25519 / Ed25519 keygen | ~0.02 ms |
| RSA-2048 keygen | ~17 ms (prime search; high variance) |
| RSA-3072 keygen | ~87 ms |
| ML-KEM encrypt / decrypt (64 KiB) | ~0.04 ms / ~0.09 ms |
| ML-DSA-65 sign / verify | ~0.5 ms / ~0.8 ms |
| Ed25519 sign | ~0.11 ms |
| Encrypt / decrypt throughput | ~3 GB/s, AES-NI bound |
| RSA private key **load** | ~22 ms — the library validates the primes |

**Post-quantum is not the slow option.** ML-KEM generates a key pair roughly
1,700× faster than RSA-3072, and encapsulation is cheaper than RSA-OAEP. The
real cost is size: ML-KEM ciphertexts carry 1,088 bytes of encapsulation
against RSA's 256, and an ML-DSA-65 signature is 3,309 bytes against
Ed25519's 64.

> [!CAUTION]
> Encryption is **not streamed**. Peak memory is roughly **four times** the
> payload: a 128 MiB input needs ~512 MB. The CLI therefore refuses input
> above `--max-size` (default 64 MiB) rather than being killed mid-write.
> Suitable for keys, credentials, configuration and documents; not for
> multi-gigabyte files.

Run them yourself: `python benches/bench_crypto.py --quick`

---

## Development

```bash
poetry install
poetry run pre-commit install

poetry run pytest                               # 557 tests, 100% branch coverage
poetry run ruff check . && poetry run ruff format --check .
poetry run mypy --strict encryption_helper
poetry run bandit -c pyproject.toml -r encryption_helper
```

```bash
python examples/01_generate_key_pair.py         # every example runs in CI
python fuzz/run_fuzz.py --iterations 50000      # no fuzzing engine required
python benches/bench_crypto.py --quick
```

`fuzz/` targets the parsers that accept untrusted input — `decrypt()` and the
key loaders — and asserts they fail closed with a typed error for any input.
Both harnesses are mutation-tested: planting a defect is detected within two
iterations, with a reproducible seed. See [fuzz/README.md](./fuzz/README.md).

Documentation is checked against the implementation by
`tests/test_documentation_accuracy.py`: every flag and subcommand in this file
must exist, exit codes and error tables must match the code, and every
relative link must resolve.

Full guide: [CONTRIBUTING.md](./CONTRIBUTING.md). Architecture:
[ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Stability

`0.0.x` carries no compatibility promise. The public API changed completely
between `0.0.1` and `0.0.2`; [CHANGELOG.md](./CHANGELOG.md) records what and
why.

What will not change without a major version once `1.0.0` lands: the container
format for existing `kem_id` values, the exception hierarchy, and exit codes.
New mechanisms are added by allocating a new identifier, never by changing an
existing one — an old ciphertext stays readable.

---

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](./LICENSE)
and [NOTICE](./NOTICE).

```text
Copyright 2024-2026 HSBC Group Management Services Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

This package depends on [`cryptography`](https://github.com/pyca/cryptography),
dual-licensed Apache-2.0 / BSD-3-Clause.
