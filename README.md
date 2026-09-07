<!-- markdownlint-disable MD033 MD041 -->
<p align="center">
  <img src="https://www.hsbc.com/-/files/hsbc/header/hsbc-logo-200x25.svg" alt="HSBC Logo" width="200" title="HSBC Logo">
</p>

<h1 align="center">Encryption Helper Python</h1>

<p align="center">
  <img src="./assets/banner.jpg" alt="Encryption Helper Banner">
</p>

<p align="center">
  <strong>Generate, protect and use asymmetric key pairs — with defaults that do not leak your private key.</strong>
</p>

<p align="center">
  <a href="https://github.com/hsbc/encryption-helper-python/actions/workflows/ci.yml"><img src="https://github.com/hsbc/encryption-helper-python/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://pypi.org/project/encryption-helper/"><img src="https://img.shields.io/pypi/v/encryption-helper.svg" alt="PyPI version"></a>
  <a href="https://pypi.org/project/encryption-helper/"><img src="https://img.shields.io/pypi/pyversions/encryption-helper.svg" alt="Supported Python versions"></a>
  <a href="https://api.securityscorecards.dev/projects/github.com/hsbc/encryption-helper-python"><img src="https://api.securityscorecards.dev/projects/github.com/hsbc/encryption-helper-python/badge" alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen.svg" alt="Coverage">
  <img src="https://img.shields.io/badge/types-mypy%20strict-blue.svg" alt="mypy strict">
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#command-line-usage">CLI</a> •
  <a href="#library-usage">Library</a> •
  <a href="#security">Security</a> •
  <a href="#development">Development</a> •
  <a href="#license">License</a>
</p>
<!-- markdownlint-enable MD033 MD041 -->

> [!WARNING]
> **Version 0.0.1 leaked private keys.** It wrote them world-readable and
> printed them to stdout. If you generated a key with 0.0.1, treat it as
> compromised and rotate it. See
> [SECURITY-ADVISORY-0001](./docs/SECURITY-ADVISORY-0001.md).

## Features

- **Key generation** — RSA (2048/3072/4096), Ed25519, and ECDSA on P-256,
  P-384 and P-521.
- **Safe storage** — private keys written at mode `0600` inside a `0700`
  directory, atomically, and never silently overwritten.
- **Passphrase protection** — at-rest encryption of private keys, with the
  passphrase read from the environment or a file, never from `argv`.
- **Hybrid encryption** — AES-256-GCM under a content key wrapped with
  RSA-OAEP-SHA256, so data of any size can be encrypted correctly.
- **Signing and verification** — RSA-PSS, Ed25519 and ECDSA, with the scheme
  chosen from the key so it cannot be mismatched.
- **Fingerprints** — SHA-256 fingerprints identical to `ssh-keygen -lf`.
- **Format conversion** — PEM, DER and OpenSSH, in both directions.
- **Typed** — ships `py.typed`; the package passes `mypy --strict`.

## Installation

Requires **Python 3.10 or later**.

```bash
pip install encryption-helper
```

<details>
<summary>From source</summary>

```bash
git clone https://github.com/hsbc/encryption-helper-python.git
cd encryption-helper-python
pip install .
```

</details>

## Command-line usage

### Generate a key pair

```bash
encryption-helper keygen --out-dir ./secrets --name service
```

You will be prompted for a passphrase, twice, without echo:

```text
Passphrase for the new private key:
Confirm passphrase:

RSA key pair generated successfully.
Algorithm:   rsa
Key size:    3072 bits
Private key: /home/you/secrets/service.pem
Public key:  /home/you/secrets/service.pub.pem
Fingerprint: SHA256:U6sJe5e6rlxZi2ZFoPUW+XEW7pUS+42DwehICgx6G7g
Encrypted:   yes

/home/you/secrets/service.pem is a PRIVATE KEY. Anyone who reads it can
impersonate you and decrypt data sent to you...
```

The private key is **never printed**. The fingerprint identifies the key
without exposing it.

**An unencrypted private key is never the default.** In a non-interactive
context — CI, a script, a container — you must say which you want:

```bash
# Supply a passphrase without putting it in argv:
export KEY_PASSPHRASE='correct horse battery staple'
encryption-helper keygen --out-dir ./secrets --passphrase-env KEY_PASSPHRASE

# Or store it unencrypted, deliberately:
encryption-helper keygen --out-dir ./secrets --no-passphrase
```

Otherwise the command refuses:

```console
$ encryption-helper keygen --out-dir ./secrets < /dev/null
error: refusing to write an unencrypted private key by default.
  Supply a passphrase with --passphrase-env VAR or --passphrase-file PATH,
  or pass --no-passphrase to store the key unencrypted on purpose.
$ echo $?
2
```

Other algorithms and sizes:

```bash
encryption-helper keygen --algorithm ed25519 --out-dir ./secrets
encryption-helper keygen --algorithm ecdsa --curve p384 --out-dir ./secrets
encryption-helper keygen --key-size 4096 --out-dir ./secrets
```

#### Passphrase source semantics

| Source | Handling |
| ------ | -------- |
| `--passphrase-env VAR` | Taken verbatim. A whitespace-only value is rejected as an unset-variable accident; leading and trailing spaces are otherwise preserved. |
| `--passphrase-file PATH` | Exactly one trailing newline (`LF` or `CRLF`) is removed, because editors append one. **Nothing else is stripped**, so a passphrase may begin or end with a space, contain internal newlines, or not be valid UTF-8. Capped at 64 KiB. |
| `--no-passphrase` | Stores the key unencrypted. |

`--passphrase-env`, `--passphrase-file` and `--no-passphrase` are **mutually
exclusive at the parser level**: `--no-passphrase --passphrase-file secret.txt`
is a usage error, not a precedence puzzle. Prompting happens only when none of
the three is given and a terminal is attached.

Order of operations for a file: read → remove one trailing newline → reject
empty or whitespace-only → convert to bytes. Text sources (prompt, environment)
are UTF-8 encoded at that same single conversion point; a file is byte-exact,
so a random-bytes secret works unchanged.

On POSIX you are warned — not blocked — if the passphrase file is group- or
world-readable. CI secret mounts and enterprise filesystems have access models
this check cannot reason about, so it does not pretend to be a guarantee.

So a file containing `secret\n` yields the passphrase `secret`, and a file
containing `secret\n\n` yields `secret\n`.

`--key-size` accepts `2048`, `3072` or `4096`. Other values are refused rather
than silently accepted: the underlying library allows many sizes that clear the
minimum but interoperate poorly.

An existing key is never replaced by accident:

```console
$ encryption-helper keygen --out-dir ./secrets --name service --no-passphrase
error: Key files already exist: /home/you/secrets/service.pem, ...
Refusing to overwrite key material, because replacing it cannot be undone.
$ echo $?
3
```

Both destinations are checked *before* anything is written, so a conflict never
leaves a half-written pair. Pass `--force` to replace; the previous files are
backed up to timestamped siblings first.

You are also warned before writing keys into a git checkout:

```console
$ encryption-helper keygen --out-dir ./secrets
warning: /repo/secrets is inside the git repository at /repo.
         Private keys should not live in a working tree. Use --out-dir to
         write them somewhere outside it.
```

### Encrypt and decrypt

```bash
encryption-helper encrypt --public-key secrets/service.pub.pem \
  --in report.pdf --out report.pdf.enc

encryption-helper decrypt --private-key secrets/service.pem \
  --in report.pdf.enc --out report.pdf
```

Both commands read stdin and write stdout by default, so they compose:

```bash
pg_dump mydb | encryption-helper encrypt --public-key backup.pub.pem > dump.enc
```

### Sign and verify

```bash
encryption-helper sign   --private-key secrets/service.pem --in release.tar.gz --out release.sig
encryption-helper verify --public-key  secrets/service.pub.pem --signature release.sig --in release.tar.gz
```

`verify` exits `4` if the signature does not match.

### Fingerprint and convert

```bash
encryption-helper fingerprint secrets/service.pub.pem
encryption-helper convert --to openssh --in secrets/service.pub.pem --out ~/.ssh/id_service.pub
```

### Global options

| Flag | Meaning |
| ---- | ------- |
| `--version` | Print the installed version. |
| `-v`, `-vv` | Increase log verbosity (info, then debug). |
| `-q`, `--quiet` | Suppress non-error output. |
| `--log-level LEVEL` | Set an explicit level, overriding `-v`/`-q`. |
| `--json` | Emit machine-readable JSON on stdout. |

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Success. |
| `1` | An error occurred. |
| `2` | Usage error — bad or missing arguments. |
| `3` | A destination file exists and `--force` was not given. |
| `4` | Decryption or signature verification failed. |

## Library usage

```python
from pathlib import Path

from encryption_helper import (
    decrypt,
    encrypt,
    fingerprint_sha256,
    generate_rsa,
    sign,
    verify,
    write_key_pair,
)

key = generate_rsa(key_size=3072)

paths = write_key_pair(key, Path("./secrets"), name="service")
print(paths.private_key)  # secrets/service.pem, mode 0600
print(fingerprint_sha256(key.public_key()))  # SHA256:...

blob = encrypt(key.public_key(), b"database password")
assert decrypt(key, blob) == b"database password"

signature = sign(key, b"release manifest")
verify(key.public_key(), signature, b"release manifest")  # raises if invalid
```

Generation, serialisation and storage are separate steps, so the library can be
used in a service that never touches a disk:

```python
from encryption_helper import encode_private_key, generate_ed25519

pem = encode_private_key(generate_ed25519(), passphrase=b"...")
```

### Errors

Everything raised deliberately derives from `EncryptionHelperError`, and no
error message contains key material, passphrases, or plaintext.

```python
from encryption_helper import DecryptionError, KeyExistsError, decrypt

try:
    decrypt(key, blob)
except DecryptionError:
    ...  # tampered, truncated, or encrypted to a different key
```

| Exception | Raised when |
| --------- | ----------- |
| `InvalidArgumentError` | An argument is missing, malformed, or out of range. |
| `UnsupportedAlgorithmError` | The algorithm, curve, or format is not supported. |
| `KeyGenerationError` | The backend failed to generate a key. |
| `KeyExistsError` | A destination exists and overwriting was not requested. |
| `KeyPairValidationError` | A generated pair failed its self-check; nothing was written. |
| `KeyWriteError` | Key material could not be written to disk. |
| `KeyReadError` | Key material could not be read or parsed, including a wrong passphrase. |
| `DecryptionError` | A ciphertext failed to decrypt or failed its integrity check. |
| `SignatureVerificationError` | A signature did not verify. |

## Security

### How your private key is protected

| Property | Behaviour |
| -------- | --------- |
| File permissions | `0600` for private keys, inside a `0700` directory. Not subject to the process umask. |
| Printing / logging | Private key material is never printed or logged, at any verbosity. |
| At rest | Optionally encrypted with a passphrase (`BestAvailableEncryption`). |
| Overwrites | Refused by default; `--force` backs up the previous key first. |
| Atomicity | Written via a temporary file and `rename`, so an interrupted run cannot truncate a key. |
| Symlinks | Writing through a symbolic link is refused. |
| Passphrase input | Prompted without echo, or read from an environment variable or a file — never from `argv`, which is world-readable via `/proc`. |
| Destination aliasing | Symlinked destinations are refused; so are hard-linked pairs and a private key path with more than one link. |
| Plaintext keys | Never a default. Storing one unencrypted requires an explicit `--no-passphrase`. |
| Pair integrity | Serialised keys are parsed back and matched before either file is written; a partial write is rolled back. |
| Path handling | `~` is expanded and relative paths resolved, so `--out-dir ~/keys` writes to your home directory rather than creating a directory named `~`. |
| Error text | Unexpected exception detail is logged, not printed, so it cannot spill paths or values into a terminal. |

### Cryptographic choices

| Purpose | Construction |
| ------- | ------------ |
| Encryption | AES-256-GCM under a random 256-bit content key, wrapped with RSA-OAEP (SHA-256, MGF1-SHA256). |
| Private key container | **PKCS#8** (`-----BEGIN PRIVATE KEY-----`). |
| Public key container | SubjectPublicKeyInfo, or the OpenSSH single-line form. |
| RSA signatures | PSS with SHA-256 and a salt the length of the digest. PKCS#1 v1.5 is not offered. |
| EdDSA / ECDSA signatures | Ed25519 (PureEdDSA); ECDSA with SHA-256. |
| Default RSA size | 3072 bits. Only 2048, 3072 and 4096 are accepted. |
| Fingerprints | SHA-256 over the OpenSSH wire encoding, matching `ssh-keygen -lf`. |

Data of any size can be encrypted: the RSA key wraps only the 32-byte content
key, never the message. Encryption and decryption operate on whole messages in
memory, which suits keys, credentials, configuration and documents — but not
multi-gigabyte files. Streaming is deliberately absent rather than implemented
badly.

### Threat model

**This package protects key material with filesystem permissions.** That is
its entire defence at rest.

It is designed to resist:

- Another local user reading your private key.
- Key material leaking into logs, terminal captures, or CI output.
- Silent destruction of a key by re-running a command.
- Tampered ciphertext being accepted as authentic.

It does **not** protect against:

- An attacker with root, or with your user account, on the host.
- Memory disclosure — keys are ordinary Python objects and are not locked into
  RAM or zeroed after use.
- Side-channel attacks against the underlying primitives.

> [!IMPORTANT]
> This is not a substitute for a hardware security module or a managed KMS. If
> your keys must never be exportable, or your threat model includes a
> privileged local attacker, use an HSM or a cloud KMS instead.

### Reporting a vulnerability

See [SECURITY.md](./SECURITY.md). Please do not open a public issue.

## Development

```bash
git clone https://github.com/hsbc/encryption-helper-python.git
cd encryption-helper-python

poetry install
poetry run pre-commit install

poetry run pytest                     # 250+ tests, with a 95% branch-coverage gate
poetry run ruff check .               # lint (source and tests)
poetry run ruff format --check .      # formatting
poetry run mypy --strict encryption_helper
poetry run bandit -c pyproject.toml -r encryption_helper
```

### Examples, benchmarks and fuzzing

```bash
python examples/01_generate_key_pair.py    # all four run in CI
python benches/bench_crypto.py --quick     # indicative timings, not a gate
python fuzz/run_fuzz.py --iterations 50000 # no fuzzing engine required
```

`examples/` is executed by CI, so an example that stops working fails the
build. `fuzz/` targets the two parsers that accept untrusted input --
`decrypt()` and the key loaders -- and asserts they fail closed with a typed
error for any input; see [fuzz/README.md](./fuzz/README.md). Atheris entry
points are provided for coverage-guided runs, but the standalone runner is
what CI uses because it needs no engine and no compiler.

Full contributor guide: [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](./LICENSE) and
[NOTICE](./NOTICE).

```text
Copyright 2024-2026 HSBC Group Management Services Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

[0]: https://github.com/pyca/cryptography
