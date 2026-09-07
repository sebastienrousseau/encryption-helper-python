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
  <img src="https://img.shields.io/badge/coverage-98%25-brightgreen.svg" alt="Coverage">
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

```text
Private key: secrets/service.pem
Public key:  secrets/service.pub.pem
Fingerprint: SHA256:U6sJe5e6rlxZi2ZFoPUW+XEW7pUS+42DwehICgx6G7g

secrets/service.pem is a PRIVATE KEY. Anyone who reads it can impersonate you
and decrypt data sent to you...
```

The private key is **never printed**. The fingerprint is shown instead, so you
can identify the key without handling it.

Protect it with a passphrase:

```bash
export KEY_PASSPHRASE='correct horse battery staple'
encryption-helper keygen --out-dir ./secrets --passphrase-env KEY_PASSPHRASE
```

Other algorithms:

```bash
encryption-helper keygen --algorithm ed25519 --out-dir ./secrets
encryption-helper keygen --algorithm ecdsa --curve p384 --out-dir ./secrets
encryption-helper keygen --algorithm rsa --key-size 4096 --out-dir ./secrets
```

An existing key is never replaced by accident:

```console
$ encryption-helper keygen --out-dir ./secrets
error: secrets/key.pem already exists. Refusing to overwrite it, because
replacing key material cannot be undone. ...
$ echo $?
3
```

Pass `--force` to replace it; the old key is backed up to a timestamped
sibling first.

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
| `KeyWriteError` / `KeyReadError` | Key material could not be written / read. |
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
| Passphrase input | Read from an environment variable or a file — never from `argv`, which is world-readable via `/proc`. |

### Cryptographic choices

| Purpose | Construction |
| ------- | ------------ |
| Encryption | AES-256-GCM under a random 256-bit content key, wrapped with RSA-OAEP (SHA-256, MGF1-SHA256). |
| Private key container | **PKCS#8** (`-----BEGIN PRIVATE KEY-----`). |
| Public key container | SubjectPublicKeyInfo, or the OpenSSH single-line form. |
| RSA signatures | PSS with SHA-256 and a salt the length of the digest. PKCS#1 v1.5 is not offered. |
| EdDSA / ECDSA signatures | Ed25519 (PureEdDSA); ECDSA with SHA-256. |
| Default RSA size | 3072 bits. Below 2048 is rejected outright. |
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

Full contributor guide: [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

> [!NOTE]
> **The licence of this project is currently being confirmed.** The `LICENSE`
> file is Apache-2.0 while the previous package metadata declared MIT. Until
> HSBC Open Source resolves the discrepancy, the machine-readable `license`
> field is intentionally omitted rather than asserting a term that contradicts
> the file. Tracked as finding C1 in
> [docs/IMPLEMENTATION_PLAN.md](./docs/IMPLEMENTATION_PLAN.md).

See the [LICENSE](LICENSE) file.

[0]: https://github.com/pyca/cryptography
