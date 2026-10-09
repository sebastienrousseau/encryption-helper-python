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

- [Why this exists](#why-this-exists) — who it is for, and the 2030/2035 dates
- [Installation](#installation) — pip, Poetry, from source, or a container
- [Quick start](#quick-start) — generate, encrypt, decrypt in three commands
- [Examples](#examples) — eleven runnable scenarios, from key generation to partner file exchange

**Command line**

- [Commands](#commands) — `keygen`, `encrypt`, `decrypt`, `sign`, `verify`, `fingerprint`, `convert`, `inspect`, `scan`, `capabilities`
- [Migration planning](#migration-planning) — inventory keys on disk and see what is affected, and when
- [Algorithms](#algorithms) — what to pick, and what expires when
- [Passphrases](#passphrases) — source semantics, pinned
- [Global options and exit codes](#global-options-and-exit-codes)

**Library reference**

- [Library usage](#library-usage) — the three-step API
- [Errors](#errors) — the typed hierarchy

**Operational**

- [Container sandbox](#container-sandbox) — run everything without installing Python
- [MCP server](#mcp-server) — read-only migration scoping for an AI assistant
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

Organisations that exchange files with banks, payment providers and trading
partners need asymmetric keys: to encrypt what they send, to sign it, and to
check what they receive. The people doing this work are usually treasury
operations, integration and platform teams rather than cryptographers, and
the common failures are operational ones. A private key gets printed into a
CI log. A key file is left readable by other users. A re-run overwrites a
production key. A public key arrives by email and nobody checks it.

Encryption Helper is built around those failures. It never prints or logs a
private key, it writes key files owner-only whatever the umask, it refuses to
overwrite an existing key unless asked, and it gives every public key a
fingerprint you can confirm with your counterparty over a separate channel.

It also helps with the planning question now in front of most security and
risk teams: **which of our keys are affected by the move to post-quantum
cryptography, and by when?** `encryption-helper scan` answers that for the
keys, certificates and encrypted files on disk.

> [!IMPORTANT]
> **Classical public-key algorithms have published end dates.** NIST IR 8547
> (initial public draft) deprecates 112-bit keys such as **RSA-2048 after
> 2030**, and disallows RSA and elliptic-curve algorithms of every size
> **after 2035**. Keys below 112-bit strength, such as RSA-1024, are already
> disallowed under NIST SP 800-131A.
>
> Data encrypted today can be recorded and decrypted later, once a
> cryptanalytically relevant quantum computer exists. Where confidentiality or
> a signature must remain trustworthy past those dates, use
> `--algorithm mlkem` (encryption, FIPS 203) or `--algorithm mldsa`
> (signing, FIPS 204).
>
> Run `encryption-helper capabilities` for the table, or
> `encryption-helper scan PATH` to assess keys you already hold.

**What it is not.** It is not an HSM, a key management service or a PKI, and
it does not replace the file formats a counterparty or payment channel
specifies. See [Interoperability](#interoperability) and the
[threat model](#threat-model).

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

Where installing Python packages is not permitted, run it in a container
instead. See [Container sandbox](#container-sandbox).

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

## Examples

Each example is a short script that runs on its own, prints what it shows,
and removes everything it writes. All of them run in CI.

| Example | Scenario |
| ------- | -------- |
| [`01_generate_key_pair.py`](./examples/01_generate_key_pair.py) | Generate, serialise and store a key pair safely |
| [`02_encrypt_and_decrypt.py`](./examples/02_encrypt_and_decrypt.py) | Encrypt data of any size to a public key |
| [`03_sign_and_verify.py`](./examples/03_sign_and_verify.py) | Sign and verify with RSA-PSS, Ed25519 and ECDSA |
| [`04_load_and_convert.py`](./examples/04_load_and_convert.py) | Load keys in any encoding and convert between them |
| [`05_post_quantum.py`](./examples/05_post_quantum.py) | ML-KEM encryption and ML-DSA signing |
| [`06_large_files.py`](./examples/06_large_files.py) | Stream a file too large for memory |
| [`07_inventory_and_migration.py`](./examples/07_inventory_and_migration.py) | Scan a directory and plan a migration |
| [`08_key_rotation.py`](./examples/08_key_rotation.py) | Rotate a key without losing access to existing data |
| [`09_automation_with_json.py`](./examples/09_automation_with_json.py) | Drive the CLI from a script through the JSON contract |
| [`10_counterparty_file_exchange.py`](./examples/10_counterparty_file_exchange.py) | Send a signed, encrypted file to a counterparty, and what that stops |
| [`11_mcp_assistant_session.py`](./examples/11_mcp_assistant_session.py) | Query the read-only MCP server as an assistant would |

```bash
make examples                                   # on the host
./scripts/sandbox.sh --target examples          # in the container sandbox, nothing installed
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
| `encryption-helper inspect` | Report which algorithms protect an encrypted file, without decrypting it |
| `encryption-helper scan` | Inventory keys, certificates and encrypted files under a path |
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
# Read the passphrase without echoing it or writing it to shell history.
read -rsp 'Passphrase: ' KEY_PASSPHRASE && export KEY_PASSPHRASE
encryption-helper keygen --out-dir ./secrets --passphrase-env KEY_PASSPHRASE

# In CI, take it from the platform's secret store rather than a literal, and
# map it to the variable named here.

# or, deliberately, for test material only:
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
rsa             yes   yes            no  2048-bit: deprecated after 2030; all: disallowed after 2035
ed25519           -   yes            no  disallowed after 2035
ed448             -   yes            no  disallowed after 2035
ecdsa             -   yes            no  disallowed after 2035
x25519          yes     -            no  disallowed after 2035
mlkem           yes     -           yes  no deadline
mldsa             -   yes           yes  no deadline
```

NIST's dates follow each key's classical security strength. RSA-2048 is 112-bit,
so it is deprecated first; RSA-3072, P-256, Ed25519 and X25519 are 128-bit or
stronger and move straight to disallowed after 2035.

`--json` gives the same thing machine-readably, for a cryptographic inventory.

### inspect

Reports the key-establishment mechanism and cipher of an encrypted file from
its header alone. No private key is needed and nothing is decrypted.

```console
$ encryption-helper inspect --in statement.enc
Format version:     1
Key establishment:  ml-kem-768  [FIPS 203]
Content encryption: aes-256-gcm-segmented
Segmented:          yes

Uses a NIST post-quantum standard. No migration is required.
```

### scan

See [Migration planning](#migration-planning).

### Pipelines

`encrypt`, `decrypt` and `sign` read stdin and write stdout by default:

```bash
pg_dump mydb | encryption-helper encrypt --public-key backup.pub.pem > dump.enc
```

With `--json`, the report moves to stderr so stdout stays pure.

### Progress

A multi-gigabyte operation with no output is indistinguishable from a hang:

```console
$ encryption-helper encrypt --public-key backup.pub.pem \
    --in database.tar --out database.tar.enc --progress
1.0 GiB   32.9%  ETA 3s  1.6 GiB/s
3.1 GiB  100.0%  1.5 GiB/s  in 3s
```

Updates go to stderr, throttled to five per second, so stdout stays usable
and the reporting costs nothing measurable. Reading from a pipe the total is
unknown, so the percentage and ETA are omitted rather than guessed.
`--quiet` suppresses it.

---

## Migration planning

A post-quantum migration starts with scoping: finding the keys, certificates
and encrypted files you already hold, and which of them are affected.

```console
$ encryption-helper scan ./estate
file                                     kind                   algorithm    action
--------------------------------------------------------------------------------------
estate/legacy-h2h.pub.pem                public-key             rsa-1024     replace now with mlkem or mldsa
estate/partner-sftp.pub.pem              public-key             rsa-2048     migrate to mlkem or mldsa
estate/statement.enc                     container              ml-kem-768   none
estate/statements.pub.pem                public-key             mlkem-768    none

4 examined, 2 needing migration, 0 needing manual review.
1 below 112-bit strength: already disallowed by NIST SP 800-131A. Replace these first.
```

- Files are classified by **content**, not by name. Symbolic links are not
  followed.
- **No passphrase is ever requested.** An encrypted private key is reported
  as needing manual review, not as safe.
- An RSA key can both encrypt and sign, so it has two possible successors.
  The scanner names both rather than guess.
- `--json` emits the versioned contract in
  [`docs/schemas/cli-output-v1.json`](./docs/schemas/cli-output-v1.json), for
  an inventory system or CMDB.
- `--fail-on-finding` exits non-zero when anything needs attention, so a
  pipeline can stop new quantum-vulnerable material being committed.

The same assessment is available from Python (`encryption_helper.scan`,
`encryption_helper.assess`) and, read-only, to an AI assistant through the
[MCP server](#mcp-server).

> [!NOTE]
> The dates come from NIST publications and are reported as NIST states them.
> IR 8547 is an initial public draft and may change. Your own regulators,
> sector bodies or counterparties may set different timetables; treat this
> output as an input to your migration plan, not as compliance advice.

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

Two AEAD modes share those mechanisms:

| `aead_id` | Mode | Memory |
| :-------: | ---- | ------ |
| 1 | AES-256-GCM, one shot | proportional to payload |
| 2 | AES-256-GCM, segmented | bounded by segment size |

The CLI streams and reads either; the library's `encrypt()`/`decrypt()` are
one-shot, and `encrypt_stream()`/`decrypt_stream()` are segmented. Segment
framing is **Tink's STREAM**: a 12-byte nonce of 7-byte random prefix,
4-byte segment counter and 1-byte final flag, which together defend against
nonce reuse, reordering, segment dropping and truncation.

> [!NOTE]
> Hybrid X25519+ML-KEM is **deliberately not implemented**. A composite KEM
> needs a composite key container, and inventing one without external
> cryptographic review would be false confidence. ML-KEM alone is
> FIPS-approved and satisfies the horizon.

### Interoperability

The container above is **this library's own format**. It is not OpenPGP,
CMS/PKCS#7 or JWE, and other tools cannot decrypt it. Both sender and
receiver need `encryption-helper` 0.0.2 or later.

That suits exchanges where both ends are under your control, or agreed
bilaterally. Where a bank, payment channel or partner specifies a format,
use the format they specify. The keys themselves are standard: PKCS#8 and
SubjectPublicKeyInfo PEM or DER, and OpenSSH where one exists. `convert`
moves between them.

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
| `--progress` | Report progress on stderr while streaming |
| `--segment-size BYTES` | Plaintext bytes per encrypted segment (default 256 KiB) |
| `--max-size BYTES` | Refuse *buffered* input above this (default 64 MiB). File streaming is unbounded |

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

## Container sandbox

[`scripts/sandbox.sh`](./scripts/sandbox.sh) runs the tool in a throwaway
container with Podman or Docker. The host needs a container engine and nothing
else: no Python and no package installation.

```bash
./scripts/sandbox.sh --json capabilities                 # the CLI
./scripts/sandbox.sh scan . --fail-on-finding
./scripts/sandbox.sh --target examples                   # every example
./scripts/sandbox.sh --target mcp                        # the MCP server, on stdio
```

The container has no network, a read-only root filesystem, no Linux
capabilities and no route to privilege escalation. It runs as a non-root user
and sees one host directory: the current one, mounted read-only for the MCP
server and not mounted at all for the examples. Passphrases are forwarded by
variable name, never on the command line. Full details, including what the
sandbox does not protect against, are in [docs/SANDBOX.md](./docs/SANDBOX.md).

---

## MCP server

[`encryption-helper-mcp`](./packages/encryption-helper-mcp/README.md) is a
[Model Context Protocol](https://modelcontextprotocol.io) server that lets an
AI assistant answer migration-scoping questions: which keys under a directory
are affected, when, and what replaces them.

It is **read-only by design**. No tool can generate, encrypt, decrypt or sign,
and none accepts a passphrase, because an assistant's context leaves your
machine. Tests enforce this boundary.

```bash
pip install encryption-helper-mcp
encryption-helper-mcp --root /path/to/inspect
```

> [!CAUTION]
> Scan results include file paths and certificate subjects, and those are sent
> to whichever model the assistant uses. Point the server's root directory at the narrowest
> directory that answers the question, and follow your organisation's policy
> on what may be shared with an AI service.

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
| Device destinations | `--out /dev/null` writes through directly; a temporary file is never renamed over a device node |

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

Measured on one machine (24 cores, AES-NI); indicative, not a guarantee.

### File encryption, 5 MB to 5 GB

Encryption is **segmented**, so memory is bounded by the segment size rather
than the payload.

| Size | Encrypt | Decrypt | Throughput | Peak RSS |
| ---- | ------- | ------- | ---------- | -------- |
| 5 MB | 0.06 s | 0.07 s | 83 MB/s | 30 MB |
| 50 MB | 0.09 s | 0.09 s | 556 MB/s | 30 MB |
| 250 MB | 0.24 s | 0.19 s | ~1.2 GB/s | 29 MB |
| 1 GB | 0.69 s | 0.59 s | ~1.6 GB/s | 29 MB |
| 2 GB | 1.33 s | 1.19 s | ~1.6 GB/s | 30 MB |
| 5 GB | 3.63 s | 3.14 s | ~1.5 GB/s | **30 MB** |

**Memory is flat.** A 5 GB file uses the same ~30 MB as a 5 MB one. The small
sizes look slow in MB/s only because ~60 ms of that is Python interpreter
startup, which is fixed cost rather than throughput.

### Under concurrent load

16 parallel 50 MB encryptions, wall clock:

| Concurrency | Wall | Aggregate |
| ----------- | ---- | --------- |
| 1 | 0.29 s | 172 MB/s |
| 4 | 0.24 s | 833 MB/s |
| 8 | 0.20 s | ~2.0 GB/s |
| 16 | 0.39 s | ~2.1 GB/s |

### Primitives

| Operation | Cost |
| --------- | ---- |
| ML-KEM-768 keygen | ~0.05 ms |
| ML-DSA-65 keygen | ~0.13 ms |
| X25519 / Ed25519 keygen | ~0.02 ms |
| RSA-2048 / RSA-3072 keygen | ~17 ms / ~87 ms |
| ML-DSA-65 sign / verify | ~0.5 ms / ~0.8 ms |
| Ed25519 sign | ~0.11 ms |
| RSA private key **load** | ~22 ms — the library validates the primes |
| CLI process startup | ~60 ms |

**Post-quantum is not the slow option.** ML-KEM generates a key pair roughly
1,700× faster than RSA-3072, and encapsulation is cheaper than RSA-OAEP. The
cost is size: ML-KEM ciphertexts carry 1,088 bytes of encapsulation against
RSA's 256, and an ML-DSA-65 signature is 3,309 bytes against Ed25519's 64.

> [!NOTE]
> **What "fast" can mean here.** Raw AES-GCM on this machine peaks at
> ~4.1 GiB/s, so a 5 GB pass costs **at least 1.2 s** before any file I/O.
> Sub-second operation is achievable up to roughly 1–2 GB; beyond that you are
> bounded by hardware, not by this code. Operations are CPU-bound and
> independent, so throughput scales with cores — run them in parallel rather
> than expecting one to go faster.

Run them yourself: `python benches/bench_crypto.py --quick`

---

## Development

```bash
poetry install
poetry run pre-commit install

make check                                      # everything CI runs
poetry run pytest                               # the suite, 100% branch coverage
poetry run ruff check . && poetry run ruff format --check .
poetry run mypy --strict encryption_helper
poetry run bandit -c pyproject.toml -r encryption_helper
```

```bash
make examples                                   # every example runs in CI
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

## Support

This is open-source software, provided under the Apache License 2.0 without
warranty. It is not an HSBC banking product or service, and using it does not
change the terms of any agreement you have with HSBC.

Questions and bugs go to [GitHub issues](https://github.com/hsbc/encryption-helper-python/issues);
see [SUPPORT.md](./SUPPORT.md). Report vulnerabilities privately through
[SECURITY.md](./SECURITY.md). **Never post keys, passphrases, account details
or client data in an issue.**

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
