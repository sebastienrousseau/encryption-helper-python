<!-- SPDX-License-Identifier: Apache-2.0 -->

# Architecture

How this package is put together, and why. For usage see
[README.md](./README.md); for development workflow see
[CONTRIBUTING.md](./CONTRIBUTING.md).

## Dependency direction

The single rule: **secret material flows one way, and presentation lives at
the edge.**

```text
cli.py                  argument parsing, prompts, output, exit codes
   │                    the ONLY module that prints or configures logging
   ▼
keys/generate.py        produce a key object. no I/O, no logging
   │
   ├──► keys/serialize.py     key object  ->  bytes
   │
   ├──► crypto/envelope.py    hybrid encryption (KEM + AES-256-GCM)
   │
   ├──► crypto/signing.py     sign / verify
   │
   ▼
keys/store.py           the pair-write transaction
   │
   ▼
_io.py                  permissions, atomicity, rollback
```

Nothing below `cli.py` prints. `__init__.py` installs a `NullHandler` and
configures nothing, so a host application keeps control of logging.

## The invariant

```text
PRIVATE KEY MATERIAL AND PASSPHRASES
      may exist in  ─── cryptographic objects
                    ─── serialised bytes in flight
                    ─── the file they were explicitly written to
      never reach   ─── stdout
                    ─── stderr
                    ─── a log record, at any level
                    ─── an exception message
                    ─── the argparse namespace
```

`tests/test_security_regressions.py` asserts this across every log level, for
every passphrase source, and for `repr()` of the result object and the parsed
arguments.

## Why generation, serialisation and storage are separate

`generate_*` returns a live key and performs no I/O. That is what makes the
library usable from a service that never touches a disk, and what makes the
cryptography testable without a filesystem.

The alternative — one function that generates, serialises, writes, logs and
prints — is what version 0.0.1 did. It could not be used in a server, could
not be tested without mocking `open`, and printed the key.

## The pair-write transaction

Ordinary filesystems offer no cross-file transaction. `keys/store.py`
approximates one in three steps:

1. **Pre-flight.** Both destinations are checked before anything is written —
   existence, directories, symlinks, hard-link aliasing, path collision.
2. **Validation.** The serialised halves are parsed back and their public
   parts compared. A mismatched pair cannot reach the disk.
3. **Rollback.** Two layers, deliberately separated:

```text
_io.secure_write_bytes()        displaced the old file  ->  restores it itself
       │                        restoration is part of the failed write
       ▼
keys/store.write_key_pair()     private write succeeded, public failed
                                ->  undoes the private write
```

The caller never has to repair a failure that happened inside the writer. The
result: after any recoverable failure the directory holds the complete old
pair, the complete new pair, or no pair — never a mixed one.

## Cryptographic agility

The container header is the agility hook:

```text
  0      4   5      6       7        8        10
  ┌──────┬───┬──────┬───────┬────────┬─────────┬─────────┬──────────────┐
  │ MAGIC│ver│kem_id│aead_id│reserved│ enc_len │ encap.  │ nonce │ ct+tag│
  └──────┴───┴──────┴───────┴────────┴─────────┴─────────┴──────────────┘
```

Every byte of framing is authenticated as AEAD associated data, so altering
the header is detected as tampering rather than reinterpreted.

Adding a mechanism means allocating a `kem_id` and adding a branch. It never
means changing an existing identifier, so old ciphertexts stay readable. The
identifier is also mixed into the HKDF `info`, so one shared secret cannot
derive the same content key under two labels.

| `kem_id` | Mechanism | Encapsulation holds |
| :------: | --------- | ------------------- |
| 1 | RSA-OAEP-SHA256 | the wrapped content key |
| 2 | ML-KEM-768 | the KEM ciphertext |
| 3 | ML-KEM-1024 | the KEM ciphertext |
| 4 | X25519 + HKDF | the ephemeral public key |

RSA wraps a content key directly, so no KDF is involved. The others agree a
shared secret and derive the content key from it.

## Error taxonomy

```text
EncryptionHelperError
├── InvalidArgumentError (also ValueError)
│   └── UnsupportedAlgorithmError
├── KeyGenerationError
├── KeyPairValidationError
├── KeyExistsError
├── KeyWriteError
├── KeyReadError
├── DecryptionError
└── SignatureVerificationError
```

The split between `InvalidArgumentError` and `DecryptionError` is deliberate:
a key that can never decrypt is a programming mistake, while a key that could
decrypt but does not match this container is indistinguishable from a tampered
header and is therefore a property of the data.

`KeyReadError` never distinguishes a wrong passphrase from a corrupt file.
That distinction is only useful to someone probing a key they should not have.

## Known limits

- **No streaming.** Peak memory is ~4× the payload. The CLI refuses input
  above `--max-size` rather than being OOM-killed mid-write.
- **No hybrid KEM.** A composite X25519+ML-KEM key needs a composite key
  container; inventing one without external review would be false confidence.
- **Windows permissions are advisory.** NTFS uses ACLs, which `os.chmod`
  cannot express. Documented, with platform tests skipped rather than faked.
