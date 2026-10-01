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

### AEAD modes

`aead_id` selects how the payload is protected, independently of the KEM:

| `aead_id` | Mode | Memory |
| :-------: | ---- | ------ |
| 1 | AES-256-GCM, one shot | proportional to payload |
| 2 | AES-256-GCM, segmented | bounded by segment size |

Segment framing is **Tink's STREAM**, not a new design:

```text
nonce = prefix (7 bytes) ‖ segment number (4, big endian) ‖ final (1 byte)
```

One 12-byte value defends three properties:

- the **random prefix** prevents nonce reuse across messages under one key;
- the **segment number** prevents reordering and dropping, because moving a
  segment changes the nonce it must open with;
- the **final flag** prevents truncation -- the last segment is marked as
  last, so stopping early fails rather than yielding a shorter plaintext.

Truncation resistance is what a naive chunked AEAD loses. Each segment is
individually authenticated, so forging one is infeasible, but without a final
marker an attacker can simply stop and the recipient cannot tell.

`decrypt_stream` writes each segment only after its tag verifies, but earlier
segments are already written when a later one fails. The CLI therefore writes
to a temporary file in the destination directory and renames on success, so a
caller never observes a partial plaintext.

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

- **Throughput is hardware-bound, not code-bound.** Raw AES-GCM peaks at
  ~4.1 GiB/s here, so a 5 GB pass costs at least 1.2 s. Operations are
  CPU-bound and independent; parallelism, not micro-optimisation, is the
  lever. Sixteen concurrent 50 MB jobs sustain ~2.1 GB/s aggregate.
- **~60 ms of interpreter startup** dominates small operations. A 5 MB
  encryption takes 60 ms, essentially all of it `import`. Deferring the
  `importlib.metadata` lookup for `__version__` saved ~9.5 ms of that; the
  remainder is `logging` and `cryptography`, both unavoidable.
- **No hybrid KEM.** A composite X25519+ML-KEM key needs a composite key
  container; inventing one without external review would be false confidence.
- **Windows permissions are advisory.** NTFS uses ACLs, which `os.chmod`
  cannot express. Documented, with platform tests skipped rather than faked.
