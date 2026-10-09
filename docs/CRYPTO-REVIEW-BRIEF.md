<!-- SPDX-License-Identifier: Apache-2.0 -->

# Cryptographic review brief

A scoped brief for an external reviewer. The intent is that a competent
cryptographer can audit this package in a few hours rather than first spending
those hours working out what to look at.

**Reviewing:** `encryption-helper` v0.0.2
**Primitives:** all from [`cryptography`](https://github.com/pyca/cryptography)
46+ (OpenSSL / Rust). **No primitive is implemented here.**
**What is implemented here:** key encapsulation selection, a KDF binding, a
container format, and segment framing.

---

## 1. What is in scope

Four things, in descending order of risk. Everything else is key handling and
filesystem work, covered by the test suite and not cryptographic.

### 1.1 Content-key derivation and KEM binding — `crypto/envelope.py`

```python
HKDF(
    algorithm=SHA256,
    length=32,
    salt=None,
    info=b"encryption-helper/v1 content-key" + bytes([kem_id]),
)
```

- `salt=None` means HKDF-Extract runs with a zero salt. The input is a KEM
  shared secret, which is already uniform; is that acceptable, or should the
  encapsulation be mixed in as salt?
- The `kem_id` byte is appended to `info` for domain separation, so one shared
  secret cannot derive the same content key under two mechanism labels. Is a
  single byte of `info` sufficient separation?
- **RSA does not use the KDF at all.** It wraps a random 32-byte content key
  directly with OAEP. The others derive. Is that asymmetry a problem?

### 1.2 Mechanism selection — `crypto/envelope.py`

| `kem_id` | Mechanism | Encapsulation |
| :------: | --------- | ------------- |
| 1 | RSA-OAEP-SHA256 | wrapped content key |
| 2 | ML-KEM-768 | KEM ciphertext |
| 3 | ML-KEM-1024 | KEM ciphertext |
| 4 | X25519 + HKDF | ephemeral public key |

- X25519 is ephemeral-static: a fresh ephemeral key agrees with the
  recipient's static key, HKDF derives the content key, the ephemeral public
  key is the encapsulation. **No contributory behaviour check and no
  recipient-key validation** beyond what `cryptography` does. Sufficient?
- ML-KEM uses implicit rejection, so decapsulating with the wrong key yields
  an unrelated secret rather than failing; the AEAD tag rejects it one step
  later. Is deferring to the tag acceptable?
- `kem_id` 3 is ML-KEM-1024 with a 256-bit content key, i.e. the KEM's
  security level exceeds the AEAD's. Intentional; worth confirming it is not
  misleading.

### 1.3 Segment framing — `crypto/streaming.py`

Tink's STREAM:

```text
nonce = prefix (7 bytes) ‖ segment number (4, big endian) ‖ final (1 byte)
```

- Associated data for **every** segment is
  `header ‖ encapsulation ‖ stream_header ‖ caller_aad`, constant across
  segments. Position is bound only through the nonce. Tink does this; please
  confirm it holds here.
- The 4-byte counter caps a stream at 2³²−1 segments. At the 64 MiB maximum
  segment that is 256 PiB; at the 4 KiB minimum it is 16 TiB. Over-run raises
  rather than wrapping.
- The segment size is stored in the clear in `stream_header`, which is
  authenticated. An attacker can therefore cause a *rejection* by altering it
  but not a misparse. Confirm.
- `decrypt_stream` writes each segment only after its tag verifies, but
  earlier segments are already written when a later one fails. The CLI
  mitigates with a temporary file and rename. Is the library-level contract
  stated clearly enough?

### 1.4 Container format — both modes

```text
0      4   5      6       7        8      10
┌──────┬───┬──────┬───────┬────────┬───────┬──────────┬───────┬────────┐
│ MAGIC│ver│kem_id│aead_id│reserved│enc_len│ encap.   │ nonce │ ct+tag │
└──────┴───┴──────┴───────┴────────┴───────┴──────────┴───────┴────────┘
```

- Every framing byte is authenticated as associated data.
- `enc_len` is a uint16, so the encapsulation is capped at 65,535 bytes.
  ML-KEM-1024 needs 1,568. Headroom is adequate but finite.
- Unknown `kem_id` or `aead_id` is rejected with a message naming what this
  build understands.

---

## 2. Out of scope

Primitive implementations; key file permissions, atomicity and rollback
(tested, not cryptographic); passphrase sourcing; the CLI; packaging.

---

## 3. Questions we most want answered

1. Is the HKDF binding sufficient to prevent cross-mechanism and
   cross-container key reuse?
2. Does the STREAM framing as implemented actually provide truncation and
   reordering resistance, or is there a gap between this and Tink's?
3. Is the RSA path's bypass of the KDF a weakness or merely an inconsistency?
4. Is any error message distinguishable enough to serve as an oracle? The
   intent is that wrong key, corrupt container and tampered ciphertext are
   indistinguishable.
5. Is `salt=None` in HKDF-Extract appropriate for these inputs?

---

## 4. What already exists to help

- `tests/crypto/test_envelope.py`, `tests/crypto/test_streaming.py` — tamper,
  truncation, reordering, dropping, duplication and cross-key tests
- `fuzz/` — parser fuzz targets; the harnesses are mutation-tested, so
  planting a defect is caught within two iterations with a reproducible seed
- `ARCHITECTURE.md` — dependency direction, invariants, format diagrams
- 100% statement and branch coverage; `mypy --strict`; `bandit` clean

## 5. Known gaps we are not asking about

- **Hybrid X25519+ML-KEM is deliberately absent.** A composite KEM needs a
  composite key container and we declined to invent one unreviewed. If you
  think the hybrid is necessary rather than optional, say so.
- Keys are ordinary Python objects: not locked into RAM, not zeroed. Stated in
  the threat model.
- Windows permissions are advisory; POSIX modes do not express NTFS ACLs.
