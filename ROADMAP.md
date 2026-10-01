<!-- SPDX-License-Identifier: Apache-2.0 -->

# Roadmap

What is planned, what is deliberately not, and why. Dates are intentions, not
commitments.

## Shipped in 0.0.2

- Post-quantum encryption (ML-KEM-768/1024, FIPS 203) and signing
  (ML-DSA-44/65/87, FIPS 204)
- X25519 ephemeral-static encryption and Ed448 signing
- Self-describing container with per-mechanism identifiers, so a new algorithm
  never breaks an old ciphertext
- `capabilities` command reporting the NIST IR 8547 horizon per algorithm
- Owner-only key storage, atomic writes, two-layer rollback, destination
  aliasing checks
- Passphrase protection with pinned source semantics
- 100% statement and branch coverage, fuzzing, documentation-accuracy tests

## Next

### Streaming encryption

Encryption holds the whole message in memory; peak usage is ~4× the payload.
The CLI currently refuses input above `--max-size` rather than risking an
out-of-memory kill.

The fix is a chunked AEAD: 64 KiB frames, per-frame nonce from a counter, and
the frame index in the associated data so reordering and truncation are
detected. That would be a new `aead_id`, leaving existing containers readable.

This is the one remaining piece of genuinely subtle cryptography here. Frame
counters and truncation resistance are where streaming AEAD designs fail, so
it needs test vectors and external review before it ships.

### Release to PyPI

The package has never been published. Trusted Publishing and build attestation
are configured; the release workflow is untested on real runners.

### Hosted API documentation

`mkdocstrings` over the existing docstrings. Everything public is already
documented with Google-style `Args`/`Returns`/`Raises`.

## Under consideration

| Item | Rationale | Blocker |
| ---- | --------- | ------- |
| Hybrid X25519+ML-KEM | Belt and braces if ML-KEM is weakened | Needs a composite key container and external review |
| SLH-DSA (FIPS 205) | Hash-based signatures, different assumptions | Not yet in `cryptography` |
| CSR and self-signed certificates | Common adjacent need | Scope — may belong in a separate package |
| Native Windows ACL support | POSIX modes are advisory there | Needs a Windows maintainer and real CI |

## Deliberately not planned

These would add cost without serving the tool's purpose. If one is genuinely
wanted it is a different product, not this one's roadmap.

- **Tracing and metrics.** This is a CLI that runs for ~40 ms and exits.
  There is no request to trace and no process to scrape. `--log-level` and
  `--json` are the right ceiling.
- **async/await.** There is nothing to overlap; key generation is CPU-bound.
- **Caching tiers.** No repeated work to cache.
- **A plugin architecture.** No third-party algorithms to host, and a plugin
  boundary in a cryptographic library is an attack surface.
- **HSM or KMS backends.** Contradicts the local-first design, and competes
  with products built for it.

## Non-goals

This package protects keys with filesystem permissions. It is not an HSM, a
KMS, a secrets manager, or a PKI. It will not grow into one.
