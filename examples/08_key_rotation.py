# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Rotate a key pair without losing access to existing ciphertext.

Rotation is a mandatory control in most organisations, and migrating from a
classical algorithm to a post-quantum one is the same exercise. The property
that governs it is simple and easy to get wrong: a ciphertext can be
decrypted only by the key it was encrypted to. This library does not
re-encrypt data and does not support multiple recipients, so the previous
private key must be retained for as long as any ciphertext under it must stay
readable.

This example shows the full sequence, including the failure that occurs if
the old key is retired too early.

Run:
    python examples/08_key_rotation.py
"""

from __future__ import annotations

from _workspace import workspace
from encryption_helper import (
    decrypt,
    encode_private_key,
    encode_public_key,
    encrypt,
    fingerprint_sha256,
    generate,
)
from encryption_helper.errors import DecryptionError


def main() -> int:
    """Rotate from RSA to ML-KEM, retaining the old key for old data."""
    directory = workspace()

    # --- Before rotation ---------------------------------------------------
    # An existing RSA key, with data already encrypted to it.
    old = generate("rsa", key_size=2048)
    archive = encrypt(old.public_key(), b"an invoice from last year")
    print(f"1. Existing key   rsa-2048   {fingerprint_sha256(old.public_key())}")
    print("   Historical data encrypted under it.")

    # --- Step 1: generate the replacement alongside the old one ------------
    # Use a distinct name rather than replacing in place. On the command line
    # that is `--name`, not `--force`: --force would back the old key up to a
    # timestamped sibling, which is recoverable but easy to lose track of.
    new = generate("mlkem")
    old_path = directory / "payments-2026.pem"
    new_path = directory / "payments-2027.pem"
    old_path.write_bytes(encode_private_key(old, passphrase=b"a-long-passphrase"))
    new_path.write_bytes(encode_private_key(new, passphrase=b"a-long-passphrase"))
    (directory / "payments-2027.pub").write_bytes(encode_public_key(new.public_key()))
    print(f"2. Replacement    ml-kem-768 {fingerprint_sha256(new.public_key())}")
    print("   Record the new fingerprint; it is how a counterparty confirms")
    print("   they have the right key.")

    # --- Step 2: senders switch to the new public key ----------------------
    current = encrypt(new.public_key(), b"this quarter's invoice")
    print("3. New data is encrypted to the replacement.")

    # --- Step 3: both must remain readable --------------------------------
    print(f"4. Old data via old key: {decrypt(old, archive)!r}")
    print(f"   New data via new key: {decrypt(new, current)!r}")

    # --- The mistake to avoid ---------------------------------------------
    # Retiring the old private key before re-encrypting its data makes that
    # data unrecoverable. There is no recovery path; this is why step 5 of a
    # rotation is "retain", not "delete".
    try:
        decrypt(new, archive)
    except DecryptionError:
        print("5. Old data via NEW key: refused, as it must be.")
        print("   Retiring the old private key now would make the historical")
        print("   archive permanently unreadable.")
    else:  # pragma: no cover - would be a correctness failure
        msg = "a key decrypted a container it was not the recipient of"
        raise AssertionError(msg)

    # --- Step 4: re-encrypt from plaintext, then retire -------------------
    recovered = decrypt(old, archive)
    reencrypted = encrypt(new.public_key(), recovered)
    print("6. Re-encrypted the archive from plaintext under the new key.")
    print(f"   Readable with the new key: {decrypt(new, reencrypted)!r}")
    print("   Only now can the old private key be retired.")

    print()
    print("Summary of the procedure:")
    print("  1. Generate the replacement alongside the existing pair.")
    print("  2. Distribute the new public key; record its fingerprint.")
    print("  3. Switch senders to it.")
    print("  4. Re-encrypt retained data from plaintext.")
    print("  5. Retire the old private key only once nothing needs it.")
    print()
    print("`encryption-helper scan` reports which files are still protected")
    print("by the old algorithm, and `inspect` reports it for one file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
