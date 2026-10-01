# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Encrypt data to a public key and decrypt it again.

Encryption is hybrid: a random AES-256-GCM content key protects the data, and
RSA-OAEP-SHA256 wraps only that key. Data of any size therefore works -- the
RSA modulus never has to hold the message.

Run:
    python examples/02_encrypt_and_decrypt.py
"""

from __future__ import annotations

from encryption_helper import DecryptionError, decrypt, encrypt, generate_rsa


def main() -> int:
    """Round-trip a payload far larger than the RSA modulus could carry."""
    key = generate_rsa(key_size=2048)
    public = key.public_key()

    # A 100 KiB payload. Direct RSA encryption caps out around 200 bytes.
    plaintext = b"sensitive configuration\n" * 4300
    blob = encrypt(public, plaintext)
    print(f"plaintext:  {len(plaintext):,} bytes")
    print(f"ciphertext: {len(blob):,} bytes")

    assert decrypt(key, blob) == plaintext
    print("round trip: OK")

    # Associated data binds a ciphertext to its context. The same value must
    # be supplied to decrypt, so a message cannot be replayed elsewhere.
    bound = encrypt(public, b"transfer approved", associated_data=b"account-42")
    assert decrypt(key, bound, associated_data=b"account-42") == b"transfer approved"
    try:
        decrypt(key, bound, associated_data=b"account-99")
    except DecryptionError as exc:
        print(f"replay in another context rejected: {exc}")
    else:  # pragma: no cover - would be a security failure
        msg = "associated data was not enforced"
        raise AssertionError(msg)

    # Any modification is detected; decryption fails closed.
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    try:
        decrypt(key, bytes(tampered))
    except DecryptionError:
        print("tampered ciphertext rejected")
    else:  # pragma: no cover - would be a security failure
        msg = "tampering was not detected"
        raise AssertionError(msg)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
