# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Exchange a signed, encrypted file with a counterparty.

The most common reason an organisation needs asymmetric keys is sending files
to another organisation: payment instructions, statements, payroll and
reconciliation reports. Two controls protect such a file, and most incidents
come from skipping one of them:

1. **Verify the counterparty's public key out of band.** Encryption to a
   key an attacker substituted is encryption to the attacker. Before you
   trust a received public key, compare its fingerprint with a value obtained
   over a separate channel, such as a call to a known contact or an
   authenticated portal.
2. **Sign, then encrypt.** Encryption gives confidentiality. Only the
   sender's signature shows the file came from them and was not altered.

The example plays both parties: a sender with an ML-DSA signing key and a
receiver with an ML-KEM encryption key. Both are post-quantum, because files
such as these are often retained for years.

.. note::
   The ciphertext uses this library's own container format, not OpenPGP or
   CMS. Both parties need ``encryption-helper`` 0.0.2 or later. Where a
   counterparty or channel specifies a format, use that format.

Run:
    python examples/10_counterparty_file_exchange.py
"""

from __future__ import annotations

import hmac

from _workspace import workspace
from encryption_helper import (
    DecryptionError,
    SignatureVerificationError,
    decrypt,
    encode_public_key,
    encrypt,
    fingerprint_sha256,
    generate_mldsa,
    generate_mlkem,
    load_public_key,
    sign,
    verify,
)

# Illustrative content only. No real account or institution is represented.
PAYMENT_FILE = b"""<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09">
  <CstmrCdtTrfInitn>
    <GrpHdr><MsgId>EXAMPLE-0001</MsgId><NbOfTxs>1</NbOfTxs></GrpHdr>
  </CstmrCdtTrfInitn>
</Document>
"""


def fingerprints_match(received: str, expected: str) -> bool:
    """Compare two fingerprints without leaking where they first differ."""
    return hmac.compare_digest(received.encode(), expected.encode())


def main() -> int:
    """Run the exchange from both sides, then three ways it can go wrong."""
    outbox = workspace()

    # -- Onboarding: each party generates a key and publishes the public half.
    sender_key = generate_mldsa(level=65)
    receiver_key = generate_mlkem(level=768)

    # What travels between the parties is the PEM text, never a key object.
    sender_public_pem = encode_public_key(sender_key.public_key())
    receiver_public_pem = encode_public_key(receiver_key.public_key())

    # The fingerprint each party reads to the other over a separate channel.
    receiver_fingerprint_by_phone = fingerprint_sha256(receiver_key.public_key())
    sender_fingerprint_by_phone = fingerprint_sha256(sender_key.public_key())

    # -- Sender: verify the receiver's key before using it.
    receiver_public = load_public_key(receiver_public_pem)
    if not fingerprints_match(
        fingerprint_sha256(receiver_public), receiver_fingerprint_by_phone
    ):
        msg = "receiver key does not match the fingerprint confirmed by phone"
        raise SystemExit(msg)
    print(f"sender:   receiver key verified  {receiver_fingerprint_by_phone}")

    # Sign the file itself, then encrypt it. The signature travels alongside.
    signature = sign(sender_key, PAYMENT_FILE)
    ciphertext = encrypt(receiver_public, PAYMENT_FILE)
    (outbox / "payments.xml.enc").write_bytes(ciphertext)
    (outbox / "payments.xml.sig").write_bytes(signature)
    print(
        f"sender:   sent {len(ciphertext):,} encrypted bytes "
        f"and a {len(signature):,}-byte signature"
    )

    # -- Receiver: decrypt, then verify the signature against a sender key
    #    that was itself checked against its out-of-band fingerprint.
    sender_public = load_public_key(sender_public_pem)
    if not fingerprints_match(
        fingerprint_sha256(sender_public), sender_fingerprint_by_phone
    ):
        msg = "sender key does not match the fingerprint confirmed by phone"
        raise SystemExit(msg)
    received = decrypt(receiver_key, (outbox / "payments.xml.enc").read_bytes())
    verify(sender_public, (outbox / "payments.xml.sig").read_bytes(), received)
    print("receiver: decrypted and verified; the file is from the sender, unaltered")

    # -- What the controls stop.

    # 1. A substituted public key. Someone in the path replaces the
    #    receiver's PEM with their own. The out-of-band check catches it
    #    before anything is encrypted.
    impostor_pem = encode_public_key(generate_mlkem(level=768).public_key())
    impostor = load_public_key(impostor_pem)
    if fingerprints_match(fingerprint_sha256(impostor), receiver_fingerprint_by_phone):
        msg = "a substituted key matched the confirmed fingerprint"
        raise AssertionError(msg)
    print("stopped:  substituted public key (fingerprint mismatch)")

    # 2. A modified ciphertext. Authenticated encryption rejects it outright.
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01
    try:
        decrypt(receiver_key, bytes(tampered))
    except DecryptionError:
        print("stopped:  modified ciphertext (integrity check failed)")
    else:  # pragma: no cover - would be a security failure
        msg = "a modified ciphertext decrypted"
        raise AssertionError(msg)

    # 3. A file encrypted correctly, but by someone else. Anyone holding the
    #    receiver's public key can encrypt to it, so decryption alone proves
    #    nothing about origin. Only the signature does.
    forger = generate_mldsa(level=65)
    forged = encrypt(receiver_public, PAYMENT_FILE.replace(b"0001", b"9999"))
    forged_signature = sign(forger, decrypt(receiver_key, forged))
    try:
        verify(sender_public, forged_signature, decrypt(receiver_key, forged))
    except SignatureVerificationError:
        print("stopped:  file from an unknown signer (signature did not verify)")
    else:  # pragma: no cover - would be a security failure
        msg = "a forged file verified"
        raise AssertionError(msg)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
