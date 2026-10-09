# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Post-quantum encryption and signing with ML-KEM and ML-DSA.

NIST IR 8547 (initial public draft) disallows RSA and the elliptic curves
after 2035, and deprecates 112-bit keys such as RSA-2048 after 2030. For key
material that must outlive those dates, use ML-KEM (FIPS 203) for encryption
and ML-DSA (FIPS 204) for signing.

Run:
    python examples/05_post_quantum.py
"""

from __future__ import annotations

from _workspace import workspace
from encryption_helper import (
    POST_QUANTUM,
    QUANTUM_VULNERABLE,
    DecryptionError,
    decrypt,
    encrypt,
    generate_mldsa,
    generate_mlkem,
    sign,
    verify,
    write_key_pair,
)
from encryption_helper.crypto.envelope import KEM_MLKEM768


def main() -> int:
    """Encrypt with ML-KEM and sign with ML-DSA."""
    destination = workspace()

    print(f"post-quantum:       {', '.join(sorted(POST_QUANTUM))}")
    print(f"disallowed after 2035: {', '.join(sorted(QUANTUM_VULNERABLE))}")
    print()

    # --- Encryption: ML-KEM-768 --------------------------------------------
    kem = generate_mlkem(level=768)
    paths = write_key_pair(kem, destination, name="recipient", passphrase=b"a secret")
    print(f"ML-KEM key:  {paths.private_key_path.name}  ({paths.fingerprint})")

    # Hybrid encryption: ML-KEM agrees a secret, HKDF derives the content key,
    # AES-256-GCM protects the data. The RSA modulus limit does not apply, so
    # payload size is not constrained by the key.
    plaintext = b"configuration secret\n" * 5000
    blob = encrypt(kem.public_key(), plaintext)
    assert blob[5] == KEM_MLKEM768, "the container records its mechanism"
    print(f"             {len(plaintext):,} B -> {len(blob):,} B, kem_id={blob[5]}")
    assert decrypt(kem, blob) == plaintext
    print("             round trip OK")

    # Any modification fails closed.
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    try:
        decrypt(kem, bytes(tampered))
    except DecryptionError:
        print("             tampered ciphertext rejected")
    else:  # pragma: no cover - would be a security failure
        msg = "tampering was not detected"
        raise AssertionError(msg)

    # --- Signing: ML-DSA ---------------------------------------------------
    print()
    for level in (44, 65, 87):
        dsa = generate_mldsa(level=level)
        signature = sign(dsa, b"release manifest")
        verify(dsa.public_key(), signature, b"release manifest")
        print(f"ML-DSA-{level:<3}   signature {len(signature):>5} B  valid")

    print()
    print("ML-DSA signatures are far larger than Ed25519's 64 bytes. That is")
    print("the cost of the post-quantum assumption, and it is unavoidable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
