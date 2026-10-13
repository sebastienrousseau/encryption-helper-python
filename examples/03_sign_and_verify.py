# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Sign a message and verify the signature.

The scheme is chosen from the key type, so a key cannot be paired with an
inappropriate algorithm: RSA uses PSS with SHA-256, Ed25519 uses PureEdDSA,
and ECDSA uses SHA-256.

Run:
    python examples/03_sign_and_verify.py
"""

from __future__ import annotations

from encryption_helper import (
    SignatureVerificationError,
    generate_ecdsa,
    generate_ed25519,
    generate_rsa,
    is_valid_signature,
    sign,
    verify,
)


def main() -> int:
    """Sign and verify with each supported algorithm."""
    manifest = b"release-1.2.3 sha256:0f1e2d..."

    for label, key in (
        ("RSA-PSS ", generate_rsa(key_size=2048)),
        ("Ed25519 ", generate_ed25519()),
        ("ECDSA   ", generate_ecdsa(curve="p256")),
    ):
        signature = sign(key, manifest)
        # `verify` returns None on success and raises on failure, so a caller
        # who forgets to check the result still fails closed.
        verify(key.public_key(), signature, manifest)
        print(f"{label} signature ({len(signature):>3} bytes): valid")

        # A single altered byte invalidates it.
        assert not is_valid_signature(key.public_key(), signature, manifest + b"!")

    # `verify` raises rather than returning a value you might ignore.
    key = generate_ed25519()
    try:
        verify(key.public_key(), b"not a signature", manifest)
    except SignatureVerificationError as exc:
        print(f"invalid signature rejected: {exc}")
    else:  # pragma: no cover - would be a security failure
        msg = "an invalid signature verified"
        raise AssertionError(msg)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
