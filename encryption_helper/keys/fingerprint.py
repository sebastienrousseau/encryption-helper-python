# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Public key fingerprints.

For key types OpenSSH understands -- RSA, Ed25519, Ed448 and ECDSA -- the
fingerprint is byte-identical to ``ssh-keygen -lf``: the SHA-256 digest of the
OpenSSH wire encoding, base64 without padding, prefixed ``SHA256:``.

ML-KEM, ML-DSA and X25519 have no OpenSSH encoding, so those are fingerprinted
over the DER SubjectPublicKeyInfo instead and carry a different prefix,
``SHA256-SPKI:``. The prefixes differ deliberately: two fingerprints computed
over different encodings must never look comparable.

Fingerprints exist so a key can be identified, compared and logged without
handling the key itself. The CLI reports one after generating a key pair,
in place of printing the key.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from ..errors import UnsupportedAlgorithmError
from .serialize import encode_public_key

__all__ = ["OPENSSH_PREFIX", "SPKI_PREFIX", "fingerprint_sha256"]

#: Prefix for fingerprints that match ``ssh-keygen -lf``.
OPENSSH_PREFIX = "SHA256:"

#: Prefix for fingerprints taken over DER SubjectPublicKeyInfo, used where no
#: OpenSSH encoding exists.
SPKI_PREFIX = "SHA256-SPKI:"


def _digest(data: bytes) -> str:
    """Base64 a SHA-256 digest, without padding."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")


def fingerprint_sha256(key: PublicKeyTypes) -> str:
    """Return the OpenSSH-style SHA-256 fingerprint of a public key.

    Args:
        key: Public key to fingerprint.

    Returns:
        ``SHA256:<base64>`` for key types OpenSSH understands, matching
        ``ssh-keygen -lf``; otherwise ``SHA256-SPKI:<base64>`` taken over the
        DER SubjectPublicKeyInfo.

    Raises:
        UnsupportedAlgorithmError: If the key cannot be serialised at all.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> fp = fingerprint_sha256(generate_ed25519().public_key())
        >>> fp.startswith("SHA256:")
        True
        >>> len(fp)
        50
    """
    try:
        openssh = encode_public_key(key, fmt="openssh")
    except UnsupportedAlgorithmError:
        # No OpenSSH encoding for this key type -- ML-KEM, ML-DSA and X25519.
        # Fall back to SPKI under a distinct prefix.
        return SPKI_PREFIX + _digest(encode_public_key(key, fmt="der"))

    # The OpenSSH public key line is "<type> <base64 blob> [comment]". The
    # fingerprint is taken over the decoded blob, not the whole line.
    parts = openssh.split()
    expected_parts = 2
    if len(parts) < expected_parts:
        msg = f"Unexpected OpenSSH encoding for a {type(key).__name__}."
        raise UnsupportedAlgorithmError(msg)

    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError) as exc:
        msg = f"Could not decode the OpenSSH encoding of a {type(key).__name__}."
        raise UnsupportedAlgorithmError(msg) from exc

    return OPENSSH_PREFIX + _digest(blob)
