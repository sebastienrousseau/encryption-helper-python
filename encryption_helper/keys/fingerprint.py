"""Public key fingerprints.

The fingerprints produced here are byte-identical to those printed by
``ssh-keygen -lf``: the SHA-256 digest of the OpenSSH wire encoding of the
public key, base64-encoded without padding and prefixed with ``SHA256:``.

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

__all__ = ["fingerprint_sha256"]


def fingerprint_sha256(key: PublicKeyTypes) -> str:
    """Return the OpenSSH-style SHA-256 fingerprint of a public key.

    Args:
        key: Public key to fingerprint.

    Returns:
        A string of the form ``SHA256:<base64>``, matching the output of
        ``ssh-keygen -lf`` for the same key.

    Raises:
        UnsupportedAlgorithmError: If the key type has no OpenSSH encoding.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> fp = fingerprint_sha256(generate_ed25519().public_key())
        >>> fp.startswith("SHA256:")
        True
        >>> len(fp)
        50
    """
    openssh = encode_public_key(key, fmt="openssh")

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

    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
