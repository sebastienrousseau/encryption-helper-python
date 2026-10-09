# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Human names for key objects, for messages a person will read.

Errors said things like "Cannot encrypt to a Ed25519PublicKey" -- a Python
class name, with the article wrong. An operator thinks in algorithms and
sizes; this says "an Ed25519 key" or "an RSA-2048 key" instead.
"""

from __future__ import annotations

from typing import Final

from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    mldsa,
    mlkem,
    rsa,
    x448,
    x25519,
)

_CURVES: Final = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}

_FIXED: Final[tuple[tuple[tuple[type, ...], str], ...]] = (
    ((ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey), "an Ed25519 key"),
    ((ed448.Ed448PrivateKey, ed448.Ed448PublicKey), "an Ed448 key"),
    ((x25519.X25519PrivateKey, x25519.X25519PublicKey), "an X25519 key"),
    ((x448.X448PrivateKey, x448.X448PublicKey), "an X448 key"),
    ((mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey), "an ML-KEM-768 key"),
    ((mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey), "an ML-KEM-1024 key"),
    ((mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey), "an ML-DSA-44 key"),
    ((mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey), "an ML-DSA-65 key"),
    ((mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey), "an ML-DSA-87 key"),
    ((dsa.DSAPrivateKey, dsa.DSAPublicKey), "a DSA key"),
)


def key_label(key: object) -> str:
    """Name a key the way an operator would, with its article.

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric import ed25519
        >>> key_label(ed25519.Ed25519PrivateKey.generate().public_key())
        'an Ed25519 key'
    """
    if isinstance(key, rsa.RSAPrivateKey | rsa.RSAPublicKey):
        return f"an RSA-{key.key_size} key"
    if isinstance(key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey):
        return f"an ECDSA {_CURVES.get(key.curve.name, key.curve.name)} key"
    for types, label in _FIXED:
        if isinstance(key, types):
            return label
    return f"a key of unsupported type {type(key).__name__}"
