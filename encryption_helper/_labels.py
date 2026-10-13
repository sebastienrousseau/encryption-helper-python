# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""The one table of key types, and human names for them.

Errors said things like "Cannot encrypt to a Ed25519PublicKey" -- a Python
class name, with the article wrong. An operator thinks in algorithms and
sizes; this says "an Ed25519 key" or "an RSA-2048 key" instead.

:data:`KEY_TYPES` is also the package's single list of fixed-size key types:
which public class pairs with which private class, the algorithm name and
size the package reports, and the label. It used to be copied into each
module that needed a slice of it, and the copies drifted -- ``keys/store.py``
lost X448 while this module and the inventory had it. Add a type here and
every consumer sees it.
"""

from __future__ import annotations

from dataclasses import dataclass
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

__all__ = ["KEY_TYPES", "KeyType", "key_label", "key_type"]

_CURVES: Final = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


@dataclass(frozen=True, slots=True)
class KeyType:
    """One fixed-size key type, as every part of the package names it.

    Attributes:
        private: The private key class.
        public: The matching public key class.
        algorithm: The algorithm name callers see, for example ``"mlkem"``.
        size: The size reported alongside it: a curve size for the
            classical types, the parameter set for the post-quantum ones,
            which is what identifies the variant and what callers display.
        label: How a message names it, with its article.
    """

    private: type
    public: type
    algorithm: str
    size: int
    label: str


#: Every fixed-size key type the package knows. RSA, ECDSA and DSA are absent
#: because their size lives on the instance, so callers ask the key directly.
KEY_TYPES: Final[tuple[KeyType, ...]] = (
    KeyType(
        ed25519.Ed25519PrivateKey,
        ed25519.Ed25519PublicKey,
        "ed25519",
        256,
        "an Ed25519 key",
    ),
    KeyType(ed448.Ed448PrivateKey, ed448.Ed448PublicKey, "ed448", 448, "an Ed448 key"),
    KeyType(
        x25519.X25519PrivateKey, x25519.X25519PublicKey, "x25519", 256, "an X25519 key"
    ),
    KeyType(x448.X448PrivateKey, x448.X448PublicKey, "x448", 448, "an X448 key"),
    KeyType(
        mlkem.MLKEM768PrivateKey,
        mlkem.MLKEM768PublicKey,
        "mlkem",
        768,
        "an ML-KEM-768 key",
    ),
    KeyType(
        mlkem.MLKEM1024PrivateKey,
        mlkem.MLKEM1024PublicKey,
        "mlkem",
        1024,
        "an ML-KEM-1024 key",
    ),
    KeyType(
        mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey, "mldsa", 44, "an ML-DSA-44 key"
    ),
    KeyType(
        mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey, "mldsa", 65, "an ML-DSA-65 key"
    ),
    KeyType(
        mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey, "mldsa", 87, "an ML-DSA-87 key"
    ),
)


def key_type(key: object) -> KeyType | None:
    """Return the :data:`KEY_TYPES` entry for a private or public key, if any.

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric import x448
        >>> key_type(x448.X448PrivateKey.generate().public_key()).algorithm
        'x448'
    """
    for entry in KEY_TYPES:
        if isinstance(key, entry.private | entry.public):
            return entry
    return None


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
    if isinstance(key, dsa.DSAPrivateKey | dsa.DSAPublicKey):
        return "a DSA key"
    entry = key_type(key)
    if entry is not None:
        return entry.label
    return f"a key of unsupported type {type(key).__name__}"
