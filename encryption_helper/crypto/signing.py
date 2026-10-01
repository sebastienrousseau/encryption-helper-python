# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Digital signatures over RSA-PSS, Ed25519 and ECDSA.

The algorithm and parameters are chosen from the key type, so a caller cannot
accidentally pair a key with an inappropriate scheme. RSA signing uses PSS with
SHA-256 and a salt the length of the digest; PKCS#1 v1.5 is not offered for new
signatures.

:func:`verify` raises on failure rather than returning a boolean, so a caller
who forgets to check the result fails closed. :func:`is_valid_signature` is
provided for the cases where a boolean genuinely is what you want.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    mldsa,
    padding,
    rsa,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from ..errors import SignatureVerificationError, UnsupportedAlgorithmError

__all__ = ["is_valid_signature", "sign", "verify"]

#: Every ML-DSA parameter set, as a tuple suitable for `isinstance`.
_MLDSA_PRIVATE = (
    mldsa.MLDSA44PrivateKey,
    mldsa.MLDSA65PrivateKey,
    mldsa.MLDSA87PrivateKey,
)
_MLDSA_PUBLIC = (
    mldsa.MLDSA44PublicKey,
    mldsa.MLDSA65PublicKey,
    mldsa.MLDSA87PublicKey,
)

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.DIGEST_LENGTH,
)


def sign(private_key: PrivateKeyTypes, data: bytes) -> bytes:
    """Sign ``data`` with ``private_key``.

    The scheme is selected from the key type:

    ==================  ==========================================
    Key type            Signature scheme
    ==================  ==========================================
    RSA                 RSA-PSS, SHA-256, salt length = digest
    Ed25519             Ed25519 (PureEdDSA)
    Ed448               Ed448 (PureEdDSA)
    ECDSA               ECDSA with SHA-256
    ML-DSA 44/65/87     ML-DSA (FIPS 204), hedged
    ==================  ==========================================

    ML-DSA is the only one of these believed secure against a quantum
    computer. The others are deprecated from 2030 and disallowed from 2035
    under NIST IR 8547.

    Args:
        private_key: Key to sign with.
        data: Message to sign.

    Returns:
        The signature.

    Raises:
        UnsupportedAlgorithmError: If the key type cannot sign.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> key = generate_ed25519()
        >>> sig = sign(key, b"message")
        >>> verify(key.public_key(), sig, b"message")
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(data, _PSS_PADDING, hashes.SHA256())
    if isinstance(private_key, ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey):
        return private_key.sign(data)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(private_key, _MLDSA_PRIVATE):
        return private_key.sign(data)

    msg = (
        f"Cannot sign with a {type(private_key).__name__}. Supported key types "
        "are RSA, Ed25519, Ed448, ECDSA and ML-DSA. X25519 and ML-KEM keys are "
        "for encryption, not signing."
    )
    raise UnsupportedAlgorithmError(msg)


def verify(public_key: PublicKeyTypes, signature: bytes, data: bytes) -> None:
    """Verify ``signature`` over ``data`` using ``public_key``.

    Args:
        public_key: Key to verify against.
        signature: Signature produced by :func:`sign`.
        data: Message the signature is expected to cover.

    Returns:
        :data:`None` if the signature is valid.

    Raises:
        SignatureVerificationError: If the signature does not verify. Returning
            normally is the only success indication; there is no truthy value
            to forget to check.
        UnsupportedAlgorithmError: If the key type cannot verify.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> key = generate_ed25519()
        >>> verify(key.public_key(), sign(key, b"hello"), b"hello")
    """
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, _PSS_PADDING, hashes.SHA256())
            return
        if isinstance(public_key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            public_key.verify(signature, data)
            return
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return
        if isinstance(public_key, _MLDSA_PUBLIC):
            public_key.verify(signature, data)
            return
    except InvalidSignature as exc:
        msg = (
            "Signature verification failed. The data, the signature, or the "
            "key does not match."
        )
        raise SignatureVerificationError(msg) from exc

    msg = (
        f"Cannot verify with a {type(public_key).__name__}. Supported key "
        "types are RSA, Ed25519, Ed448, ECDSA and ML-DSA."
    )
    raise UnsupportedAlgorithmError(msg)


def is_valid_signature(
    public_key: PublicKeyTypes, signature: bytes, data: bytes
) -> bool:
    """Return whether ``signature`` is valid, instead of raising.

    Args:
        public_key: Key to verify against.
        signature: Signature to check.
        data: Message the signature is expected to cover.

    Returns:
        :data:`True` if the signature verifies, :data:`False` if it does not.

    Raises:
        UnsupportedAlgorithmError: If the key type cannot verify. An
            unsupported key is a programming error, not an invalid signature,
            so it is not reported as :data:`False`.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> key = generate_ed25519()
        >>> is_valid_signature(key.public_key(), sign(key, b"a"), b"b")
        False
    """
    try:
        verify(public_key, signature, data)
    except SignatureVerificationError:
        return False
    return True
