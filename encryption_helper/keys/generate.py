# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Asymmetric key pair generation.

These functions return live key objects and perform no input or output. They
never print, never log secret material, and never touch the filesystem.
Serialising and storing a key are separate, explicit steps -- see
:mod:`encryption_helper.keys.serialize` and
:func:`encryption_helper.keys.store.write_key_pair`.

That separation is deliberate. A library that generates a key and writes it to
a fixed location in one call cannot be used safely from a service, and cannot
be tested without touching a disk.
"""

from __future__ import annotations

from typing import Final

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from ..errors import InvalidArgumentError, KeyGenerationError, UnsupportedAlgorithmError

__all__ = [
    "ALLOWED_RSA_KEY_SIZES",
    "DEFAULT_ALGORITHM",
    "DEFAULT_RSA_KEY_SIZE",
    "MIN_RSA_KEY_SIZE",
    "SUPPORTED_ALGORITHMS",
    "generate",
    "generate_ecdsa",
    "generate_ed25519",
    "generate_rsa",
]

#: Smallest RSA modulus this package will produce. Keys below 2048 bits are
#: considered broken for new material and are rejected outright rather than
#: warned about.
MIN_RSA_KEY_SIZE: Final = 2048

#: RSA sizes this package will produce. An allowlist rather than a lower
#: bound: the underlying library accepts arbitrary values, most of which are
#: interoperability hazards even when they clear the minimum.
ALLOWED_RSA_KEY_SIZES: Final = (2048, 3072, 4096)

#: Default RSA modulus size. 3072 bits rather than 2048: a key generated today
#: may still be in service well past the point where 2048 is comfortable, and
#: the extra cost at generation time is paid once.
DEFAULT_RSA_KEY_SIZE: Final = 3072

#: The conventional RSA public exponent. F4 (65537) is the only value with
#: broad interoperability and no small-exponent caveats.
DEFAULT_PUBLIC_EXPONENT: Final = 65537

#: Named elliptic curves, mapped to their `cryptography` implementations.
SUPPORTED_CURVES: Final[dict[str, type[ec.EllipticCurve]]] = {
    "p256": ec.SECP256R1,
    "p384": ec.SECP384R1,
    "p521": ec.SECP521R1,
}

#: Algorithm identifiers accepted by :func:`generate`.
SUPPORTED_ALGORITHMS: Final = ("rsa", "ed25519", "ecdsa")

#: Algorithm used when the caller does not choose one.
DEFAULT_ALGORITHM: Final = "rsa"


def generate_rsa(
    *,
    key_size: int = DEFAULT_RSA_KEY_SIZE,
    public_exponent: int = DEFAULT_PUBLIC_EXPONENT,
) -> rsa.RSAPrivateKey:
    """Generate an RSA private key.

    The public key is derived from the result with ``key.public_key()``; there
    is no separate public key generation step.

    Args:
        key_size: Modulus size in bits. Must be at least
            :data:`MIN_RSA_KEY_SIZE`.
        public_exponent: RSA public exponent. Leave at the default unless you
            have a specific interoperability requirement.

    Returns:
        The generated private key.

    Raises:
        InvalidArgumentError: If ``key_size`` is below the minimum or
            ``public_exponent`` is not a supported value.
        KeyGenerationError: If the underlying backend fails.

    Example:
        >>> key = generate_rsa(key_size=2048)
        >>> key.key_size
        2048
    """
    if key_size < MIN_RSA_KEY_SIZE:
        msg = (
            f"RSA key size {key_size} is too small; the minimum is "
            f"{MIN_RSA_KEY_SIZE} bits. Keys below this offer no meaningful "
            "security margin for new material."
        )
        raise InvalidArgumentError(msg)
    if key_size not in ALLOWED_RSA_KEY_SIZES:
        allowed = ", ".join(str(size) for size in ALLOWED_RSA_KEY_SIZES)
        msg = (
            f"RSA key size {key_size} is not an allowed size; choose one of: "
            f"{allowed}. Unusual sizes are accepted by the underlying library "
            "but interoperate poorly."
        )
        raise InvalidArgumentError(msg)
    if public_exponent not in (3, DEFAULT_PUBLIC_EXPONENT):
        msg = (
            f"Unsupported RSA public exponent {public_exponent}; use "
            f"{DEFAULT_PUBLIC_EXPONENT}."
        )
        raise InvalidArgumentError(msg)

    try:
        return rsa.generate_private_key(
            public_exponent=public_exponent, key_size=key_size
        )
    except Exception as exc:  # pragma: no cover - backend failure
        msg = f"RSA key generation failed: {exc}"
        raise KeyGenerationError(msg) from exc


def generate_ed25519() -> ed25519.Ed25519PrivateKey:
    """Generate an Ed25519 private key.

    Ed25519 has no size or curve parameters: the algorithm fixes them. It is a
    good default for signing where interoperability allows, being fast, compact
    and free of parameter-choice pitfalls. It cannot be used for encryption.

    Returns:
        The generated private key.

    Raises:
        KeyGenerationError: If the underlying backend fails.

    Example:
        >>> key = generate_ed25519()
        >>> type(key).__name__
        'Ed25519PrivateKey'
    """
    try:
        return ed25519.Ed25519PrivateKey.generate()
    except Exception as exc:  # pragma: no cover - backend failure
        msg = f"Ed25519 key generation failed: {exc}"
        raise KeyGenerationError(msg) from exc


def generate_ecdsa(*, curve: str = "p256") -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA private key on a NIST curve.

    Args:
        curve: One of ``"p256"``, ``"p384"``, or ``"p521"``.

    Returns:
        The generated private key.

    Raises:
        UnsupportedAlgorithmError: If ``curve`` is not recognised.
        KeyGenerationError: If the underlying backend fails.

    Example:
        >>> key = generate_ecdsa(curve="p384")
        >>> key.curve.name
        'secp384r1'
    """
    normalised = curve.strip().lower()
    if normalised not in SUPPORTED_CURVES:
        supported = ", ".join(sorted(SUPPORTED_CURVES))
        msg = f"Unsupported curve {curve!r}; choose one of: {supported}."
        raise UnsupportedAlgorithmError(msg)

    try:
        return ec.generate_private_key(SUPPORTED_CURVES[normalised]())
    except Exception as exc:  # pragma: no cover - backend failure
        msg = f"ECDSA key generation failed: {exc}"
        raise KeyGenerationError(msg) from exc


def generate(
    algorithm: str = DEFAULT_ALGORITHM,
    *,
    key_size: int = DEFAULT_RSA_KEY_SIZE,
    curve: str = "p256",
) -> PrivateKeyTypes:
    """Generate a private key for the named algorithm.

    A thin dispatcher over :func:`generate_rsa`, :func:`generate_ed25519` and
    :func:`generate_ecdsa`, for callers driven by configuration or command-line
    input.

    Args:
        algorithm: One of :data:`SUPPORTED_ALGORITHMS`.
        key_size: RSA modulus size. Ignored for other algorithms.
        curve: ECDSA curve name. Ignored for other algorithms.

    Returns:
        The generated private key.

    Raises:
        UnsupportedAlgorithmError: If ``algorithm`` is not recognised.
        InvalidArgumentError: If a parameter is out of range.
        KeyGenerationError: If the underlying backend fails.

    Example:
        >>> key = generate("ed25519")
        >>> type(key).__name__
        'Ed25519PrivateKey'
    """
    normalised = algorithm.strip().lower()
    if normalised == "rsa":
        return generate_rsa(key_size=key_size)
    if normalised == "ed25519":
        return generate_ed25519()
    if normalised == "ecdsa":
        return generate_ecdsa(curve=curve)

    supported = ", ".join(SUPPORTED_ALGORITHMS)
    msg = f"Unsupported algorithm {algorithm!r}; choose one of: {supported}."
    raise UnsupportedAlgorithmError(msg)
