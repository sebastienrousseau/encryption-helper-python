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

from collections.abc import Callable
from typing import Final

from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    mldsa,
    mlkem,
    rsa,
    x25519,
)
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from ..errors import InvalidArgumentError, KeyGenerationError, UnsupportedAlgorithmError

__all__ = [
    "ALLOWED_RSA_KEY_SIZES",
    "DEFAULT_ALGORITHM",
    "DEFAULT_MLDSA_LEVEL",
    "DEFAULT_MLKEM_LEVEL",
    "DEFAULT_RSA_KEY_SIZE",
    "MIN_RSA_KEY_SIZE",
    "POST_QUANTUM",
    "QUANTUM_VULNERABLE",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_MLDSA_LEVELS",
    "SUPPORTED_MLKEM_LEVELS",
    "MLDSAPrivateKey",
    "MLKEMPrivateKey",
    "generate",
    "generate_ecdsa",
    "generate_ed448",
    "generate_ed25519",
    "generate_mldsa",
    "generate_mlkem",
    "generate_rsa",
    "generate_x25519",
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

#: Any ML-KEM private key, whatever the parameter set.
MLKEMPrivateKey = mlkem.MLKEM768PrivateKey | mlkem.MLKEM1024PrivateKey

#: Any ML-DSA private key, whatever the parameter set.
MLDSAPrivateKey = (
    mldsa.MLDSA44PrivateKey | mldsa.MLDSA65PrivateKey | mldsa.MLDSA87PrivateKey
)

#: ML-KEM parameter sets (FIPS 203), by security level.
SUPPORTED_MLKEM_LEVELS: Final[dict[int, Callable[[], MLKEMPrivateKey]]] = {
    768: mlkem.MLKEM768PrivateKey.generate,
    1024: mlkem.MLKEM1024PrivateKey.generate,
}

#: ML-DSA parameter sets (FIPS 204), by security level.
SUPPORTED_MLDSA_LEVELS: Final[dict[int, Callable[[], MLDSAPrivateKey]]] = {
    44: mldsa.MLDSA44PrivateKey.generate,
    65: mldsa.MLDSA65PrivateKey.generate,
    87: mldsa.MLDSA87PrivateKey.generate,
}

#: Default ML-KEM parameter set.
DEFAULT_MLKEM_LEVEL: Final = 768

#: Default ML-DSA parameter set.
DEFAULT_MLDSA_LEVEL: Final = 65

#: Algorithm identifiers accepted by :func:`generate`.
SUPPORTED_ALGORITHMS: Final = (
    "rsa",
    "ed25519",
    "ed448",
    "ecdsa",
    "x25519",
    "mlkem",
    "mldsa",
)

#: Algorithms broken by a sufficiently large quantum computer.
#:
#: NIST IR 8547 (initial public draft) deprecates 112-bit-security public-key
#: algorithms such as RSA-2048 after 2030, and disallows all of these after
#: 2035 whatever their strength. P-256, Ed25519 and X25519 are 128-bit and so
#: skip the deprecation step. CNSA 2.0 is
#: stricter still for national security systems. Keys generated today for
#: long-lived credentials will outlive those dates, so :func:`generate`
#: records which choices are affected and the CLI says so at generation time.
QUANTUM_VULNERABLE: Final = frozenset({"rsa", "ecdsa", "ed25519", "ed448", "x25519"})

#: Algorithms standardised for the post-quantum era.
POST_QUANTUM: Final = frozenset({"mlkem", "mldsa"})

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


def generate_ed448() -> ed448.Ed448PrivateKey:
    """Generate an Ed448 private key.

    Ed448 targets a higher security level than Ed25519 at the cost of larger
    keys and signatures. Like Ed25519 it cannot be used for encryption, and
    like Ed25519 it is broken by a quantum computer -- see
    :data:`QUANTUM_VULNERABLE`.

    Returns:
        The generated private key.

    Raises:
        KeyGenerationError: If the underlying backend fails.

    Example:
        >>> type(generate_ed448()).__name__
        'Ed448PrivateKey'
    """
    try:
        return ed448.Ed448PrivateKey.generate()
    except Exception as exc:  # pragma: no cover - backend failure
        msg = f"Ed448 key generation failed: {exc}"
        raise KeyGenerationError(msg) from exc


def generate_x25519() -> x25519.X25519PrivateKey:
    """Generate an X25519 private key for encryption.

    X25519 is a key-agreement algorithm, not a signature algorithm. This
    package uses it for encryption in the standard ephemeral-static form: a
    fresh ephemeral key agrees a secret with the recipient's static key, and
    HKDF derives the content key from it. That is the same construction
    ``age`` uses.

    Returns:
        The generated private key.

    Raises:
        KeyGenerationError: If the underlying backend fails.

    Example:
        >>> type(generate_x25519()).__name__
        'X25519PrivateKey'
    """
    try:
        return x25519.X25519PrivateKey.generate()
    except Exception as exc:  # pragma: no cover - backend failure
        msg = f"X25519 key generation failed: {exc}"
        raise KeyGenerationError(msg) from exc


def generate_mlkem(*, level: int = DEFAULT_MLKEM_LEVEL) -> MLKEMPrivateKey:
    """Generate an ML-KEM private key for encryption (FIPS 203).

    ML-KEM is a key-encapsulation mechanism believed secure against quantum
    computers. It replaces RSA-OAEP and ECDH for the encryption path, and is
    the algorithm NIST expects to carry that role past 2035.

    Args:
        level: Parameter set, 768 or 1024. 768 targets roughly AES-192
            equivalent security and is the common default; 1024 targets
            AES-256.

    Returns:
        The generated private key.

    Raises:
        UnsupportedAlgorithmError: If ``level`` is not a supported parameter
            set.
        KeyGenerationError: If the underlying backend fails.

    Example:
        >>> type(generate_mlkem(level=768)).__name__
        'MLKEM768PrivateKey'
    """
    if level not in SUPPORTED_MLKEM_LEVELS:
        supported = ", ".join(str(lvl) for lvl in sorted(SUPPORTED_MLKEM_LEVELS))
        msg = f"Unsupported ML-KEM level {level}; choose one of: {supported}."
        raise UnsupportedAlgorithmError(msg)
    try:
        return SUPPORTED_MLKEM_LEVELS[level]()
    except Exception as exc:  # pragma: no cover - backend failure
        msg = f"ML-KEM key generation failed: {exc}"
        raise KeyGenerationError(msg) from exc


def generate_mldsa(*, level: int = DEFAULT_MLDSA_LEVEL) -> MLDSAPrivateKey:
    """Generate an ML-DSA private key for signing (FIPS 204).

    ML-DSA is a lattice signature scheme believed secure against quantum
    computers. It replaces Ed25519 and ECDSA for signing, and is the algorithm
    NIST expects to carry that role past 2035.

    Args:
        level: Parameter set, 44, 65 or 87, in increasing security and size.
            65 is the common default.

    Returns:
        The generated private key.

    Raises:
        UnsupportedAlgorithmError: If ``level`` is not a supported parameter
            set.
        KeyGenerationError: If the underlying backend fails.

    Example:
        >>> type(generate_mldsa(level=65)).__name__
        'MLDSA65PrivateKey'
    """
    if level not in SUPPORTED_MLDSA_LEVELS:
        supported = ", ".join(str(lvl) for lvl in sorted(SUPPORTED_MLDSA_LEVELS))
        msg = f"Unsupported ML-DSA level {level}; choose one of: {supported}."
        raise UnsupportedAlgorithmError(msg)
    try:
        return SUPPORTED_MLDSA_LEVELS[level]()
    except Exception as exc:  # pragma: no cover - backend failure
        msg = f"ML-DSA key generation failed: {exc}"
        raise KeyGenerationError(msg) from exc


def generate(
    algorithm: str = DEFAULT_ALGORITHM,
    *,
    key_size: int = DEFAULT_RSA_KEY_SIZE,
    curve: str = "p256",
    level: int = 0,
) -> PrivateKeyTypes:
    """Generate a private key for the named algorithm.

    A thin dispatcher over :func:`generate_rsa`, :func:`generate_ed25519` and
    :func:`generate_ecdsa`, for callers driven by configuration or command-line
    input.

    Args:
        algorithm: One of :data:`SUPPORTED_ALGORITHMS`.
        key_size: RSA modulus size. Ignored for other algorithms.
        curve: ECDSA curve name. Ignored for other algorithms.
        level: ML-KEM or ML-DSA parameter set. Zero selects that algorithm's
            default (768 for ML-KEM, 65 for ML-DSA). Ignored otherwise.

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
    builders: dict[str, Callable[[], PrivateKeyTypes]] = {
        "rsa": lambda: generate_rsa(key_size=key_size),
        "ed25519": generate_ed25519,
        "ed448": generate_ed448,
        "ecdsa": lambda: generate_ecdsa(curve=curve),
        "x25519": generate_x25519,
        "mlkem": lambda: generate_mlkem(level=level or DEFAULT_MLKEM_LEVEL),
        "mldsa": lambda: generate_mldsa(level=level or DEFAULT_MLDSA_LEVEL),
    }
    builder = builders.get(normalised)
    if builder is None:
        supported = ", ".join(SUPPORTED_ALGORITHMS)
        msg = f"Unsupported algorithm {algorithm!r}; choose one of: {supported}."
        raise UnsupportedAlgorithmError(msg)
    return builder()
