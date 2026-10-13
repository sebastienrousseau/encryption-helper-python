# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Encoding and decoding of keys to and from PEM, DER and OpenSSH formats.

Private keys default to PKCS#8, the modern container format, and are encrypted
whenever a passphrase is supplied. Passing an empty passphrase is rejected
rather than quietly treated as "no encryption", because a caller that passes an
empty string usually believes the key is protected.
"""

from __future__ import annotations

from typing import Final

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from .._labels import key_label
from ..errors import InvalidArgumentError, UnsupportedAlgorithmError
from . import _pkcs8

__all__ = [
    "SUPPORTED_PRIVATE_FORMATS",
    "SUPPORTED_PUBLIC_FORMATS",
    "encode_private_key",
    "encode_public_key",
]

#: Output formats accepted for private keys.
SUPPORTED_PRIVATE_FORMATS: Final = ("pem", "der", "openssh")

#: Output formats accepted for public keys.
SUPPORTED_PUBLIC_FORMATS: Final = ("pem", "der", "openssh")


def _encryption(passphrase: bytes | None) -> serialization.KeySerializationEncryption:
    """Build the serialisation encryption for an optional passphrase.

    Args:
        passphrase: Passphrase bytes, or :data:`None` for an unencrypted key.

    Returns:
        ``BestAvailableEncryption`` when a passphrase is given, otherwise
        ``NoEncryption``.

    Raises:
        InvalidArgumentError: If ``passphrase`` is present but empty.
    """
    if passphrase is None:
        return serialization.NoEncryption()
    _require_real_passphrase(passphrase)
    return serialization.BestAvailableEncryption(passphrase)


def _require_real_passphrase(passphrase: bytes) -> None:
    """Refuse an empty passphrase, which would protect nothing.

    Raises:
        InvalidArgumentError: If ``passphrase`` is empty.
    """
    if not passphrase:
        msg = (
            "An empty passphrase does not protect the key. Pass None "
            "explicitly to write an unencrypted key, or supply a real "
            "passphrase."
        )
        raise InvalidArgumentError(msg)


def encode_private_key(
    key: PrivateKeyTypes,
    *,
    fmt: str = "pem",
    passphrase: bytes | None = None,
) -> bytes:
    """Serialise a private key.

    Args:
        key: Private key to encode.
        fmt: One of :data:`SUPPORTED_PRIVATE_FORMATS`. ``"pem"`` and ``"der"``
            produce PKCS#8; ``"openssh"`` produces the OpenSSH private key
            format.
        passphrase: Optional passphrase. For ``"pem"`` and ``"der"`` the key
            is written as standard PKCS#8 PBES2 using PBKDF2-HMAC-SHA256 at
            :data:`~encryption_helper.keys._pkcs8.PBKDF2_ITERATIONS`
            iterations and AES-256-CBC, which OpenSSL and every mainstream
            PKCS#8 reader accept. ``cryptography``'s default for PKCS#8 is
            2,048 iterations and cannot be raised. ``"openssh"`` uses the
            OpenSSH format's own bcrypt KDF.

    Returns:
        The encoded key.

    Raises:
        UnsupportedAlgorithmError: If ``fmt`` is not recognised, or the key
            type cannot be represented in that format.
        InvalidArgumentError: If ``passphrase`` is present but empty.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> pem = encode_private_key(generate_ed25519())
        >>> pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        True
    """
    normalised = fmt.strip().lower()
    if passphrase is not None and normalised in {"pem", "der"}:
        return _strongly_protected_pkcs8(key, normalised, passphrase)
    encryption = _encryption(passphrase)

    if normalised == "pem":
        encoding = serialization.Encoding.PEM
        private_format = serialization.PrivateFormat.PKCS8
    elif normalised == "der":
        encoding = serialization.Encoding.DER
        private_format = serialization.PrivateFormat.PKCS8
    elif normalised == "openssh":
        encoding = serialization.Encoding.PEM
        private_format = serialization.PrivateFormat.OpenSSH
    else:
        supported = ", ".join(SUPPORTED_PRIVATE_FORMATS)
        msg = f"Unsupported private key format {fmt!r}; choose one of: {supported}."
        raise UnsupportedAlgorithmError(msg)

    try:
        return key.private_bytes(
            encoding=encoding,
            format=private_format,
            encryption_algorithm=encryption,
        )
    except (ValueError, TypeError) as exc:
        msg = f"Cannot encode {key_label(key)} as {normalised}: {exc}"
        raise UnsupportedAlgorithmError(msg) from exc
    except UnsupportedAlgorithm as exc:
        # The OpenSSH format's KDF is bcrypt-pbkdf, which cryptography only
        # provides when the optional `bcrypt` package is installed. This
        # escaped untranslated, so `keygen --format openssh` with a
        # passphrase ended in "unexpected internal error".
        msg = (
            "A passphrase-protected OpenSSH key needs the optional 'bcrypt' "
            "package (pip install bcrypt). Alternatively use the pem or der "
            "format, which is protected with PBKDF2 at "
            f"{_pkcs8.PBKDF2_ITERATIONS:,} iterations."
        )
        raise UnsupportedAlgorithmError(msg) from exc


def _strongly_protected_pkcs8(
    key: PrivateKeyTypes, normalised: str, passphrase: bytes
) -> bytes:
    """Encode ``key`` as PBES2 PKCS#8 with a meaningful KDF cost."""
    _require_real_passphrase(passphrase)
    try:
        der = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except (ValueError, TypeError) as exc:  # pragma: no cover - every type has PKCS#8
        msg = f"Cannot encode {key_label(key)} as {normalised}: {exc}"
        raise UnsupportedAlgorithmError(msg) from exc
    protected = _pkcs8.protect(der, passphrase)
    return _pkcs8.to_pem(protected) if normalised == "pem" else protected


def encode_public_key(key: PublicKeyTypes, *, fmt: str = "pem") -> bytes:
    """Serialise a public key.

    Args:
        key: Public key to encode.
        fmt: One of :data:`SUPPORTED_PUBLIC_FORMATS`. ``"pem"`` and ``"der"``
            produce SubjectPublicKeyInfo; ``"openssh"`` produces the
            single-line ``authorized_keys`` form.

    Returns:
        The encoded key.

    Raises:
        UnsupportedAlgorithmError: If ``fmt`` is not recognised, or the key
            type cannot be represented in that format.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> pub = generate_ed25519().public_key()
        >>> encode_public_key(pub, fmt="openssh").startswith(b"ssh-ed25519 ")
        True
    """
    normalised = fmt.strip().lower()

    if normalised == "pem":
        encoding = serialization.Encoding.PEM
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    elif normalised == "der":
        encoding = serialization.Encoding.DER
        public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    elif normalised == "openssh":
        encoding = serialization.Encoding.OpenSSH
        public_format = serialization.PublicFormat.OpenSSH
    else:
        supported = ", ".join(SUPPORTED_PUBLIC_FORMATS)
        msg = f"Unsupported public key format {fmt!r}; choose one of: {supported}."
        raise UnsupportedAlgorithmError(msg)

    try:
        return key.public_bytes(encoding=encoding, format=public_format)
    except (ValueError, TypeError) as exc:
        msg = f"Cannot encode {key_label(key)} as {normalised}: {exc}"
        raise UnsupportedAlgorithmError(msg) from exc
