# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Loading keys from bytes or files, with format auto-detection.

The loaders accept PEM, DER and OpenSSH input without the caller having to say
which it is, and translate the underlying library's exceptions into
:class:`~encryption_helper.errors.KeyReadError`.

Error messages here deliberately do not distinguish "wrong passphrase" from
"corrupt file". Both mean the same thing to a legitimate caller, and the
distinction is only useful to someone probing a key they should not have.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
from typing import Final

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from .._io import read_bytes
from ..errors import KeyReadError
from . import _pkcs8

logger = logging.getLogger(__name__)

__all__ = [
    "load_private_key",
    "load_private_key_file",
    "load_public_key",
    "load_public_key_file",
]

_PEM_MARKER = b"-----BEGIN"

#: Largest key file the file loaders read. The biggest key this package
#: handles, an encrypted ML-DSA-87 or RSA-4096 PEM, is a few kilobytes; the
#: cap exists so a path to /dev/zero or a huge file fails fast instead of
#: exhausting memory.
MAX_KEY_FILE_BYTES: Final = 1024 * 1024

#: Largest bcrypt round count accepted in an OpenSSH private key. ssh-keygen
#: writes 16 by default, and ``-a 100`` is generous; the cost is linear and
#: read from the file, so it needs the same ceiling as PBKDF2.
MAX_BCRYPT_ROUNDS: Final = 1_000

_OPENSSH_MAGIC = b"openssh-key-v1\x00"
_OPENSSH_PUBLIC_PREFIXES = (b"ssh-", b"ecdsa-sha2-", b"sk-ssh-", b"sk-ecdsa-")


def load_private_key(
    data: bytes, *, passphrase: bytes | None = None
) -> PrivateKeyTypes:
    """Load a private key from PEM, DER, or OpenSSH bytes.

    The encoding is detected from the content, so the caller does not need to
    know it in advance.

    Args:
        data: Encoded private key.
        passphrase: Passphrase, if the key is encrypted.

    Returns:
        The decoded private key.

    Raises:
        KeyReadError: If the data is not a private key this package can decode,
            or the passphrase is absent or wrong.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> from encryption_helper.keys.serialize import encode_private_key
        >>> pem = encode_private_key(generate_ed25519())
        >>> type(load_private_key(pem)).__name__
        'Ed25519PrivateKey'
    """
    if not data:
        msg = "Cannot load a private key from empty input."
        raise KeyReadError(msg)
    last_error: Exception

    if passphrase is not None:
        _refuse_excessive_kdf_cost(data)

    try:
        if b"OPENSSH PRIVATE KEY" in data:
            return serialization.load_ssh_private_key(data, password=passphrase)
        if data.lstrip().startswith(_PEM_MARKER):
            key = serialization.load_pem_private_key(data, password=passphrase)
            der = _pkcs8.der_from_pem(data)
        else:
            key = serialization.load_der_private_key(data, password=passphrase)
            der = data
    except TypeError as exc:
        if passphrase is None:
            # The key's own header already says it is encrypted, so naming
            # that reveals nothing; it only stops a missing passphrase being
            # reported as a possibly corrupt file.
            msg = (
                "The private key is encrypted and no passphrase was supplied. "
                "Provide one with --passphrase-env VAR or --passphrase-file "
                "PATH, or the passphrase argument."
            )
            raise KeyReadError(msg) from exc
        last_error = exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        last_error = exc
    else:
        _warn_if_weakly_protected(der)
        return key

    msg = (
        "Could not load the private key. The data may be corrupt, in an "
        "unsupported format, or protected by a different passphrase."
    )
    raise KeyReadError(msg) from last_error


def _refuse_excessive_kdf_cost(data: bytes) -> None:
    """Refuse a key whose stored derivation cost exceeds the ceiling.

    Runs before decryption is attempted: the point is to never start the
    derivation. Input this cannot parse is left for the real loader to
    reject, so this never becomes the reason a valid key fails to load.
    """
    if b"OPENSSH PRIVATE KEY" in data:
        rounds = _openssh_bcrypt_rounds(data)
        if rounds is not None and rounds > MAX_BCRYPT_ROUNDS:
            msg = (
                f"The private key asks for {rounds} bcrypt rounds, more than "
                f"the {MAX_BCRYPT_ROUNDS} this package will run. Re-protect it "
                "with fewer rounds (ssh-keygen -p -a 100)."
            )
            raise KeyReadError(msg)
        return
    der = _pkcs8.der_from_pem(data) if data.lstrip().startswith(_PEM_MARKER) else data
    iterations = _pkcs8.pbkdf2_iterations(der) if der is not None else None
    if iterations is not None and iterations > _pkcs8.MAX_ITERATIONS:
        msg = (
            f"The private key asks for {iterations} PBKDF2 iterations, more "
            f"than the {_pkcs8.MAX_ITERATIONS} this package will run."
        )
        raise KeyReadError(msg)


def _openssh_bcrypt_rounds(data: bytes) -> int | None:
    """Return the bcrypt round count of an OpenSSH private key, if any.

    The layout is the magic ``openssh-key-v1`` and a NUL, then three
    length-prefixed strings: cipher name, KDF name, KDF options. For bcrypt
    the options are a length-prefixed salt and a big-endian uint32 count.
    """
    try:
        body = data.split(b"-----BEGIN OPENSSH PRIVATE KEY-----", 1)[1]
        raw = base64.b64decode(b"".join(body.split(b"-----END", 1)[0].split()))
        if not raw.startswith(_OPENSSH_MAGIC):
            return None
        _cipher, offset = _ssh_string(raw, len(_OPENSSH_MAGIC))
        kdf, offset = _ssh_string(raw, offset)
        options, _ = _ssh_string(raw, offset)
        _salt, offset = _ssh_string(options, 0)
    except (IndexError, ValueError, binascii.Error):
        return None
    if kdf != b"bcrypt" or len(options) != offset + 4:
        return None
    return int.from_bytes(options[offset:], "big")


def _ssh_string(buffer: bytes, offset: int) -> tuple[bytes, int]:
    """Read one SSH wire-format string; return ``(value, next_offset)``.

    Raises:
        ValueError: If the length prefix or the string is truncated.
    """
    start = offset + 4
    end = start + int.from_bytes(buffer[offset:start], "big")
    if start > len(buffer) or end > len(buffer):
        raise ValueError
    return buffer[start:end], end


def _warn_if_weakly_protected(der: bytes | None) -> None:
    """Log a warning when a loaded key's passphrase protection is weak.

    Keys written before this release, and by tools using
    ``cryptography``'s default, are protected by PBKDF2 at 2,048
    iterations. They still load -- refusing would lock people out of their
    own keys -- but the owner should know, and know the fix.
    """
    if der is None:
        return
    iterations = _pkcs8.pbkdf2_iterations(der)
    if iterations is not None and iterations < _pkcs8.WEAK_ITERATIONS_BELOW:
        logger.warning(
            "This private key's passphrase protection is weak (PBKDF2, %d "
            "iterations; %d is used now), so a stolen copy is cheap to guess. "
            "Re-protect it with: encryption-helper convert --private --to pem "
            "--in KEY --out NEW",
            iterations,
            _pkcs8.PBKDF2_ITERATIONS,
        )


def load_public_key(data: bytes) -> PublicKeyTypes:
    """Load a public key from PEM, DER, or OpenSSH bytes.

    Args:
        data: Encoded public key.

    Returns:
        The decoded public key.

    Raises:
        KeyReadError: If the data is not a public key this package can decode.

    Example:
        >>> from encryption_helper.keys.generate import generate_ed25519
        >>> from encryption_helper.keys.serialize import encode_public_key
        >>> pub = encode_public_key(generate_ed25519().public_key())
        >>> type(load_public_key(pub)).__name__
        'Ed25519PublicKey'
    """
    if not data:
        msg = "Cannot load a public key from empty input."
        raise KeyReadError(msg)

    stripped = data.lstrip()
    try:
        if stripped.startswith(_OPENSSH_PUBLIC_PREFIXES):
            return serialization.load_ssh_public_key(data)
        if stripped.startswith(_PEM_MARKER):
            return serialization.load_pem_public_key(data)
        return serialization.load_der_public_key(data)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        last_error = exc

    msg = (
        "Could not load the public key. The data may be corrupt or in an "
        "unsupported format."
    )
    raise KeyReadError(msg) from last_error


def load_private_key_file(
    path: str | os.PathLike[str], *, passphrase: bytes | None = None
) -> PrivateKeyTypes:
    """Load a private key from a file.

    Args:
        path: File containing the encoded key.
        passphrase: Passphrase, if the key is encrypted.

    Returns:
        The decoded private key.

    Raises:
        KeyReadError: If the file cannot be read or decoded.
    """
    return load_private_key(
        read_bytes(path, limit=MAX_KEY_FILE_BYTES), passphrase=passphrase
    )


def load_public_key_file(path: str | os.PathLike[str]) -> PublicKeyTypes:
    """Load a public key from a file.

    Args:
        path: File containing the encoded key.

    Returns:
        The decoded public key.

    Raises:
        KeyReadError: If the file cannot be read or decoded.
    """
    return load_public_key(read_bytes(path, limit=MAX_KEY_FILE_BYTES))
