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

import os

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from .._io import read_bytes
from ..errors import KeyReadError

__all__ = [
    "load_private_key",
    "load_private_key_file",
    "load_public_key",
    "load_public_key_file",
]

_PEM_MARKER = b"-----BEGIN"
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

    try:
        if b"OPENSSH PRIVATE KEY" in data:
            return serialization.load_ssh_private_key(data, password=passphrase)
        if data.lstrip().startswith(_PEM_MARKER):
            return serialization.load_pem_private_key(data, password=passphrase)
        return serialization.load_der_private_key(data, password=passphrase)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        last_error = exc

    msg = (
        "Could not load the private key. The data may be corrupt, in an "
        "unsupported format, or protected by a different passphrase."
    )
    raise KeyReadError(msg) from last_error


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
    return load_private_key(read_bytes(path), passphrase=passphrase)


def load_public_key_file(path: str | os.PathLike[str]) -> PublicKeyTypes:
    """Load a public key from a file.

    Args:
        path: File containing the encoded key.

    Returns:
        The decoded public key.

    Raises:
        KeyReadError: If the file cannot be read or decoded.
    """
    return load_public_key(read_bytes(path))
