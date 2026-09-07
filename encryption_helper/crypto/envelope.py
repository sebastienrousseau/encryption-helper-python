# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Hybrid (envelope) encryption using RSA-OAEP and AES-256-GCM.

RSA cannot encrypt arbitrary-length data. A 3072-bit key with OAEP-SHA256 can
carry roughly 318 bytes, and naively calling ``public_key.encrypt(plaintext)``
either fails on anything larger or -- worse, in libraries that silently chunk
it -- produces something that looks like it works and is not secure. That
mistake is the most common way a "helper" library becomes a vulnerability.

This module does what TLS, JWE, age and PGP all do instead:

1. Generate a fresh random 256-bit content key.
2. Encrypt the plaintext with AES-256-GCM under that content key, which
   provides both confidentiality and integrity.
3. Encrypt ("wrap") the content key with the recipient's RSA public key using
   OAEP with SHA-256.
4. Emit a self-describing container holding the wrapped key, the nonce and the
   ciphertext.

The container header, wrapped key and nonce are all fed to the AEAD as
associated data, so any modification to the framing is detected as tampering
rather than silently reinterpreted.

.. warning::
   Encryption and decryption operate on whole messages held in memory. This is
   appropriate for keys, credentials, configuration and documents. It is not
   suitable for multi-gigabyte files; streaming support is deliberately not
   implemented rather than implemented badly.
"""

from __future__ import annotations

import os
import struct
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import DecryptionError, InvalidArgumentError

__all__ = ["MAGIC", "VERSION", "decrypt", "encrypt"]

#: Container magic, identifying the format in a hex dump or file(1) rule.
MAGIC: Final = b"EHEV"

#: Container format version. Incremented only for breaking format changes.
VERSION: Final = 1

#: Key encapsulation mechanism identifier: RSA-OAEP with SHA-256 and MGF1.
KEM_RSA_OAEP_SHA256: Final = 1

#: AEAD identifier: AES-256-GCM.
AEAD_AES_256_GCM: Final = 1

#: ``magic | version | kem | aead | reserved | wrapped key length``.
_HEADER_STRUCT: Final = struct.Struct(">4sBBBBH")
_HEADER_SIZE: Final = _HEADER_STRUCT.size

#: GCM standard nonce length. 96 bits is the only size with a security proof
#: for the standard construction.
_NONCE_SIZE: Final = 12

#: AES-256 content key length in bytes.
_CONTENT_KEY_SIZE: Final = 32

#: GCM authentication tag length in bytes.
_TAG_SIZE: Final = 16

_OAEP_PADDING: Final = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def _aad(header: bytes, wrapped_key: bytes, nonce: bytes, extra: bytes) -> bytes:
    """Build the associated data binding the framing to the ciphertext."""
    return header + wrapped_key + nonce + extra


def encrypt(
    public_key: PublicKeyTypes,
    plaintext: bytes,
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Encrypt ``plaintext`` to the holder of ``public_key``.

    Args:
        public_key: Recipient's RSA public key.
        plaintext: Data to encrypt. May be empty.
        associated_data: Optional context to authenticate but not encrypt. The
            same value must be supplied to :func:`decrypt`. Use it to bind a
            ciphertext to its intended purpose, so a message cannot be replayed
            in a different context.

    Returns:
        The encrypted container.

    Raises:
        InvalidArgumentError: If ``public_key`` is not an RSA public key, or is
            too small to wrap a 256-bit content key.

    Example:
        >>> from encryption_helper.keys.generate import generate_rsa
        >>> key = generate_rsa(key_size=2048)
        >>> blob = encrypt(key.public_key(), b"attack at dawn")
        >>> decrypt(key, blob)
        b'attack at dawn'
    """
    if not isinstance(public_key, rsa.RSAPublicKey):
        msg = (
            f"Encryption requires an RSA public key, got "
            f"{type(public_key).__name__}. Ed25519 and ECDSA keys are for "
            "signing, not encryption."
        )
        raise InvalidArgumentError(msg)

    content_key = AESGCM.generate_key(bit_length=_CONTENT_KEY_SIZE * 8)
    nonce = os.urandom(_NONCE_SIZE)

    try:
        wrapped_key = public_key.encrypt(content_key, _OAEP_PADDING)
    except ValueError as exc:
        msg = (
            f"RSA key is too small to wrap a {_CONTENT_KEY_SIZE * 8}-bit "
            f"content key with OAEP-SHA256: {exc}"
        )
        raise InvalidArgumentError(msg) from exc

    header = _HEADER_STRUCT.pack(
        MAGIC,
        VERSION,
        KEM_RSA_OAEP_SHA256,
        AEAD_AES_256_GCM,
        0,
        len(wrapped_key),
    )
    ciphertext = AESGCM(content_key).encrypt(
        nonce, plaintext, _aad(header, wrapped_key, nonce, associated_data)
    )
    return header + wrapped_key + nonce + ciphertext


def _parse(blob: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Split a container into header, wrapped key, nonce and ciphertext.

    Raises:
        DecryptionError: If the container is malformed or an unsupported
            version.
    """
    if len(blob) < _HEADER_SIZE:
        msg = "Ciphertext is too short to be a valid container."
        raise DecryptionError(msg)

    header = blob[:_HEADER_SIZE]
    magic, version, kem_id, aead_id, reserved, wrapped_len = _HEADER_STRUCT.unpack(
        header
    )

    if magic != MAGIC:
        msg = "Not an encryption-helper container: bad magic bytes."
        raise DecryptionError(msg)
    if version != VERSION:
        msg = (
            f"Unsupported container version {version}; this build understands "
            f"version {VERSION}. Upgrade encryption-helper to read it."
        )
        raise DecryptionError(msg)
    if kem_id != KEM_RSA_OAEP_SHA256:
        msg = f"Unsupported key encapsulation identifier {kem_id}."
        raise DecryptionError(msg)
    if aead_id != AEAD_AES_256_GCM:
        msg = f"Unsupported AEAD identifier {aead_id}."
        raise DecryptionError(msg)
    if reserved != 0:
        msg = "Reserved header byte is not zero; the container is malformed."
        raise DecryptionError(msg)

    minimum = _HEADER_SIZE + wrapped_len + _NONCE_SIZE + _TAG_SIZE
    if len(blob) < minimum:
        msg = "Ciphertext is truncated."
        raise DecryptionError(msg)

    offset = _HEADER_SIZE
    wrapped_key = blob[offset : offset + wrapped_len]
    offset += wrapped_len
    nonce = blob[offset : offset + _NONCE_SIZE]
    offset += _NONCE_SIZE
    return header, wrapped_key, nonce, blob[offset:]


def decrypt(
    private_key: PrivateKeyTypes,
    blob: bytes,
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt a container produced by :func:`encrypt`.

    Args:
        private_key: RSA private key matching the public key used to encrypt.
        blob: The encrypted container.
        associated_data: The same value passed to :func:`encrypt`, if any.

    Returns:
        The original plaintext.

    Raises:
        InvalidArgumentError: If ``private_key`` is not an RSA private key.
        DecryptionError: If the container is malformed, was encrypted to a
            different key, or has been tampered with. The plaintext is never
            returned in this case, not even partially.

    Example:
        >>> from encryption_helper.keys.generate import generate_rsa
        >>> key = generate_rsa(key_size=2048)
        >>> decrypt(key, encrypt(key.public_key(), b"secret"))
        b'secret'
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        msg = (
            f"Decryption requires an RSA private key, got {type(private_key).__name__}."
        )
        raise InvalidArgumentError(msg)

    header, wrapped_key, nonce, ciphertext = _parse(blob)

    try:
        content_key = private_key.decrypt(wrapped_key, _OAEP_PADDING)
    except ValueError as exc:
        # Deliberately uniform: a wrong key and a corrupt wrapped key are not
        # distinguished, so this cannot be used as an oracle.
        msg = (
            "Could not unwrap the content key. The ciphertext was encrypted "
            "to a different key, or has been modified."
        )
        raise DecryptionError(msg) from exc

    if len(content_key) != _CONTENT_KEY_SIZE:
        msg = "Unwrapped content key has the wrong length; container is invalid."
        raise DecryptionError(msg)

    try:
        return AESGCM(content_key).decrypt(
            nonce, ciphertext, _aad(header, wrapped_key, nonce, associated_data)
        )
    except InvalidTag as exc:
        msg = (
            "Ciphertext failed its integrity check. It has been modified, or "
            "the associated data does not match."
        )
        raise DecryptionError(msg) from exc
