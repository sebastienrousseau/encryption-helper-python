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
from cryptography.hazmat.primitives.asymmetric import mlkem, padding, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..errors import DecryptionError, InvalidArgumentError

__all__ = [
    "MAGIC",
    "SUPPORTED_KEMS",
    "VERSION",
    "decrypt",
    "encrypt",
]

#: Container magic, identifying the format in a hex dump or file(1) rule.
MAGIC: Final = b"EHEV"

#: Container format version. Incremented only for breaking format changes.
VERSION: Final = 1

#: Key encapsulation mechanism identifiers.
#:
#: The identifier is a byte in the container header, so a recipient always
#: knows which mechanism produced a ciphertext and an old container stays
#: readable after a new mechanism is added. This is the agility hook: adding
#: a mechanism means adding an identifier and a branch, never a format break.
KEM_RSA_OAEP_SHA256: Final = 1
KEM_MLKEM768: Final = 2
KEM_MLKEM1024: Final = 3
KEM_X25519_HKDF: Final = 4

#: Every mechanism this build can read.
SUPPORTED_KEMS: Final = frozenset(
    {KEM_RSA_OAEP_SHA256, KEM_MLKEM768, KEM_MLKEM1024, KEM_X25519_HKDF}
)

#: Mechanisms that a sufficiently large quantum computer breaks.
QUANTUM_VULNERABLE_KEMS: Final = frozenset({KEM_RSA_OAEP_SHA256, KEM_X25519_HKDF})

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

_RSA_LABEL: Final = "an RSA"
_MLKEM_LABEL: Final = "an ML-KEM"
_X25519_LABEL: Final = "an X25519"

#: HKDF domain separation. Changing this string changes every derived key, so
#: it is versioned and must not be edited without a new KEM identifier.
_HKDF_INFO: Final = b"encryption-helper/v1 content-key"


def _derive_content_key(shared_secret: bytes, kem_id: int) -> bytes:
    """Derive the AEAD content key from a KEM shared secret.

    The KEM identifier is mixed into the HKDF ``info``, so the same shared
    secret under two different mechanisms cannot yield the same content key.

    Args:
        shared_secret: Raw secret from encapsulation or key agreement.
        kem_id: The mechanism that produced it.

    Returns:
        A :data:`_CONTENT_KEY_SIZE`-byte key.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_CONTENT_KEY_SIZE,
        salt=None,
        info=_HKDF_INFO + bytes([kem_id]),
    ).derive(shared_secret)


def _kem_for_public_key(public_key: PublicKeyTypes) -> int:
    """Select the KEM identifier a public key implies.

    Raises:
        InvalidArgumentError: If the key type cannot encrypt.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return KEM_RSA_OAEP_SHA256
    if isinstance(public_key, mlkem.MLKEM768PublicKey):
        return KEM_MLKEM768
    if isinstance(public_key, mlkem.MLKEM1024PublicKey):
        return KEM_MLKEM1024
    if isinstance(public_key, x25519.X25519PublicKey):
        return KEM_X25519_HKDF
    raise _cannot_encrypt(public_key)


def _aad(header: bytes, encapsulation: bytes, nonce: bytes, extra: bytes) -> bytes:
    """Build the associated data binding the framing to the ciphertext.

    Every byte of framing is authenticated, so altering the header, the
    encapsulation or the nonce is detected as tampering rather than silently
    reinterpreted.
    """
    return header + encapsulation + nonce + extra


def _encapsulate(public_key: PublicKeyTypes, kem_id: int) -> tuple[bytes, bytes]:
    """Produce the per-message content key and the bytes the recipient needs.

    Args:
        public_key: Recipient's public key.
        kem_id: Mechanism chosen by :func:`_kem_for_public_key`.

    Returns:
        A ``(content_key, encapsulation)`` pair. The encapsulation is stored in
        the container: the RSA-wrapped key, the ML-KEM ciphertext, or the
        ephemeral X25519 public key, depending on the mechanism.

    Raises:
        InvalidArgumentError: If the key cannot carry a content key.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        # RSA wraps a content key directly rather than agreeing one, so no
        # KDF is involved: the random key *is* the content key.
        content_key = os.urandom(_CONTENT_KEY_SIZE)
        try:
            return content_key, public_key.encrypt(content_key, _OAEP_PADDING)
        except ValueError as exc:
            msg = (
                f"RSA key is too small to wrap a {_CONTENT_KEY_SIZE * 8}-bit "
                f"content key with OAEP-SHA256: {exc}"
            )
            raise InvalidArgumentError(msg) from exc

    if isinstance(public_key, mlkem.MLKEM768PublicKey | mlkem.MLKEM1024PublicKey):
        shared_secret, ciphertext = public_key.encapsulate()
        return _derive_content_key(shared_secret, kem_id), ciphertext

    if isinstance(public_key, x25519.X25519PublicKey):
        # Ephemeral-static Diffie-Hellman, as used by age and HPKE.
        ephemeral = x25519.X25519PrivateKey.generate()
        shared_secret = ephemeral.exchange(public_key)
        return (
            _derive_content_key(shared_secret, kem_id),
            ephemeral.public_key().public_bytes_raw(),
        )

    raise _cannot_encrypt(public_key)  # pragma: no cover - guarded upstream


def _decapsulate(
    private_key: PrivateKeyTypes, kem_id: int, encapsulation: bytes
) -> bytes:
    """Recover the content key from a container's encapsulation.

    Args:
        private_key: Recipient's private key.
        kem_id: Mechanism recorded in the container header.
        encapsulation: The mechanism-specific bytes from the container.

    Returns:
        The content key.

    Raises:
        InvalidArgumentError: If the key type does not match the mechanism.
        DecryptionError: If the encapsulation cannot be processed. The message
            never distinguishes a wrong key from a corrupt container.

    Note:
        ML-KEM uses implicit rejection: decapsulating with the wrong key
        succeeds and yields an unrelated secret rather than failing. The AEAD
        tag is what rejects it, one step later.
    """
    if kem_id == KEM_RSA_OAEP_SHA256:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise _wrong_key_type(_RSA_LABEL, private_key)
        try:
            return private_key.decrypt(encapsulation, _OAEP_PADDING)
        except ValueError as exc:
            raise _opaque_kem_failure() from exc

    if kem_id in (KEM_MLKEM768, KEM_MLKEM1024):
        if not isinstance(
            private_key, mlkem.MLKEM768PrivateKey | mlkem.MLKEM1024PrivateKey
        ):
            raise _wrong_key_type(_MLKEM_LABEL, private_key)
        try:
            shared = private_key.decapsulate(encapsulation)
        except ValueError as exc:
            raise _opaque_kem_failure() from exc
        return _derive_content_key(shared, kem_id)

    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise _wrong_key_type(_X25519_LABEL, private_key)
    try:
        peer = x25519.X25519PublicKey.from_public_bytes(encapsulation)
        shared = private_key.exchange(peer)
    except ValueError as exc:
        raise _opaque_kem_failure() from exc
    return _derive_content_key(shared, kem_id)


def _cannot_encrypt(public_key: PublicKeyTypes) -> InvalidArgumentError:
    """Build the error for a key type that cannot encrypt."""
    msg = (
        f"Cannot encrypt to a {type(public_key).__name__}. Encryption requires "
        "an RSA, ML-KEM or X25519 public key; Ed25519, Ed448, ECDSA and ML-DSA "
        "keys are for signing."
    )
    return InvalidArgumentError(msg)


#: Key types that can decrypt something, whatever the mechanism.
_DECRYPTION_CAPABLE: Final = (
    rsa.RSAPrivateKey,
    mlkem.MLKEM768PrivateKey,
    mlkem.MLKEM1024PrivateKey,
    x25519.X25519PrivateKey,
)


def _wrong_key_type(
    wanted: str, private_key: PrivateKeyTypes
) -> InvalidArgumentError | DecryptionError:
    """Build the error for a key that does not match the container.

    The distinction matters. A key that can never decrypt anything -- Ed25519,
    Ed448, ECDSA, ML-DSA -- is a programming mistake, so it raises
    :class:`~encryption_helper.errors.InvalidArgumentError`. A key that *can*
    decrypt but not this container is either the wrong key file or a tampered
    header, which is indistinguishable from the outside and is a property of
    the data rather than of the call, so it raises
    :class:`~encryption_helper.errors.DecryptionError`.

    That split also keeps the property "no mutation of a container ever
    returns plaintext" expressible as a single exception type.
    """
    supplied = type(private_key).__name__
    if not isinstance(private_key, _DECRYPTION_CAPABLE):
        msg = (
            f"Cannot decrypt with a {supplied}. Decryption requires an RSA, "
            "ML-KEM or X25519 private key; Ed25519, Ed448, ECDSA and ML-DSA "
            "keys are for signing."
        )
        return InvalidArgumentError(msg)
    msg = (
        f"This ciphertext needs {wanted} private key, but a {supplied} was "
        "supplied. The key does not match the ciphertext, or the ciphertext "
        "has been modified."
    )
    return DecryptionError(msg)


def _opaque_kem_failure() -> DecryptionError:
    """Build the uniform failure used for every key-recovery error.

    Deliberately identical whatever went wrong, so it cannot be used as an
    oracle to distinguish a wrong key from a malformed container.
    """
    msg = (
        "Could not recover the content key. The ciphertext was encrypted to a "
        "different key, or has been modified."
    )
    return DecryptionError(msg)


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
    kem_id = _kem_for_public_key(public_key)

    content_key, encapsulation = _encapsulate(public_key, kem_id)

    nonce = os.urandom(_NONCE_SIZE)
    header = _HEADER_STRUCT.pack(
        MAGIC, VERSION, kem_id, AEAD_AES_256_GCM, 0, len(encapsulation)
    )
    ciphertext = AESGCM(content_key).encrypt(
        nonce, plaintext, _aad(header, encapsulation, nonce, associated_data)
    )
    return header + encapsulation + nonce + ciphertext


def _parse(blob: bytes) -> tuple[bytes, int, bytes, bytes, bytes]:
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
    if kem_id not in SUPPORTED_KEMS:
        known = ", ".join(str(k) for k in sorted(SUPPORTED_KEMS))
        msg = (
            f"Unsupported key encapsulation identifier {kem_id}; this build "
            f"understands {known}. Upgrade encryption-helper to read it."
        )
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
    encapsulation = blob[offset : offset + wrapped_len]
    offset += wrapped_len
    nonce = blob[offset : offset + _NONCE_SIZE]
    offset += _NONCE_SIZE
    return header, kem_id, encapsulation, nonce, blob[offset:]


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
    header, kem_id, encapsulation, nonce, ciphertext = _parse(blob)
    content_key = _decapsulate(private_key, kem_id, encapsulation)

    if len(content_key) != _CONTENT_KEY_SIZE:
        msg = "Recovered content key has the wrong length; container is invalid."
        raise DecryptionError(msg)

    try:
        return AESGCM(content_key).decrypt(
            nonce, ciphertext, _aad(header, encapsulation, nonce, associated_data)
        )
    except InvalidTag as exc:
        msg = (
            "Ciphertext failed its integrity check. It has been modified, or "
            "the associated data does not match."
        )
        raise DecryptionError(msg) from exc
