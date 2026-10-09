# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Reading a container's header without decrypting it.

Two questions come up repeatedly and neither needs a private key:

* *Which algorithm protects this file?* Answering this for an inventory or a
  review does not require the private key, and the key should not be supplied
  in order to answer it. The header states which mechanism the writer used; it
  is authenticated, so it cannot be altered undetected, but it is not evidence
  of a FIPS validation. See :data:`~encryption_helper.policy.VALIDATION_NOTE`.
* *Can this build read this file?* A container written by a newer version
  states its format version in clear, so the answer is available before a
  decryption is attempted and fails.

The header is deliberately not confidential. It carries no key material and
no information about the plaintext beyond its approximate length, and it is
covered by the authenticated encryption as associated data, so altering it
causes decryption to fail rather than to succeed differently.

Example:
    >>> from encryption_helper import generate, encrypt
    >>> key = generate("x25519")
    >>> container = encrypt(key.public_key(), b"payload")
    >>> info = describe_container(container)
    >>> info.key_establishment
    'x25519-hkdf-sha256'
    >>> info.quantum_vulnerable
    True
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ..errors import InvalidArgumentError
from .envelope import (
    AEAD_AES_256_GCM,
    AEAD_AES_256_GCM_STREAM,
    HEADER_STRUCT,
    KEM_MLKEM768,
    KEM_MLKEM1024,
    KEM_RSA_OAEP_SHA256,
    KEM_X25519_HKDF,
    MAGIC,
    QUANTUM_VULNERABLE_KEMS,
    VERSION,
)

__all__ = [
    "HEADER_SIZE",
    "ContainerInfo",
    "describe_container",
    "is_container",
]

#: Bytes that must be available before a container can be described. A
#: caller reading from a stream need read no more than this.
HEADER_SIZE: Final = HEADER_STRUCT.size

#: Human-readable name for each key-establishment mechanism identifier.
_KEM_NAMES: Final = {
    KEM_RSA_OAEP_SHA256: "rsa-oaep-sha256",
    KEM_MLKEM768: "ml-kem-768",
    KEM_MLKEM1024: "ml-kem-1024",
    KEM_X25519_HKDF: "x25519-hkdf-sha256",
}

#: The standard each mechanism comes from, for a report that must cite one.
_KEM_STANDARDS: Final = {
    KEM_RSA_OAEP_SHA256: "RFC 8017 (PKCS #1 v2.2)",
    KEM_MLKEM768: "FIPS 203",
    KEM_MLKEM1024: "FIPS 203",
    KEM_X25519_HKDF: "RFC 7748, RFC 5869",
}

#: Human-readable name for each content-encryption mode identifier.
_AEAD_NAMES: Final = {
    AEAD_AES_256_GCM: "aes-256-gcm",
    AEAD_AES_256_GCM_STREAM: "aes-256-gcm-segmented",
}


@dataclass(frozen=True)
class ContainerInfo:
    """What a container's header states about itself.

    Attributes:
        format_version: Container format version. A value above
            :data:`~encryption_helper.crypto.envelope.VERSION` cannot be read
            by this build.
        readable: Whether this build can read this format version.
        key_establishment: Name of the mechanism protecting the content key,
            or :data:`None` if the identifier is not one this build knows.
        key_establishment_id: The raw identifier from the header.
        key_establishment_standard: Publication specifying the mechanism, or
            :data:`None` if unrecognised.
        content_encryption: Name of the content-encryption mode, or
            :data:`None` if unrecognised.
        content_encryption_id: The raw identifier from the header.
        segmented: Whether the content is encrypted in independently
            authenticated segments, which is how arbitrarily large inputs are
            handled at constant memory.
        quantum_vulnerable: Whether the key-establishment mechanism is broken
            by a cryptanalytically relevant quantum computer. For stored
            data this is a present concern, not a future one: a container
            recorded today can be decrypted once such a computer exists.
    """

    format_version: int
    readable: bool
    key_establishment: str | None
    key_establishment_id: int
    key_establishment_standard: str | None
    content_encryption: str | None
    content_encryption_id: int
    segmented: bool
    quantum_vulnerable: bool

    def as_dict(self) -> dict[str, object]:
        """Return the description as a JSON-serialisable mapping."""
        return {
            "format_version": self.format_version,
            "readable": self.readable,
            "key_establishment": self.key_establishment,
            "key_establishment_id": self.key_establishment_id,
            "key_establishment_standard": self.key_establishment_standard,
            "content_encryption": self.content_encryption,
            "content_encryption_id": self.content_encryption_id,
            "segmented": self.segmented,
            "quantum_vulnerable": self.quantum_vulnerable,
        }


def is_container(blob: bytes) -> bool:
    """Report whether ``blob`` begins with this library's container header.

    Args:
        blob: At least :data:`HEADER_SIZE` bytes from the start of the data.

    Returns:
        Whether the magic number matches. A false result means the data was
        not produced by this library; it does not mean the data is damaged.

    Example:
        >>> is_container(b"not a container at all")
        False
    """
    return len(blob) >= len(MAGIC) and blob[: len(MAGIC)] == MAGIC


def describe_container(blob: bytes) -> ContainerInfo:
    """Describe a container from its header alone.

    No private key is required and no plaintext is recovered. Unrecognised
    identifiers are reported as :data:`None` with the raw value preserved,
    rather than raising: a container written by a newer version should still
    be describable enough to explain why it cannot be read.

    Args:
        blob: The container, or at least its first :data:`HEADER_SIZE` bytes.

    Returns:
        The :class:`ContainerInfo` the header states.

    Raises:
        InvalidArgumentError: If ``blob`` is too short to contain a header,
            or does not carry this library's magic number.

    Example:
        >>> describe_container(
        ...     b"EHEV" + bytes([1, 2, 2, 0]) + (1088).to_bytes(2, "big")
        ... )
        ... # doctest: +ELLIPSIS
        ContainerInfo(format_version=1, readable=True, ...)
    """
    if len(blob) < HEADER_SIZE:
        msg = (
            f"Need at least {HEADER_SIZE} bytes to describe a container, "
            f"got {len(blob)}."
        )
        raise InvalidArgumentError(msg)
    if not is_container(blob):
        msg = (
            "This data does not carry the encryption-helper container "
            "header, so it was not produced by this library."
        )
        raise InvalidArgumentError(msg)

    _, version, kem_id, aead_id, _, _ = HEADER_STRUCT.unpack(blob[:HEADER_SIZE])
    return ContainerInfo(
        format_version=version,
        readable=version <= VERSION,
        key_establishment=_KEM_NAMES.get(kem_id),
        key_establishment_id=kem_id,
        key_establishment_standard=_KEM_STANDARDS.get(kem_id),
        content_encryption=_AEAD_NAMES.get(aead_id),
        content_encryption_id=aead_id,
        segmented=aead_id == AEAD_AES_256_GCM_STREAM,
        quantum_vulnerable=kem_id in QUANTUM_VULNERABLE_KEMS,
    )
