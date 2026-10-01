# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Streaming authenticated encryption, for data too large to hold in memory.

:func:`~encryption_helper.crypto.envelope.encrypt` holds the whole message in
memory, and peak usage measures at roughly four times the payload. That is
fine for keys, credentials and documents, and hopeless for a 5 GB file.

This module encrypts in fixed-size segments so memory stays bounded at a few
hundred kilobytes regardless of input size.

Construction
------------

The segment framing is Tink's **STREAM**, not a new design. Each segment gets
a distinct nonce built from three parts::

    nonce = prefix (7 bytes) || segment number (4 bytes, big endian) || final (1 byte)

That single 12-byte value defends three properties at once:

* the **random prefix** stops nonce reuse across messages under the same key;
* the **segment number** stops segments being reordered or dropped, because
  moving a segment changes the nonce it must be opened with;
* the **final flag** stops truncation -- the last segment is cryptographically
  marked as last, so a truncated stream fails rather than decrypting to a
  shorter plaintext.

Truncation resistance is the property naive chunked AEADs miss. Each segment
is individually authenticated, so an attacker cannot forge one, but without a
final marker they can simply stop early and the recipient cannot tell.

The container header and the KEM encapsulation are fed to every segment as
associated data, so the framing is bound to the ciphertext and altering the
header is detected rather than reinterpreted.

Compatibility
-------------

Streaming is a distinct AEAD identifier (``aead_id = 2``), so a one-shot
container stays readable and a streaming container is self-describing. The
reader dispatches on the header; callers do not have to know which they have.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Callable
from typing import IO, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import DecryptionError, InvalidArgumentError
from .envelope import (
    _HEADER_STRUCT,
    _TAG_SIZE,
    AEAD_AES_256_GCM_STREAM,
    MAGIC,
    VERSION,
    _decapsulate,
    _encapsulate,
    _kem_for_public_key,
)

#: Called with the cumulative plaintext byte count after each segment.
#:
#: The library never prints. A caller that wants progress supplies a callback
#: and owns the presentation, which keeps `cli/` the only layer that writes
#: to a terminal.
ProgressCallback = Callable[[int], None]

__all__ = [
    "DEFAULT_SEGMENT_SIZE",
    "MAX_SEGMENT_SIZE",
    "MIN_SEGMENT_SIZE",
    "ProgressCallback",
    "decrypt_stream",
    "encrypt_stream",
]

#: Plaintext bytes per segment.
#:
#: 256 KiB measured fastest across 5 MiB to 5 GiB on the development machine.
#: Smaller segments pay the per-segment tag and Python call overhead too
#: often; larger ones stop fitting comfortably in L2/L3 cache and start
#: costing more in memory traffic than they save in overhead.
DEFAULT_SEGMENT_SIZE: Final = 256 * 1024

#: Smallest permitted segment. Below this the 16-byte tag per segment becomes
#: a significant fraction of the output.
MIN_SEGMENT_SIZE: Final = 4 * 1024

#: Largest permitted segment. Bounds peak memory: a reader must hold one
#: segment plus its tag.
MAX_SEGMENT_SIZE: Final = 64 * 1024 * 1024

#: Nonce layout: 7-byte random prefix, 4-byte segment counter, 1-byte final
#: flag. Sums to the 12 bytes AES-GCM expects.
_PREFIX_SIZE: Final = 7
_COUNTER_SIZE: Final = 4
_FINAL_SIZE: Final = 1

#: ``segment size`` as a big-endian uint32, stored so the reader can allocate
#: correctly without guessing.
_STREAM_HEADER_STRUCT: Final = struct.Struct(">I")
_STREAM_HEADER_SIZE: Final = _STREAM_HEADER_STRUCT.size + _PREFIX_SIZE

#: Highest segment number a 4-byte counter can express. At the maximum
#: segment size this bounds a single stream at 256 PiB, which is not a
#: practical limit; at the minimum it is still 16 TiB.
_MAX_SEGMENTS: Final = 2**32 - 1


def _segment_nonce(prefix: bytes, number: int, *, final: bool) -> bytes:
    """Build the nonce for one segment.

    Args:
        prefix: The stream's 7-byte random prefix.
        number: Zero-based segment number.
        final: Whether this is the last segment.

    Returns:
        A 12-byte nonce unique to this segment of this stream.
    """
    return (
        prefix + number.to_bytes(_COUNTER_SIZE, "big") + (b"\x01" if final else b"\x00")
    )


def _validate_segment_size(segment_size: int) -> None:
    """Reject a segment size outside the permitted range.

    Raises:
        InvalidArgumentError: If the size is out of range.
    """
    if not MIN_SEGMENT_SIZE <= segment_size <= MAX_SEGMENT_SIZE:
        msg = (
            f"Segment size {segment_size} is outside the permitted range "
            f"{MIN_SEGMENT_SIZE}..{MAX_SEGMENT_SIZE} bytes."
        )
        raise InvalidArgumentError(msg)


def encrypt_stream(  # noqa: PLR0913 - three of six are keyword-only options
    public_key: PublicKeyTypes,
    source: IO[bytes],
    destination: IO[bytes],
    *,
    associated_data: bytes = b"",
    segment_size: int = DEFAULT_SEGMENT_SIZE,
    progress: ProgressCallback | None = None,
) -> int:
    """Encrypt ``source`` into ``destination`` in bounded memory.

    Args:
        public_key: Recipient's public key. RSA, ML-KEM or X25519.
        source: Readable binary stream.
        destination: Writable binary stream.
        associated_data: Optional context to authenticate but not encrypt.
            The same value must be given to :func:`decrypt_stream`.
        segment_size: Plaintext bytes per segment.
        progress: Optional callback invoked with the cumulative plaintext byte
            count after each segment. Throttling and formatting are the
            caller's concern.

    Returns:
        The number of plaintext bytes read.

    Raises:
        InvalidArgumentError: If the key cannot encrypt, or the segment size
            is out of range.

    Example:
        >>> import io
        >>> from encryption_helper.keys.generate import generate_x25519
        >>> key = generate_x25519()
        >>> out = io.BytesIO()
        >>> encrypt_stream(key.public_key(), io.BytesIO(b"hello"), out)
        5
    """
    _validate_segment_size(segment_size)
    kem_id = _kem_for_public_key(public_key)
    content_key, encapsulation = _encapsulate(public_key, kem_id)

    header = _HEADER_STRUCT.pack(
        MAGIC, VERSION, kem_id, AEAD_AES_256_GCM_STREAM, 0, len(encapsulation)
    )
    prefix = os.urandom(_PREFIX_SIZE)
    stream_header = _STREAM_HEADER_STRUCT.pack(segment_size) + prefix

    destination.write(header)
    destination.write(encapsulation)
    destination.write(stream_header)

    aead = AESGCM(content_key)
    aad = header + encapsulation + stream_header + associated_data

    total = 0
    number = 0
    # Read one segment ahead, so the final segment can be flagged as final
    # without seeking or knowing the input length up front. That is what makes
    # this work on a pipe.
    current = source.read(segment_size)
    while True:
        following = source.read(segment_size)
        final = not following
        if number > _MAX_SEGMENTS:  # pragma: no cover - 256 PiB of input
            msg = "Input exceeds the maximum number of segments."
            raise InvalidArgumentError(msg)
        destination.write(
            aead.encrypt(_segment_nonce(prefix, number, final=final), current, aad)
        )
        total += len(current)
        if progress is not None:
            progress(total)
        if final:
            break
        current = following
        number += 1

    return total


def _read_exact(source: IO[bytes], count: int) -> bytes:
    """Read exactly ``count`` bytes, or fewer at end of stream."""
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _parse_stream_header(
    source: IO[bytes],
) -> tuple[bytes, int, bytes, bytes, int, bytes]:
    """Read and validate a streaming container's framing.

    Returns:
        ``(header, kem_id, encapsulation, stream_header, segment_size,
        prefix)``.

    Raises:
        DecryptionError: If the framing is malformed, truncated, or not a
            streaming container.
    """
    header = _read_exact(source, _HEADER_STRUCT.size)
    if len(header) < _HEADER_STRUCT.size:
        msg = "Ciphertext is too short to be a valid container."
        raise DecryptionError(msg)

    magic, version, kem_id, aead_id, reserved, encap_len = _HEADER_STRUCT.unpack(header)
    if magic != MAGIC:
        msg = "Not an encryption-helper container: bad magic bytes."
        raise DecryptionError(msg)
    if version != VERSION:
        msg = f"Unsupported container version {version}; this build reads {VERSION}."
        raise DecryptionError(msg)
    if aead_id != AEAD_AES_256_GCM_STREAM:
        msg = (
            f"This is not a streaming container (aead_id {aead_id}). Use "
            "decrypt() for a one-shot container."
        )
        raise DecryptionError(msg)
    if reserved != 0:
        msg = "Reserved header byte is not zero; the container is malformed."
        raise DecryptionError(msg)

    encapsulation = _read_exact(source, encap_len)
    stream_header = _read_exact(source, _STREAM_HEADER_SIZE)
    if len(encapsulation) < encap_len or len(stream_header) < _STREAM_HEADER_SIZE:
        msg = "Ciphertext is truncated before the segment header."
        raise DecryptionError(msg)

    size_bytes = stream_header[: _STREAM_HEADER_STRUCT.size]
    (segment_size,) = _STREAM_HEADER_STRUCT.unpack(size_bytes)
    prefix = stream_header[_STREAM_HEADER_STRUCT.size :]
    try:
        _validate_segment_size(segment_size)
    except InvalidArgumentError as exc:
        msg = f"Container declares an unusable segment size: {exc}"
        raise DecryptionError(msg) from exc

    return header, kem_id, encapsulation, stream_header, segment_size, prefix


def decrypt_stream(
    private_key: PrivateKeyTypes,
    source: IO[bytes],
    destination: IO[bytes],
    *,
    associated_data: bytes = b"",
    progress: ProgressCallback | None = None,
) -> int:
    """Decrypt a streaming container into ``destination`` in bounded memory.

    Plaintext is written segment by segment as it is authenticated, so memory
    stays bounded. A segment is never written before its tag verifies -- but
    note that earlier segments *are* already written when a later one fails,
    so a caller writing to a final destination should treat a failure as
    leaving that destination incomplete. The CLI writes to a temporary file
    and renames only on success.

    Args:
        private_key: Recipient's private key.
        source: Readable binary stream positioned at the container start.
        destination: Writable binary stream.
        associated_data: The same value given to :func:`encrypt_stream`.
        progress: Optional callback invoked with the cumulative plaintext byte
            count after each authenticated segment.

    Returns:
        The number of plaintext bytes written.

    Raises:
        InvalidArgumentError: If the key type cannot decrypt.
        DecryptionError: If the container is malformed, truncated, reordered,
            encrypted to a different key, or tampered with.

    Example:
        >>> import io
        >>> from encryption_helper.keys.generate import generate_x25519
        >>> key = generate_x25519()
        >>> sealed = io.BytesIO()
        >>> _ = encrypt_stream(key.public_key(), io.BytesIO(b"hello"), sealed)
        >>> out = io.BytesIO()
        >>> decrypt_stream(key, io.BytesIO(sealed.getvalue()), out)
        5
        >>> out.getvalue()
        b'hello'
    """
    header, kem_id, encapsulation, stream_header, segment_size, prefix = (
        _parse_stream_header(source)
    )

    content_key = _decapsulate(private_key, kem_id, encapsulation)
    aead = AESGCM(content_key)
    aad = header + encapsulation + stream_header + associated_data

    sealed_size = segment_size + _TAG_SIZE
    total = 0
    number = 0
    current = _read_exact(source, sealed_size)
    if not current:
        msg = "Ciphertext contains no segments."
        raise DecryptionError(msg)

    while True:
        following = _read_exact(source, sealed_size)
        final = not following
        nonce = _segment_nonce(prefix, number, final=final)
        try:
            plaintext = aead.decrypt(nonce, current, aad)
        except InvalidTag as exc:
            # A failure here covers tampering, truncation (the segment is not
            # actually final), reordering (wrong counter) and a wrong key.
            # They are deliberately indistinguishable.
            msg = (
                f"Segment {number} failed its integrity check. The ciphertext "
                "has been modified, truncated, reordered, or was encrypted to "
                "a different key."
            )
            raise DecryptionError(msg) from exc
        destination.write(plaintext)
        total += len(plaintext)
        if progress is not None:
            progress(total)
        if final:
            break
        current = following
        number += 1

    return total
