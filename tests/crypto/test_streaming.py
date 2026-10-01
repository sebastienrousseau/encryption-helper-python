# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for segmented (streaming) encryption.

The construction is Tink's STREAM: a 12-byte nonce built from a 7-byte random
prefix, a 4-byte segment counter and a 1-byte final flag. The tests below
check each property that layout is there to provide, because a naive chunked
AEAD gets confidentiality right and silently loses truncation resistance.
"""

from __future__ import annotations

import io

import pytest
from encryption_helper.crypto.envelope import AEAD_AES_256_GCM_STREAM, MAGIC, decrypt
from encryption_helper.crypto.streaming import (
    DEFAULT_SEGMENT_SIZE,
    MAX_SEGMENT_SIZE,
    MIN_SEGMENT_SIZE,
    decrypt_stream,
    encrypt_stream,
)
from encryption_helper.errors import DecryptionError, InvalidArgumentError

SEGMENT = 4096
#: Framing before the first segment: 10-byte header, 32-byte X25519
#: encapsulation, 11-byte stream header (4 size + 7 prefix).
OFFSET = 10 + 32 + 11
SEALED = SEGMENT + 16


def seal(key, data: bytes, *, segment_size: int = SEGMENT) -> bytearray:
    """Encrypt ``data`` and return the container as a mutable buffer."""
    out = io.BytesIO()
    encrypt_stream(key.public_key(), io.BytesIO(data), out, segment_size=segment_size)
    return bytearray(out.getvalue())


def open_sealed(key, blob: bytes, **kwargs) -> bytes:
    """Decrypt a container and return the plaintext."""
    out = io.BytesIO()
    decrypt_stream(key, io.BytesIO(blob), out, **kwargs)
    return out.getvalue()


class TestRoundTrip:
    @pytest.mark.parametrize("fixture", ["rsa_key", "mlkem_key", "x25519_key"])
    @pytest.mark.parametrize(
        "size",
        [0, 1, 15, SEGMENT - 1, SEGMENT, SEGMENT + 1, SEGMENT * 3, SEGMENT * 3 + 7],
    )
    def test_every_kem_at_every_segment_boundary(self, request, fixture, size):
        """Boundaries are where off-by-one framing errors live."""
        key = request.getfixturevalue(fixture)
        data = bytes(range(256)) * (size // 256) + b"q" * (size % 256)
        assert open_sealed(key, bytes(seal(key, data))) == data

    def test_memory_is_bounded_not_proportional(self, x25519_key):
        """A reader holds one segment, not the whole stream."""
        data = b"z" * (SEGMENT * 50)
        blob = bytes(seal(x25519_key, data))
        # The container is only marginally larger than the plaintext: one tag
        # per segment plus the fixed framing.
        overhead = len(blob) - len(data)
        assert overhead == OFFSET + 16 * 50

    def test_associated_data_round_trips(self, x25519_key):
        blob = bytes(seal(x25519_key, b"payload" * 1000))
        out = io.BytesIO()
        encrypt_stream(
            x25519_key.public_key(),
            io.BytesIO(b"bound"),
            out,
            associated_data=b"ctx",
            segment_size=SEGMENT,
        )
        assert (
            open_sealed(x25519_key, out.getvalue(), associated_data=b"ctx") == b"bound"
        )
        assert blob  # the unbound container is unaffected

    def test_mismatched_associated_data_is_rejected(self, x25519_key):
        out = io.BytesIO()
        encrypt_stream(
            x25519_key.public_key(), io.BytesIO(b"bound"), out, associated_data=b"ctx"
        )
        with pytest.raises(DecryptionError):
            open_sealed(x25519_key, out.getvalue(), associated_data=b"other")

    def test_container_is_self_describing(self, x25519_key):
        blob = seal(x25519_key, b"data")
        assert blob[:4] == MAGIC
        assert blob[6] == AEAD_AES_256_GCM_STREAM

    def test_one_shot_reader_refuses_a_streaming_container(self, x25519_key):
        """And says what to use instead."""
        blob = bytes(seal(x25519_key, b"data"))
        with pytest.raises(DecryptionError, match="streaming container"):
            decrypt(x25519_key, blob)


class TestSegmentIntegrity:
    """Each property the nonce layout exists to provide."""

    @pytest.fixture
    def data(self) -> bytes:
        return b"A" * (SEGMENT * 5 + 17)

    def test_truncation_mid_segment_is_rejected(self, x25519_key, data):
        blob = seal(x25519_key, data)
        with pytest.raises(DecryptionError, match="integrity check"):
            open_sealed(x25519_key, bytes(blob[:-100]))

    def test_truncation_at_a_segment_boundary_is_rejected(self, x25519_key, data):
        """The property a naive chunked AEAD loses: each segment is valid, so
        only the final flag reveals that the stream stopped early."""
        blob = seal(x25519_key, data)
        with pytest.raises(DecryptionError, match="integrity check"):
            open_sealed(x25519_key, bytes(blob[: OFFSET + SEALED * 3]))

    def test_reordering_is_rejected(self, x25519_key, data):
        blob = seal(x25519_key, data)
        first = blob[OFFSET : OFFSET + SEALED]
        second = blob[OFFSET + SEALED : OFFSET + 2 * SEALED]
        blob[OFFSET : OFFSET + SEALED] = second
        blob[OFFSET + SEALED : OFFSET + 2 * SEALED] = first
        with pytest.raises(DecryptionError, match="integrity check"):
            open_sealed(x25519_key, bytes(blob))

    def test_dropping_a_segment_is_rejected(self, x25519_key, data):
        blob = seal(x25519_key, data)
        del blob[OFFSET : OFFSET + SEALED]
        with pytest.raises(DecryptionError, match="integrity check"):
            open_sealed(x25519_key, bytes(blob))

    def test_appending_a_segment_is_rejected(self, x25519_key, data):
        blob = seal(x25519_key, data)
        blob.extend(blob[OFFSET : OFFSET + SEALED])
        with pytest.raises(DecryptionError, match="integrity check"):
            open_sealed(x25519_key, bytes(blob))

    def test_duplicating_the_first_segment_is_rejected(self, x25519_key, data):
        blob = seal(x25519_key, data)
        blob[OFFSET + SEALED : OFFSET + 2 * SEALED] = blob[OFFSET : OFFSET + SEALED]
        with pytest.raises(DecryptionError, match="integrity check"):
            open_sealed(x25519_key, bytes(blob))

    @pytest.mark.parametrize("position", [OFFSET + 10, OFFSET + SEALED + 10, -30, -1])
    def test_any_byte_flip_is_rejected(self, x25519_key, data, position):
        blob = seal(x25519_key, data)
        blob[position] ^= 0xFF
        with pytest.raises(DecryptionError):
            open_sealed(x25519_key, bytes(blob))

    def test_header_relabelling_is_rejected(self, x25519_key, data):
        """The header is associated data, so altering it breaks every tag."""
        blob = seal(x25519_key, data)
        blob[5] = 99
        with pytest.raises(DecryptionError):
            open_sealed(x25519_key, bytes(blob))

    def test_altered_segment_size_is_rejected(self, x25519_key, data):
        blob = seal(x25519_key, data)
        blob[OFFSET - 11] ^= 0xFF
        with pytest.raises(DecryptionError):
            open_sealed(x25519_key, bytes(blob))

    def test_wrong_key_is_rejected(self, x25519_key, data):
        from encryption_helper.keys import generate_x25519

        blob = bytes(seal(x25519_key, data))
        with pytest.raises(DecryptionError):
            open_sealed(generate_x25519(), blob)


class TestMalformedContainers:
    def test_empty_input(self, x25519_key):
        with pytest.raises(DecryptionError, match="too short"):
            open_sealed(x25519_key, b"")

    def test_bad_magic(self, x25519_key):
        with pytest.raises(DecryptionError, match="magic"):
            open_sealed(x25519_key, b"XXXX" + bytes(40))

    def test_unsupported_version(self, x25519_key):
        blob = seal(x25519_key, b"data")
        blob[4] = 99
        with pytest.raises(DecryptionError, match="Unsupported container version"):
            open_sealed(x25519_key, bytes(blob))

    def test_non_streaming_aead_id(self, x25519_key):
        blob = seal(x25519_key, b"data")
        blob[6] = 1
        with pytest.raises(DecryptionError, match="not a streaming container"):
            open_sealed(x25519_key, bytes(blob))

    def test_nonzero_reserved_byte(self, x25519_key):
        blob = seal(x25519_key, b"data")
        blob[7] = 1
        with pytest.raises(DecryptionError, match="Reserved header byte"):
            open_sealed(x25519_key, bytes(blob))

    def test_truncated_before_the_segment_header(self, x25519_key):
        blob = seal(x25519_key, b"data")
        with pytest.raises(DecryptionError, match="truncated"):
            open_sealed(x25519_key, bytes(blob[: OFFSET - 4]))

    def test_no_segments(self, x25519_key):
        blob = seal(x25519_key, b"data")
        with pytest.raises(DecryptionError, match="no segments"):
            open_sealed(x25519_key, bytes(blob[:OFFSET]))

    def test_declared_segment_size_out_of_range(self, x25519_key):
        blob = seal(x25519_key, b"data")
        blob[OFFSET - 11 : OFFSET - 7] = (MAX_SEGMENT_SIZE * 2).to_bytes(4, "big")
        with pytest.raises(DecryptionError, match="unusable segment size"):
            open_sealed(x25519_key, bytes(blob))


class TestSegmentSizeValidation:
    @pytest.mark.parametrize("size", [0, 1, MIN_SEGMENT_SIZE - 1, MAX_SEGMENT_SIZE + 1])
    def test_rejected_sizes(self, x25519_key, size):
        with pytest.raises(InvalidArgumentError, match="outside the permitted range"):
            encrypt_stream(
                x25519_key.public_key(),
                io.BytesIO(b"data"),
                io.BytesIO(),
                segment_size=size,
            )

    @pytest.mark.parametrize("size", [MIN_SEGMENT_SIZE, DEFAULT_SEGMENT_SIZE])
    def test_accepted_sizes(self, x25519_key, size):
        data = b"w" * (size + 1)
        assert (
            open_sealed(x25519_key, bytes(seal(x25519_key, data, segment_size=size)))
            == data
        )

    def test_default_is_256_kib(self):
        assert DEFAULT_SEGMENT_SIZE == 256 * 1024

    def test_segment_size_does_not_affect_the_plaintext(self, x25519_key):
        """The reader takes the size from the container, not a flag."""
        data = b"portable" * 2000
        for size in (MIN_SEGMENT_SIZE, 8192, 65536):
            assert (
                open_sealed(
                    x25519_key, bytes(seal(x25519_key, data, segment_size=size))
                )
                == data
            )


class TestKeyTypeValidation:
    @pytest.mark.parametrize("fixture", ["ed25519_key", "mldsa_key", "ecdsa_key"])
    def test_signing_keys_cannot_encrypt_a_stream(self, request, fixture):
        key = request.getfixturevalue(fixture)
        with pytest.raises(InvalidArgumentError, match="Cannot encrypt to a"):
            encrypt_stream(key.public_key(), io.BytesIO(b"d"), io.BytesIO())

    def test_wrong_key_kind_on_decrypt(self, x25519_key, mlkem_key):
        blob = bytes(seal(x25519_key, b"data"))
        with pytest.raises(DecryptionError, match="needs an"):
            open_sealed(mlkem_key, blob)
