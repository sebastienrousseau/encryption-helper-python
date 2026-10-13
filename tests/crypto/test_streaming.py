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
from hypothesis import given, settings
from hypothesis import strategies as st

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

    @pytest.mark.parametrize("fixture", ["rsa_key", "mlkem_key", "x25519_key"])
    def test_unknown_kem_identifier_is_rejected(self, request, fixture):
        """The streaming reader skipped this check, unlike the one-shot reader.

        An unknown identifier fell through to the X25519 path: an RSA key got
        "needs an X25519 private key", and an X25519 key a misleading
        integrity failure, where both readers must name the real problem.
        """
        key = request.getfixturevalue(fixture)
        blob = seal(key, b"data")
        blob[5] = 99
        # Matches the header validator's wording specifically, so this test
        # fails if that check goes, even though _decapsulate would still
        # refuse the identifier one layer down.
        with pytest.raises(DecryptionError, match="99; this build understands"):
            open_sealed(key, bytes(blob))

    def test_decapsulate_fails_closed_on_an_unknown_identifier(self, x25519_key):
        """Defence in depth behind header validation: no fall-through."""
        from encryption_helper.crypto.envelope import _decapsulate

        with pytest.raises(DecryptionError, match="Unsupported key encapsulation"):
            _decapsulate(x25519_key, 99, bytes(32))

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


class TestReaderSegmentCap:
    """The writer picks the segment size; a reader may refuse to allocate it."""

    def test_a_segment_above_the_cap_is_refused_before_any_output(self, x25519_key):
        blob = seal(x25519_key, b"x" * 10, segment_size=SEGMENT * 2)
        out = io.BytesIO()
        with pytest.raises(DecryptionError, match="limit this reader accepts"):
            decrypt_stream(
                x25519_key, io.BytesIO(bytes(blob)), out, max_segment_size=SEGMENT
            )
        assert out.getvalue() == b""

    def test_a_segment_at_the_cap_is_accepted(self, x25519_key):
        blob = seal(x25519_key, b"x" * (SEGMENT + 1), segment_size=SEGMENT)
        plaintext = open_sealed(x25519_key, bytes(blob), max_segment_size=SEGMENT)
        assert plaintext == b"x" * (SEGMENT + 1)

    def test_the_default_cap_is_the_format_maximum(self):
        import inspect

        default = inspect.signature(decrypt_stream).parameters["max_segment_size"]
        assert default.default == MAX_SEGMENT_SIZE

    def test_streaming_is_part_of_the_public_api(self):
        import encryption_helper

        assert encryption_helper.encrypt_stream is encrypt_stream
        assert encryption_helper.decrypt_stream is decrypt_stream
        assert {"encrypt_stream", "decrypt_stream"} <= set(encryption_helper.__all__)


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


class _ShortReader(io.RawIOBase):
    """A raw stream that returns at most ``chunk`` bytes per read.

    Raw files, sockets and pipes all behave like this; ``read(n)`` returning
    fewer than ``n`` bytes before end of stream is legitimate.
    """

    def __init__(self, data: bytes, chunk: int) -> None:
        self._buffer = io.BytesIO(data)
        self._chunk = chunk

    def readable(self) -> bool:
        return True

    def readinto(self, target) -> int:
        view = memoryview(target)[: self._chunk]
        return self._buffer.readinto(view)


class _ShortWriter(io.RawIOBase):
    """A raw stream that accepts at most ``chunk`` bytes per write."""

    def __init__(self, chunk: int) -> None:
        self.sink = io.BytesIO()
        self._chunk = chunk

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        return self.sink.write(bytes(data[: self._chunk]))


class TestPartialReadsAndWrites:
    """Short reads and writes must not change the container.

    ``encrypt_stream`` used plain ``read(segment_size)``. A source returning
    fewer bytes per call produced short interior segments; encryption
    succeeded, and the reader -- which splits at fixed boundaries -- rejected
    segment 0. The plaintext was recoverable only from the original.
    """

    def test_short_reads_round_trip(self, x25519_key):
        data = bytes(range(256)) * 100  # 25,600 bytes: six full segments plus
        source = _ShortReader(data, chunk=1000)
        out = io.BytesIO()
        encrypt_stream(x25519_key.public_key(), source, out, segment_size=SEGMENT)
        assert open_sealed(x25519_key, out.getvalue()) == data

    def test_short_reads_produce_the_same_framing_as_full_reads(self, x25519_key):
        """Segment lengths depend only on the plaintext length, not on reads."""
        data = b"z" * (SEGMENT * 2 + 5)
        out = io.BytesIO()
        encrypt_stream(
            x25519_key.public_key(), _ShortReader(data, 7), out, segment_size=SEGMENT
        )
        reference = seal(x25519_key, data)
        assert len(out.getvalue()) == len(reference)

    def test_decrypting_from_a_short_reader(self, x25519_key):
        data = b"q" * (SEGMENT * 3 + 1)
        blob = bytes(seal(x25519_key, data))
        out = io.BytesIO()
        decrypt_stream(x25519_key, _ShortReader(blob, 333), out)
        assert out.getvalue() == data

    def test_short_writes_are_completed(self, x25519_key):
        data = b"w" * (SEGMENT * 2 + 9)
        sink = _ShortWriter(chunk=100)
        encrypt_stream(
            x25519_key.public_key(), io.BytesIO(data), sink, segment_size=SEGMENT
        )
        assert open_sealed(x25519_key, sink.sink.getvalue()) == data

        plain = _ShortWriter(chunk=50)
        decrypt_stream(x25519_key, io.BytesIO(sink.sink.getvalue()), plain)
        assert plain.sink.getvalue() == data

    def test_a_sink_returning_none_is_treated_as_complete(self, x25519_key):
        """Arbitrary file-likes that return nothing kept working before; still do."""

        class Sink:
            def __init__(self) -> None:
                self.parts: list[bytes] = []

            def write(self, data):
                self.parts.append(bytes(data))

        sink = Sink()
        encrypt_stream(x25519_key.public_key(), io.BytesIO(b"abc"), sink)
        assert open_sealed(x25519_key, b"".join(sink.parts)) == b"abc"

    def test_a_sink_that_accepts_nothing_raises_rather_than_spinning(self, x25519_key):
        class Stuck(io.RawIOBase):
            def writable(self) -> bool:
                return True

            def write(self, data) -> int:
                return 0

        with pytest.raises(OSError, match="accepted no bytes"):
            encrypt_stream(x25519_key.public_key(), io.BytesIO(b"abc"), Stuck())

    @given(
        size=st.integers(min_value=0, max_value=SEGMENT * 4),
        chunk=st.integers(min_value=1, max_value=SEGMENT * 2),
    )
    @settings(max_examples=40, deadline=None)
    def test_any_read_size_round_trips(self, x25519_key, size, chunk):
        data = bytes(i % 251 for i in range(size))
        out = io.BytesIO()
        encrypt_stream(
            x25519_key.public_key(),
            _ShortReader(data, chunk),
            out,
            segment_size=SEGMENT,
        )
        assert open_sealed(x25519_key, out.getvalue()) == data


class TestContentKeyLength:
    """A sender can wrap a key of any length with RSA-OAEP.

    The one-shot reader always rejected anything but a 256-bit content key;
    the streaming reader once handed the unwrapped bytes straight to AES-GCM,
    so a 128-bit key was accepted and a 40-bit one escaped as a bare
    ``ValueError``. Both readers now share the check inside decapsulation.
    """

    @staticmethod
    def _forge(rsa_key, content_key: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from encryption_helper.crypto import envelope, streaming

        genuine = seal(rsa_key, b"")
        size = envelope.HEADER_STRUCT.size
        magic, version, kem_id, aead_id, reserved, encap_len = (
            envelope.HEADER_STRUCT.unpack(bytes(genuine[:size]))
        )
        start = size + encap_len
        stream_header = bytes(genuine[start : start + streaming._STREAM_HEADER_SIZE])
        prefix = stream_header[streaming._STREAM_HEADER_STRUCT.size :]

        wrapped = rsa_key.public_key().encrypt(content_key, envelope._OAEP_PADDING)
        header = envelope.HEADER_STRUCT.pack(
            magic, version, kem_id, aead_id, reserved, len(wrapped)
        )
        try:
            sealed = AESGCM(content_key).encrypt(
                streaming._segment_nonce(prefix, 0, final=True),
                b"forged",
                header + wrapped + stream_header,
            )
        except ValueError:  # Not a usable AES key at all.
            sealed = bytes(16)
        return header + wrapped + stream_header + sealed

    @pytest.mark.parametrize("length", [5, 16, 24, 31, 33])
    def test_a_wrongly_sized_content_key_is_rejected(self, rsa_key, length):
        blob = self._forge(rsa_key, b"\x01" * length)
        with pytest.raises(DecryptionError, match="Could not recover the content key"):
            open_sealed(rsa_key, blob)

    def test_the_correct_length_is_what_the_check_admits(self, rsa_key):
        blob = self._forge(rsa_key, b"\x01" * 32)
        assert open_sealed(rsa_key, blob) == b"forged"


def _peak_in_segments(run, segment_size: int) -> float:
    """Peak traced allocation during ``run()``, in units of one segment."""
    import tracemalloc

    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        run()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak / segment_size


class _Sink:
    """A destination that keeps nothing, so only the codec's own memory counts."""

    def write(self, data) -> int:
        return len(data)


class TestMemoryBound:
    """The docstrings promise a peak in segments; hold the code to it.

    Decryption once kept the previous segment's plaintext alive while the
    next was decrypted, peaking at four segments while documented as three.
    The bound below has half a segment of margin for interpreter noise, so a
    regression to four fails.
    """

    SEGMENT_SIZE = 256 * 1024

    def _container(self, key, data: bytes) -> bytes:
        out = io.BytesIO()
        encrypt_stream(
            key.public_key(), io.BytesIO(data), out, segment_size=self.SEGMENT_SIZE
        )
        return out.getvalue()

    def test_decryption_peaks_at_three_segments(self, x25519_key):
        blob = self._container(x25519_key, b"a" * (self.SEGMENT_SIZE * 8 + 5))
        source = io.BytesIO(blob)
        peak = _peak_in_segments(
            lambda: decrypt_stream(x25519_key, source, _Sink()), self.SEGMENT_SIZE
        )
        assert peak < 3.5

    def test_encryption_peaks_at_three_segments(self, x25519_key):
        source = io.BytesIO(b"a" * (self.SEGMENT_SIZE * 8 + 5))
        peak = _peak_in_segments(
            lambda: encrypt_stream(
                x25519_key.public_key(),
                source,
                _Sink(),
                segment_size=self.SEGMENT_SIZE,
            ),
            self.SEGMENT_SIZE,
        )
        assert peak < 3.5


class TestSegmentCountLimit:
    """The reader enforces the same segment ceiling as the writer.

    The counter is four bytes. Without the check, segment 2**32 made
    ``int.to_bytes`` raise a bare ``OverflowError`` instead of the library's
    error; the ceiling is lowered here so the test does not need 16 TiB.
    """

    def test_a_container_past_the_ceiling_is_rejected(self, x25519_key, monkeypatch):
        from encryption_helper.crypto import streaming

        blob = bytes(seal(x25519_key, b"s" * (SEGMENT * 3 + 1)))  # segments 0..3
        monkeypatch.setattr(streaming, "_MAX_SEGMENTS", 2)
        with pytest.raises(DecryptionError, match="maximum number of segments"):
            open_sealed(x25519_key, blob)

    def test_a_container_at_the_ceiling_is_accepted(self, x25519_key, monkeypatch):
        from encryption_helper.crypto import streaming

        data = b"s" * (SEGMENT * 2 + 1)  # segments 0..2
        blob = bytes(seal(x25519_key, data))
        monkeypatch.setattr(streaming, "_MAX_SEGMENTS", 2)
        assert open_sealed(x25519_key, blob) == data
