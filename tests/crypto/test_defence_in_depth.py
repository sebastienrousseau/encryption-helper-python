# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Direct tests for defence-in-depth properties.

Mutation testing found three properties that the end-to-end suite could not
see, despite 100% statement and branch coverage:

* the KEM identifier is mixed into the HKDF ``info``;
* the container framing is authenticated as associated data;
* each stream gets a random nonce prefix.

Removing any of them left all 674 tests passing. That is not because the
tests were lazy -- it is because each property is *redundant* end to end. The
KEM identifier is already validated against the key type, every header field
is already range-checked, and a fresh content key is agreed per message, so
none of the three is individually load-bearing for an attack the suite could
construct.

They are defence in depth: the layer that holds when one of the others is
later weakened by a refactor. Redundancy is exactly what makes a property
invisible to end-to-end testing and exactly why it needs asserting directly.
These tests therefore target the functions, not the round trip.
"""

from __future__ import annotations

import io

import pytest
from encryption_helper.crypto import envelope
from encryption_helper.crypto.streaming import (
    _PREFIX_SIZE,
    _STREAM_HEADER_STRUCT,
    encrypt_stream,
)


class TestKdfDomainSeparation:
    """The KEM identifier is mixed into HKDF ``info``.

    Without it, one shared secret derives the same content key under every
    mechanism. End to end this is masked by the key-type check, which rejects
    a relabelled container before the KDF matters.
    """

    SECRET = b"\x5a" * 32

    def test_each_mechanism_derives_a_different_key(self):
        derived = {
            kem: envelope._derive_content_key(self.SECRET, kem)
            for kem in sorted(envelope.SUPPORTED_KEMS)
        }
        assert len(set(derived.values())) == len(derived), (
            "two mechanisms derived the same content key from one secret"
        )

    def test_derivation_is_deterministic(self):
        first = envelope._derive_content_key(self.SECRET, envelope.KEM_MLKEM768)
        second = envelope._derive_content_key(self.SECRET, envelope.KEM_MLKEM768)
        assert first == second

    def test_different_secrets_derive_different_keys(self):
        a = envelope._derive_content_key(b"\x01" * 32, envelope.KEM_MLKEM768)
        b = envelope._derive_content_key(b"\x02" * 32, envelope.KEM_MLKEM768)
        assert a != b

    def test_derived_key_is_the_aead_key_length(self):
        key = envelope._derive_content_key(self.SECRET, envelope.KEM_MLKEM768)
        assert len(key) == envelope._CONTENT_KEY_SIZE == 32

    def test_info_string_is_versioned(self):
        """Changing the info string changes every derived key, so it is
        versioned and must not be edited without a new identifier."""
        assert b"/v1 " in envelope._HKDF_INFO


class TestAssociatedDataCoversTheFraming:
    """Every framing byte is fed to the AEAD.

    End to end this is redundant: the header fields are separately validated,
    so a tampered header is rejected before the tag is checked. The property
    still has to hold, because those validations are what it backs up.
    """

    def test_aad_includes_every_component(self):
        aad = envelope._aad(b"HEADER", b"ENCAP", b"NONCE", b"EXTRA")
        for component in (b"HEADER", b"ENCAP", b"NONCE", b"EXTRA"):
            assert component in aad, f"{component!r} is not authenticated"

    def test_aad_is_the_concatenation_in_order(self):
        assert envelope._aad(b"A", b"B", b"C", b"D") == b"ABCD"

    def test_changing_any_component_changes_the_aad(self):
        base = envelope._aad(b"H", b"E", b"N", b"X")
        for args in (
            (b"h", b"E", b"N", b"X"),
            (b"H", b"e", b"N", b"X"),
            (b"H", b"E", b"n", b"X"),
            (b"H", b"E", b"N", b"x"),
        ):
            assert envelope._aad(*args) != base

    def test_aad_is_not_just_the_caller_context(self):
        """The regression this guards: returning only `extra` keeps the
        caller's associated data working, so context tests still pass while
        the framing becomes unauthenticated."""
        assert envelope._aad(b"H", b"E", b"N", b"X") != b"X"


class TestStreamNoncePrefixIsRandom:
    """Each stream gets a fresh random nonce prefix.

    End to end this is redundant too: a new content key is agreed per message,
    so a fixed prefix cannot cause nonce reuse under the same key today. It is
    the layer that holds if a content key is ever reused.
    """

    @staticmethod
    def _prefix(blob: bytes, encap_len: int) -> bytes:
        """Pull the nonce prefix out of a container's stream header."""
        offset = envelope._HEADER_SIZE + encap_len + _STREAM_HEADER_STRUCT.size
        return blob[offset : offset + _PREFIX_SIZE]

    def _seal(self, key) -> bytes:
        out = io.BytesIO()
        encrypt_stream(key.public_key(), io.BytesIO(b"payload"), out)
        return out.getvalue()

    def test_two_streams_get_different_prefixes(self, x25519_key):
        first = self._prefix(self._seal(x25519_key), 32)
        second = self._prefix(self._seal(x25519_key), 32)
        assert first != second, "the nonce prefix is fixed, not random"

    def test_prefix_is_not_all_zeroes(self, x25519_key):
        assert self._prefix(self._seal(x25519_key), 32) != bytes(_PREFIX_SIZE)

    def test_prefix_is_the_documented_length(self, x25519_key):
        assert len(self._prefix(self._seal(x25519_key), 32)) == _PREFIX_SIZE == 7

    def test_prefixes_vary_across_many_streams(self, x25519_key):
        """A weak source could still produce a small set of values."""
        prefixes = {self._prefix(self._seal(x25519_key), 32) for _ in range(12)}
        assert len(prefixes) == 12, "the nonce prefix repeats across streams"

    @pytest.mark.parametrize("fixture", ["rsa_key", "mlkem_key"])
    def test_prefix_is_random_for_every_mechanism(self, request, fixture):
        key = request.getfixturevalue(fixture)
        encap = {"rsa_key": 256, "mlkem_key": 1088}[fixture]
        first = self._prefix(self._seal(key), encap)
        second = self._prefix(self._seal(key), encap)
        assert first != second
