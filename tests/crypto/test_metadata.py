# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for describing a container without decrypting it.

The point of this module is that it needs no private key, so the tests check
that too: a description must be obtainable from the header alone, and must
not require or reveal anything secret.
"""

from __future__ import annotations

import json

import pytest
from encryption_helper import encrypt, generate
from encryption_helper.crypto.envelope import (
    AEAD_AES_256_GCM,
    AEAD_AES_256_GCM_STREAM,
    HEADER_STRUCT,
    MAGIC,
    VERSION,
)
from encryption_helper.crypto.metadata import (
    HEADER_SIZE,
    describe_container,
    is_container,
)
from encryption_helper.errors import InvalidArgumentError


def header(*, version=VERSION, kem_id=1, aead_id=AEAD_AES_256_GCM, encap_len=256):
    """Build a container header with the given field values."""
    return HEADER_STRUCT.pack(MAGIC, version, kem_id, aead_id, 0, encap_len)


class TestIsContainer:
    def test_a_real_container_is_recognised(self):
        key = generate("x25519")
        assert is_container(encrypt(key.public_key(), b"payload")) is True

    def test_unrelated_data_is_not(self):
        assert is_container(b"-----BEGIN PUBLIC KEY-----") is False

    def test_data_shorter_than_the_magic_is_not(self):
        """Must report false rather than raising on a two-byte file."""
        assert is_container(b"EH") is False

    def test_empty_data_is_not(self):
        assert is_container(b"") is False


class TestDescribeFromARealContainer:
    @pytest.mark.parametrize(
        ("algorithm", "expected"),
        [
            ("rsa", "rsa-oaep-sha256"),
            ("x25519", "x25519-hkdf-sha256"),
            ("mlkem", "ml-kem-768"),
        ],
    )
    def test_the_mechanism_is_reported(self, algorithm, expected):
        key = generate(algorithm, key_size=2048)
        info = describe_container(encrypt(key.public_key(), b"payload"))
        assert info.key_establishment == expected

    def test_a_classical_mechanism_is_flagged_vulnerable(self):
        key = generate("x25519")
        info = describe_container(encrypt(key.public_key(), b"payload"))
        assert info.quantum_vulnerable is True

    def test_a_post_quantum_mechanism_is_not(self):
        key = generate("mlkem")
        info = describe_container(encrypt(key.public_key(), b"payload"))
        assert info.quantum_vulnerable is False

    def test_a_one_shot_container_is_not_segmented(self):
        key = generate("x25519")
        info = describe_container(encrypt(key.public_key(), b"payload"))
        assert info.segmented is False
        assert info.content_encryption == "aes-256-gcm"

    def test_only_the_header_is_needed(self):
        """A caller reading from a stream need not buffer the whole file."""
        key = generate("mlkem")
        container = encrypt(key.public_key(), b"x" * 10_000)
        assert describe_container(container[:HEADER_SIZE]) == describe_container(
            container
        )

    def test_describing_does_not_require_the_private_key(self):
        """The whole point: no secret is involved in answering.

        Only the public key is used to produce the container, and nothing
        beyond the header is read to describe it.
        """
        key = generate("mlkem")
        container = encrypt(key.public_key(), b"payload")
        del key
        assert describe_container(container).key_establishment == "ml-kem-768"


class TestDescribeFromASynthesisedHeader:
    def test_a_segmented_container_is_flagged(self):
        info = describe_container(header(aead_id=AEAD_AES_256_GCM_STREAM))
        assert info.segmented is True
        assert info.content_encryption == "aes-256-gcm-segmented"

    def test_the_current_version_is_readable(self):
        assert describe_container(header()).readable is True

    def test_a_future_version_is_described_but_not_readable(self):
        """A newer container must explain itself rather than only failing.

        Refusing to describe it would leave an operator with a file and no
        way to find out why it cannot be read.
        """
        info = describe_container(header(version=VERSION + 1))
        assert info.format_version == VERSION + 1
        assert info.readable is False

    def test_an_unknown_mechanism_keeps_its_raw_identifier(self):
        info = describe_container(header(kem_id=99))
        assert info.key_establishment is None
        assert info.key_establishment_id == 99
        assert info.key_establishment_standard is None

    def test_an_unknown_content_mode_keeps_its_raw_identifier(self):
        info = describe_container(header(aead_id=99))
        assert info.content_encryption is None
        assert info.content_encryption_id == 99

    @pytest.mark.parametrize(
        ("kem_id", "standard"),
        [(1, "RFC 8017 (PKCS #1 v2.2)"), (2, "FIPS 203"), (3, "FIPS 203")],
    )
    def test_each_mechanism_cites_its_publication(self, kem_id, standard):
        assert (
            describe_container(header(kem_id=kem_id)).key_establishment_standard
            == standard
        )


class TestRejections:
    def test_data_too_short_for_a_header_is_refused(self):
        with pytest.raises(InvalidArgumentError, match="at least 10 bytes"):
            describe_container(b"EHEV")

    def test_data_without_the_magic_is_refused(self):
        with pytest.raises(InvalidArgumentError, match="not produced by this library"):
            describe_container(b"NOPE" + bytes(6))

    def test_the_rejection_names_the_required_length(self):
        with pytest.raises(InvalidArgumentError) as excinfo:
            describe_container(b"")
        assert str(HEADER_SIZE) in str(excinfo.value)


class TestSerialisation:
    def test_as_dict_round_trips_through_json(self):
        key = generate("mlkem")
        payload = json.loads(
            json.dumps(describe_container(encrypt(key.public_key(), b"x")).as_dict())
        )
        assert payload["key_establishment"] == "ml-kem-768"
        assert payload["quantum_vulnerable"] is False

    def test_the_description_carries_no_ciphertext(self):
        """A description is shared more widely than the data it describes."""
        key = generate("mlkem")
        container = encrypt(key.public_key(), b"a-distinctive-plaintext")
        rendered = json.dumps(describe_container(container).as_dict())
        assert "a-distinctive-plaintext" not in rendered
        assert container[HEADER_SIZE:].hex() not in rendered


class TestHeaderLayoutIsNotDuplicated:
    def test_the_layout_comes_from_the_envelope_module(self):
        """Two copies of the struct format would drift apart.

        ``metadata`` reads the container format defined by ``envelope``; if it
        restated the layout, a format change would update one and not the
        other.
        """
        assert HEADER_STRUCT.size == HEADER_SIZE
