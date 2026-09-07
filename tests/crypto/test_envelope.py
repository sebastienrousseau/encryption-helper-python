"""Tests for hybrid envelope encryption.

The tamper tests are the important ones. A cipher that round-trips is easy; a
cipher that *refuses* every modified input is the actual security property, and
it is the one a naive implementation silently fails.
"""

from __future__ import annotations

import pytest
from encryption_helper.crypto.envelope import (
    _HEADER_SIZE,
    MAGIC,
    VERSION,
    decrypt,
    encrypt,
)
from encryption_helper.errors import DecryptionError, InvalidArgumentError
from hypothesis import given, settings
from hypothesis import strategies as st


class TestRoundTrip:
    @pytest.mark.parametrize(
        "plaintext",
        [b"", b"a", b"attack at dawn", b"\x00" * 100, bytes(range(256))],
    )
    def test_round_trips(self, rsa_key, plaintext):
        assert decrypt(rsa_key, encrypt(rsa_key.public_key(), plaintext)) == plaintext

    def test_round_trips_data_far_larger_than_the_modulus(self, rsa_key):
        """The whole point of hybrid encryption.

        Direct RSA encryption cannot carry more than a few hundred bytes; a
        helper that only ever tested short strings would not notice.
        """
        plaintext = b"x" * (1024 * 1024)
        assert decrypt(rsa_key, encrypt(rsa_key.public_key(), plaintext)) == plaintext

    def test_ciphertext_does_not_contain_the_plaintext(self, rsa_key):
        plaintext = b"SUPER SECRET MARKER STRING"
        assert plaintext not in encrypt(rsa_key.public_key(), plaintext)

    def test_encryption_is_randomised(self, rsa_key):
        """Encrypting the same message twice must not produce the same bytes."""
        public = rsa_key.public_key()
        assert encrypt(public, b"same") != encrypt(public, b"same")

    def test_container_is_self_describing(self, rsa_key):
        blob = encrypt(rsa_key.public_key(), b"data")
        assert blob.startswith(MAGIC)
        assert blob[4] == VERSION


class TestAssociatedData:
    def test_round_trips_with_matching_context(self, rsa_key):
        blob = encrypt(rsa_key.public_key(), b"data", associated_data=b"ctx")
        assert decrypt(rsa_key, blob, associated_data=b"ctx") == b"data"

    def test_mismatched_context_is_rejected(self, rsa_key):
        blob = encrypt(rsa_key.public_key(), b"data", associated_data=b"ctx")
        with pytest.raises(DecryptionError, match="integrity check"):
            decrypt(rsa_key, blob, associated_data=b"other")

    def test_missing_context_is_rejected(self, rsa_key):
        blob = encrypt(rsa_key.public_key(), b"data", associated_data=b"ctx")
        with pytest.raises(DecryptionError):
            decrypt(rsa_key, blob)


class TestTampering:
    @pytest.fixture
    def blob(self, rsa_key):
        return encrypt(rsa_key.public_key(), b"the original message")

    @pytest.mark.parametrize(
        ("name", "offset"),
        [
            ("magic", 0),
            ("version", 4),
            ("kem id", 5),
            ("aead id", 6),
            ("reserved", 7),
            ("wrapped key length", 9),
        ],
    )
    def test_header_tampering_is_detected(self, rsa_key, blob, name, offset):
        mutated = bytearray(blob)
        mutated[offset] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt(rsa_key, bytes(mutated))

    def test_wrapped_key_tampering_is_detected(self, rsa_key, blob):
        mutated = bytearray(blob)
        mutated[_HEADER_SIZE + 5] ^= 0x01
        with pytest.raises(DecryptionError):
            decrypt(rsa_key, bytes(mutated))

    def test_ciphertext_tampering_is_detected(self, rsa_key, blob):
        mutated = bytearray(blob)
        mutated[-20] ^= 0x01
        with pytest.raises(DecryptionError, match="integrity check"):
            decrypt(rsa_key, bytes(mutated))

    def test_tag_tampering_is_detected(self, rsa_key, blob):
        mutated = bytearray(blob)
        mutated[-1] ^= 0x01
        with pytest.raises(DecryptionError, match="integrity check"):
            decrypt(rsa_key, bytes(mutated))

    def test_truncation_is_detected(self, rsa_key, blob):
        with pytest.raises(DecryptionError):
            decrypt(rsa_key, blob[:-1])

    def test_empty_input_is_detected(self, rsa_key):
        with pytest.raises(DecryptionError, match="too short"):
            decrypt(rsa_key, b"")

    def test_foreign_data_is_detected(self, rsa_key):
        with pytest.raises(DecryptionError, match="magic"):
            decrypt(rsa_key, b"just some bytes that are long enough to parse")

    def test_future_version_is_rejected_clearly(self, rsa_key, blob):
        mutated = bytearray(blob)
        mutated[4] = VERSION + 1
        with pytest.raises(DecryptionError, match="Unsupported container version"):
            decrypt(rsa_key, bytes(mutated))

    def test_wrong_key_cannot_decrypt(self, rsa_key, blob):
        from encryption_helper.keys import generate_rsa

        with pytest.raises(DecryptionError, match="different key"):
            decrypt(generate_rsa(key_size=2048), blob)


class TestKeyTypeValidation:
    def test_encrypt_rejects_non_rsa_keys(self, ed25519_key):
        with pytest.raises(InvalidArgumentError, match="requires an RSA public key"):
            encrypt(ed25519_key.public_key(), b"data")

    def test_decrypt_rejects_non_rsa_keys(self, rsa_key, ed25519_key):
        blob = encrypt(rsa_key.public_key(), b"data")
        with pytest.raises(InvalidArgumentError, match="requires an RSA private key"):
            decrypt(ed25519_key, blob)


class TestProperties:
    """Property-based tests over arbitrary inputs."""

    @settings(max_examples=50, deadline=None)
    @given(plaintext=st.binary(max_size=4096))
    def test_any_plaintext_round_trips(self, rsa_key, plaintext):
        assert decrypt(rsa_key, encrypt(rsa_key.public_key(), plaintext)) == plaintext

    @settings(max_examples=50, deadline=None)
    @given(
        aad=st.binary(max_size=64),
        plaintext=st.binary(max_size=256),
    )
    def test_any_associated_data_round_trips(self, rsa_key, aad, plaintext):
        blob = encrypt(rsa_key.public_key(), plaintext, associated_data=aad)
        assert decrypt(rsa_key, blob, associated_data=aad) == plaintext

    @settings(max_examples=100, deadline=None)
    @given(index=st.integers(min_value=0), mask=st.integers(min_value=1, max_value=255))
    def test_no_single_byte_mutation_ever_yields_plaintext(self, rsa_key, index, mask):
        """Flipping any bit anywhere must fail closed, never return data."""
        blob = encrypt(rsa_key.public_key(), b"the original message")
        mutated = bytearray(blob)
        mutated[index % len(mutated)] ^= mask
        if bytes(mutated) == blob:  # pragma: no cover - mask is never 0
            return
        with pytest.raises(DecryptionError):
            decrypt(rsa_key, bytes(mutated))


class TestInternalFailureBranches:
    """Defensive branches, reached with stand-in keys registered against the
    `cryptography` ABCs. The production code is untouched."""

    def test_wrapping_failure_is_reported(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        @rsa.RSAPublicKey.register
        class TooSmallKey:
            def encrypt(self, plaintext, padding):
                raise ValueError("data too large for key size")

        with pytest.raises(InvalidArgumentError, match="too small to wrap"):
            encrypt(TooSmallKey(), b"data")

    def test_wrong_length_content_key_is_rejected(self, rsa_key):
        """Defence in depth: an unwrap that succeeds but yields a bad key."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        blob = encrypt(rsa_key.public_key(), b"data")

        @rsa.RSAPrivateKey.register
        class ShortKeyUnwrapper:
            def decrypt(self, ciphertext, padding):
                return b"short"

        with pytest.raises(DecryptionError, match="wrong length"):
            decrypt(ShortKeyUnwrapper(), blob)
