# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for hybrid envelope encryption.

The tamper tests are the important ones. A cipher that round-trips is easy; a
cipher that *refuses* every modified input is the actual security property, and
it is the one a naive implementation silently fails.
"""

from __future__ import annotations

import pytest
from encryption_helper.crypto import envelope
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
    # Explicit ids: a parametrised payload otherwise lands verbatim in the
    # test id, which both bloats output and can exceed the Windows
    # environment-variable limit via PYTEST_CURRENT_TEST.
    @pytest.mark.parametrize(
        "plaintext",
        [
            pytest.param(b"", id="empty"),
            pytest.param(b"a", id="single-byte"),
            pytest.param(b"attack at dawn", id="short-text"),
            pytest.param(b"\x00" * 100, id="100-nulls"),
            pytest.param(bytes(range(256)), id="all-byte-values"),
        ],
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
    @pytest.mark.parametrize(
        "fixture", ["ed25519_key", "ed448_key", "ecdsa_key", "mldsa_key"]
    )
    def test_encrypt_rejects_signing_keys(self, request, fixture):
        """Signature keys cannot carry a content key; say so clearly."""
        key = request.getfixturevalue(fixture)
        with pytest.raises(InvalidArgumentError, match="Cannot encrypt to a"):
            encrypt(key.public_key(), b"data")

    @pytest.mark.parametrize(
        ("encrypt_fixture", "wrong_fixture"),
        [
            ("rsa_key", "mlkem_key"),
            ("mlkem_key", "rsa_key"),
            ("x25519_key", "mlkem_key"),
            ("rsa_key", "x25519_key"),
        ],
    )
    def test_decrypt_rejects_a_key_of_the_wrong_type(
        self, request, encrypt_fixture, wrong_fixture
    ):
        """The container names the mechanism, so a mismatch is detectable."""
        recipient = request.getfixturevalue(encrypt_fixture)
        wrong = request.getfixturevalue(wrong_fixture)
        blob = encrypt(recipient.public_key(), b"data")
        # A decryption-capable key of the wrong kind is a data problem: it is
        # indistinguishable from a tampered header.
        with pytest.raises(DecryptionError, match="needs an"):
            decrypt(wrong, blob)

    @pytest.mark.parametrize(
        "fixture", ["ed25519_key", "ed448_key", "ecdsa_key", "mldsa_key"]
    )
    def test_decrypt_rejects_a_signing_key(self, request, rsa_key, fixture):
        """A key that can never decrypt is a programming error, not bad data."""
        blob = encrypt(rsa_key.public_key(), b"data")
        with pytest.raises(InvalidArgumentError, match="Cannot decrypt with a"):
            decrypt(request.getfixturevalue(fixture), blob)


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


# ---------------------------------------------------------------------------
# Post-quantum and curve25519 mechanisms
# ---------------------------------------------------------------------------


class TestKeyEncapsulationMechanisms:
    """Every mechanism must round-trip and be self-identifying.

    NIST IR 8547 (initial public draft) disallows RSA and the elliptic curves
    after 2035, so ML-KEM is not optional for keys with a long
    service life. The container records which mechanism produced it, so a
    recipient never has to guess and an old ciphertext stays readable.
    """

    @pytest.mark.parametrize(
        ("fixture", "expected_kem"),
        [
            ("rsa_key", envelope.KEM_RSA_OAEP_SHA256),
            ("mlkem_key", envelope.KEM_MLKEM768),
            ("x25519_key", envelope.KEM_X25519_HKDF),
        ],
    )
    def test_container_records_its_mechanism(self, request, fixture, expected_kem):
        key = request.getfixturevalue(fixture)
        blob = encrypt(key.public_key(), b"payload")
        assert blob[:4] == MAGIC
        assert blob[5] == expected_kem

    @pytest.mark.parametrize(
        "fixture", ["rsa_key", "mlkem_key", "mlkem1024_key", "x25519_key"]
    )
    # Sizes, not payloads: a large parametrised value lands in the test
    # ID, and Windows caps PYTEST_CURRENT_TEST at 32,767 characters.
    @pytest.mark.parametrize("size", [0, 1, 100_000])
    def test_round_trip(self, request, fixture, size):
        key = request.getfixturevalue(fixture)
        plaintext = b"x" * size
        assert decrypt(key, encrypt(key.public_key(), plaintext)) == plaintext

    @pytest.mark.parametrize("fixture", ["mlkem_key", "mlkem1024_key", "x25519_key"])
    def test_encryption_is_randomised(self, request, fixture):
        """Two encapsulations of the same message must differ."""
        public = request.getfixturevalue(fixture).public_key()
        assert encrypt(public, b"same") != encrypt(public, b"same")

    @pytest.mark.parametrize("fixture", ["mlkem_key", "mlkem1024_key", "x25519_key"])
    def test_wrong_key_of_the_right_type_is_rejected(self, request, fixture):
        """ML-KEM uses implicit rejection, so the AEAD tag is what catches it."""
        from encryption_helper.keys import generate_mlkem, generate_x25519

        key = request.getfixturevalue(fixture)
        blob = encrypt(key.public_key(), b"payload")
        other = (
            generate_x25519()
            if fixture == "x25519_key"
            else generate_mlkem(level=1024 if "1024" in fixture else 768)
        )
        with pytest.raises(DecryptionError):
            decrypt(other, blob)

    @pytest.mark.parametrize("fixture", ["mlkem_key", "x25519_key"])
    def test_tampering_is_detected(self, request, fixture):
        key = request.getfixturevalue(fixture)
        blob = bytearray(encrypt(key.public_key(), b"payload"))
        blob[-1] ^= 0x01
        with pytest.raises(DecryptionError, match="integrity check"):
            decrypt(key, bytes(blob))

    def test_mechanism_is_bound_into_the_derived_key(self, mlkem_key):
        """Relabelling a container's mechanism must not decrypt.

        The KEM identifier is mixed into the HKDF info, so the same shared
        secret under a different label derives a different content key.
        """
        blob = bytearray(encrypt(mlkem_key.public_key(), b"payload"))
        blob[5] = envelope.KEM_MLKEM1024
        with pytest.raises(DecryptionError):
            decrypt(mlkem_key, bytes(blob))

    def test_unknown_mechanism_is_rejected_clearly(self, rsa_key):
        blob = bytearray(encrypt(rsa_key.public_key(), b"payload"))
        blob[5] = 99
        with pytest.raises(DecryptionError, match="Unsupported key encapsulation"):
            decrypt(rsa_key, bytes(blob))

    def test_supported_set_matches_the_implemented_branches(self):
        assert {
            envelope.KEM_RSA_OAEP_SHA256,
            envelope.KEM_MLKEM768,
            envelope.KEM_MLKEM1024,
            envelope.KEM_X25519_HKDF,
        } == envelope.SUPPORTED_KEMS

    def test_quantum_vulnerable_set_is_accurate(self):
        """RSA and X25519 are broken by a quantum computer; ML-KEM is not."""
        assert envelope.KEM_RSA_OAEP_SHA256 in envelope.QUANTUM_VULNERABLE_KEMS
        assert envelope.KEM_X25519_HKDF in envelope.QUANTUM_VULNERABLE_KEMS
        assert envelope.KEM_MLKEM768 not in envelope.QUANTUM_VULNERABLE_KEMS
        assert envelope.KEM_MLKEM1024 not in envelope.QUANTUM_VULNERABLE_KEMS

    def test_x25519_encapsulation_is_an_ephemeral_public_key(self, x25519_key):
        """32 bytes of ephemeral public key, not a wrapped content key."""
        blob = encrypt(x25519_key.public_key(), b"payload")
        wrapped_len = int.from_bytes(blob[8:10], "big")
        assert wrapped_len == 32

    def test_corrupt_x25519_encapsulation_fails_closed(self, x25519_key):
        blob = bytearray(encrypt(x25519_key.public_key(), b"payload"))
        for index in range(10, 42):
            blob[index] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt(x25519_key, bytes(blob))

    def test_corrupt_mlkem_ciphertext_fails_closed(self, mlkem_key):
        blob = bytearray(encrypt(mlkem_key.public_key(), b"payload"))
        blob[200] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt(mlkem_key, bytes(blob))


class TestMalformedEncapsulation:
    """A header can declare an encapsulation length that does not suit its
    mechanism. That must fail closed, with the same opaque error as any other
    key-recovery failure, rather than surfacing a backend ValueError."""

    @staticmethod
    def _relabel_length(blob: bytes, new_length: int) -> bytes:
        """Rewrite the container's encapsulation-length field."""
        mutated = bytearray(blob)
        mutated[8:10] = new_length.to_bytes(2, "big")
        return bytes(mutated)

    def test_short_mlkem_ciphertext(self, mlkem_key):
        blob = encrypt(mlkem_key.public_key(), b"payload")
        # ML-KEM-768 ciphertexts are 1088 bytes; 100 is structurally wrong.
        with pytest.raises(DecryptionError, match="Could not recover"):
            decrypt(mlkem_key, self._relabel_length(blob, 100))

    def test_short_x25519_public_key(self, x25519_key):
        blob = encrypt(x25519_key.public_key(), b"payload")
        # X25519 public keys are exactly 32 bytes.
        with pytest.raises(DecryptionError, match="Could not recover"):
            decrypt(x25519_key, self._relabel_length(blob, 16))

    def test_short_rsa_wrapped_key(self, rsa_key):
        blob = encrypt(rsa_key.public_key(), b"payload")
        with pytest.raises(DecryptionError, match="Could not recover"):
            decrypt(rsa_key, self._relabel_length(blob, 32))

    @pytest.mark.parametrize("fixture", ["rsa_key", "mlkem_key", "x25519_key"])
    def test_zero_length_encapsulation(self, request, fixture):
        key = request.getfixturevalue(fixture)
        blob = encrypt(key.public_key(), b"payload")
        with pytest.raises(DecryptionError):
            decrypt(key, self._relabel_length(blob, 0))
