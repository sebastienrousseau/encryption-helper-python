"""Tests for digital signatures."""

from __future__ import annotations

import pytest
from encryption_helper.crypto.signing import is_valid_signature, sign, verify
from encryption_helper.errors import (
    SignatureVerificationError,
    UnsupportedAlgorithmError,
)
from hypothesis import given, settings
from hypothesis import strategies as st

ALL_KEYS = ["rsa_key", "ed25519_key", "ecdsa_key"]


class TestSignAndVerify:
    @pytest.mark.parametrize("fixture", ALL_KEYS)
    def test_round_trip(self, request, fixture):
        key = request.getfixturevalue(fixture)
        verify(key.public_key(), sign(key, b"message"), b"message")

    @pytest.mark.parametrize("fixture", ALL_KEYS)
    def test_empty_message(self, request, fixture):
        key = request.getfixturevalue(fixture)
        verify(key.public_key(), sign(key, b""), b"")

    def test_rsa_signatures_are_randomised(self, rsa_key):
        """PSS is randomised; two signatures over the same data differ."""
        assert sign(rsa_key, b"message") != sign(rsa_key, b"message")

    def test_verify_returns_none_on_success(self, ed25519_key):
        assert verify(ed25519_key.public_key(), sign(ed25519_key, b"m"), b"m") is None


class TestVerificationFailure:
    @pytest.mark.parametrize("fixture", ALL_KEYS)
    def test_modified_message_is_rejected(self, request, fixture):
        key = request.getfixturevalue(fixture)
        signature = sign(key, b"transfer 100")
        with pytest.raises(SignatureVerificationError):
            verify(key.public_key(), signature, b"transfer 900")

    @pytest.mark.parametrize("fixture", ALL_KEYS)
    def test_modified_signature_is_rejected(self, request, fixture):
        key = request.getfixturevalue(fixture)
        signature = bytearray(sign(key, b"message"))
        signature[-1] ^= 0x01
        with pytest.raises(SignatureVerificationError):
            verify(key.public_key(), bytes(signature), b"message")

    def test_wrong_key_is_rejected(self, ed25519_key):
        from encryption_helper.keys import generate_ed25519

        signature = sign(ed25519_key, b"message")
        with pytest.raises(SignatureVerificationError):
            verify(generate_ed25519().public_key(), signature, b"message")

    def test_empty_signature_is_rejected(self, ed25519_key):
        with pytest.raises(SignatureVerificationError):
            verify(ed25519_key.public_key(), b"", b"message")

    def test_failure_mode_is_an_exception_not_a_falsy_return(self, ed25519_key):
        """A caller who forgets to check the result must still fail closed."""
        with pytest.raises(SignatureVerificationError):
            verify(ed25519_key.public_key(), b"bogus", b"message")


class TestIsValidSignature:
    def test_true_for_a_good_signature(self, ed25519_key):
        assert is_valid_signature(
            ed25519_key.public_key(), sign(ed25519_key, b"m"), b"m"
        )

    def test_false_for_a_bad_signature(self, ed25519_key):
        assert not is_valid_signature(
            ed25519_key.public_key(), sign(ed25519_key, b"m"), b"other"
        )

    def test_unsupported_key_still_raises(self):
        """An unsupported key is a bug, not an invalid signature."""
        with pytest.raises(UnsupportedAlgorithmError):
            is_valid_signature(object(), b"sig", b"data")  # type: ignore[arg-type]


class TestUnsupportedKeys:
    def test_sign_rejects_unknown_key_type(self):
        with pytest.raises(UnsupportedAlgorithmError, match="Cannot sign"):
            sign(object(), b"data")  # type: ignore[arg-type]

    def test_verify_rejects_unknown_key_type(self):
        with pytest.raises(UnsupportedAlgorithmError, match="Cannot verify"):
            verify(object(), b"sig", b"data")  # type: ignore[arg-type]


class TestProperties:
    @settings(max_examples=50, deadline=None)
    @given(message=st.binary(max_size=2048))
    def test_any_message_round_trips(self, ed25519_key, message):
        verify(ed25519_key.public_key(), sign(ed25519_key, message), message)

    @settings(max_examples=50, deadline=None)
    @given(a=st.binary(max_size=256), b=st.binary(max_size=256))
    def test_signature_does_not_transfer_between_messages(self, ed25519_key, a, b):
        if a == b:
            return
        assert not is_valid_signature(ed25519_key.public_key(), sign(ed25519_key, a), b)
