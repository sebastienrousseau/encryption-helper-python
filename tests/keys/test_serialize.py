# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for key encoding."""

from __future__ import annotations

import pytest
from encryption_helper.errors import InvalidArgumentError, UnsupportedAlgorithmError
from encryption_helper.keys import encode_private_key, encode_public_key


class TestEncodePrivateKey:
    def test_pem_is_pkcs8(self, rsa_key):
        """The README previously claimed PKCS#1; the code emits PKCS#8."""
        pem = encode_private_key(rsa_key, fmt="pem")
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_encrypted_pem_is_labelled_as_such(self, rsa_key):
        pem = encode_private_key(rsa_key, fmt="pem", passphrase=b"correct horse")
        assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

    def test_encryption_changes_the_output(self, rsa_key):
        plain = encode_private_key(rsa_key)
        sealed = encode_private_key(rsa_key, passphrase=b"correct horse")
        assert plain != sealed

    def test_der_is_binary(self, rsa_key):
        assert not encode_private_key(rsa_key, fmt="der").startswith(b"-----")

    def test_openssh_format(self, ed25519_key):
        encoded = encode_private_key(ed25519_key, fmt="openssh")
        assert encoded.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_empty_passphrase_is_rejected(self, rsa_key):
        """An empty passphrase silently means "no protection"; refuse it."""
        with pytest.raises(InvalidArgumentError, match="empty passphrase"):
            encode_private_key(rsa_key, passphrase=b"")

    def test_none_passphrase_means_unencrypted(self, rsa_key):
        assert encode_private_key(rsa_key, passphrase=None).startswith(
            b"-----BEGIN PRIVATE KEY-----"
        )

    def test_rejects_unknown_format(self, rsa_key):
        with pytest.raises(UnsupportedAlgorithmError, match="Unsupported private"):
            encode_private_key(rsa_key, fmt="jwk")


class TestEncodePublicKey:
    def test_pem_is_subject_public_key_info(self, rsa_key):
        pem = encode_public_key(rsa_key.public_key())
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

    @pytest.mark.parametrize(
        ("fixture", "prefix"),
        [("rsa_key", b"ssh-rsa "), ("ed25519_key", b"ssh-ed25519 ")],
    )
    def test_openssh_single_line(self, request, fixture, prefix):
        key = request.getfixturevalue(fixture)
        assert encode_public_key(key.public_key(), fmt="openssh").startswith(prefix)

    def test_der_is_binary(self, rsa_key):
        assert not encode_public_key(rsa_key.public_key(), fmt="der").startswith(b"--")

    def test_rejects_unknown_format(self, rsa_key):
        with pytest.raises(UnsupportedAlgorithmError, match="Unsupported public"):
            encode_public_key(rsa_key.public_key(), fmt="jwk")


class TestEncodingFailures:
    """The wrapped-failure branches, reached with a key the backend rejects."""

    def test_private_encoding_failure_is_wrapped(self):
        class RefusingKey:
            def private_bytes(self, **kwargs):
                raise ValueError("backend refused")

        with pytest.raises(UnsupportedAlgorithmError, match="Cannot encode"):
            encode_private_key(RefusingKey())

    def test_public_encoding_failure_is_wrapped(self):
        class RefusingKey:
            def public_bytes(self, **kwargs):
                raise ValueError("backend refused")

        with pytest.raises(UnsupportedAlgorithmError, match="Cannot encode"):
            encode_public_key(RefusingKey())
