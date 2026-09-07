"""Tests for key loading and format auto-detection."""

from __future__ import annotations

import pytest
from encryption_helper.errors import KeyReadError
from encryption_helper.keys import (
    encode_private_key,
    encode_public_key,
    load_private_key,
    load_private_key_file,
    load_public_key,
    load_public_key_file,
)


class TestRoundTrip:
    @pytest.mark.parametrize("fmt", ["pem", "der"])
    @pytest.mark.parametrize("fixture", ["rsa_key", "ed25519_key", "ecdsa_key"])
    def test_private_key_round_trips(self, request, fixture, fmt):
        key = request.getfixturevalue(fixture)
        reloaded = load_private_key(encode_private_key(key, fmt=fmt))
        assert encode_public_key(reloaded.public_key()) == encode_public_key(
            key.public_key()
        )

    @pytest.mark.parametrize("fmt", ["pem", "der", "openssh"])
    @pytest.mark.parametrize("fixture", ["rsa_key", "ed25519_key", "ecdsa_key"])
    def test_public_key_round_trips(self, request, fixture, fmt):
        key = request.getfixturevalue(fixture)
        encoded = encode_public_key(key.public_key(), fmt=fmt)
        reloaded = load_public_key(encoded)
        assert encode_public_key(reloaded, fmt=fmt) == encoded

    def test_openssh_private_key_round_trips(self, ed25519_key):
        encoded = encode_private_key(ed25519_key, fmt="openssh")
        assert encode_public_key(
            load_private_key(encoded).public_key()
        ) == encode_public_key(ed25519_key.public_key())

    def test_encrypted_key_round_trips(self, rsa_key):
        encoded = encode_private_key(rsa_key, passphrase=b"correct horse")
        reloaded = load_private_key(encoded, passphrase=b"correct horse")
        assert reloaded.private_numbers() == rsa_key.private_numbers()


class TestLoadErrors:
    def test_empty_private_input(self):
        with pytest.raises(KeyReadError, match="empty input"):
            load_private_key(b"")

    def test_empty_public_input(self):
        with pytest.raises(KeyReadError, match="empty input"):
            load_public_key(b"")

    def test_garbage_private_key(self):
        with pytest.raises(KeyReadError, match="Could not load the private key"):
            load_private_key(b"definitely not a key")

    def test_garbage_public_key(self):
        with pytest.raises(KeyReadError, match="Could not load the public key"):
            load_public_key(b"definitely not a key")

    def test_wrong_passphrase(self, rsa_key):
        encoded = encode_private_key(rsa_key, passphrase=b"correct horse")
        with pytest.raises(KeyReadError) as excinfo:
            load_private_key(encoded, passphrase=b"wrong horse")
        # The message must not confirm that the passphrase specifically was
        # the problem, which would make this a useful oracle.
        assert "passphrase" in str(excinfo.value)
        assert "wrong horse" not in str(excinfo.value)

    def test_missing_passphrase(self, rsa_key):
        encoded = encode_private_key(rsa_key, passphrase=b"correct horse")
        with pytest.raises(KeyReadError):
            load_private_key(encoded)

    def test_truncated_pem(self, rsa_key):
        encoded = encode_private_key(rsa_key)
        with pytest.raises(KeyReadError):
            load_private_key(encoded[: len(encoded) // 2])

    def test_public_key_is_not_a_private_key(self, rsa_key):
        with pytest.raises(KeyReadError):
            load_private_key(encode_public_key(rsa_key.public_key()))


class TestFileLoaders:
    def test_private_key_file(self, tmp_path, ed25519_key):
        path = tmp_path / "k.pem"
        path.write_bytes(encode_private_key(ed25519_key))
        assert encode_public_key(
            load_private_key_file(path).public_key()
        ) == encode_public_key(ed25519_key.public_key())

    def test_public_key_file(self, tmp_path, ed25519_key):
        path = tmp_path / "k.pub.pem"
        path.write_bytes(encode_public_key(ed25519_key.public_key()))
        assert encode_public_key(load_public_key_file(path)) == path.read_bytes()

    def test_missing_file(self, tmp_path):
        with pytest.raises(KeyReadError, match="No such file"):
            load_private_key_file(tmp_path / "absent.pem")
