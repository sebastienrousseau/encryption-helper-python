# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for writing key pairs to disk.

These exercise the real filesystem. Nothing here is mocked, because the
defects this replaces (world-readable keys, silent overwrites) were all
invisible to a suite that mocked ``open``.
"""

from __future__ import annotations

import stat

import pytest
from encryption_helper._io import PUBLIC_FILE_MODE, SECRET_FILE_MODE
from encryption_helper.errors import (
    KeyExistsError,
    KeyPairValidationError,
    KeyWriteError,
)
from encryption_helper.keys import load_private_key_file, load_public_key_file, store
from encryption_helper.keys.store import write_key_pair

from .._support import posix_only


class TestWriteKeyPair:
    def test_writes_both_halves(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path, name="service")
        assert paths.private_key_path == tmp_path / "service.pem"
        assert paths.public_key_path == tmp_path / "service.pub.pem"
        assert paths.private_key_path.exists()
        assert paths.public_key_path.exists()

    def test_written_keys_are_loadable(self, tmp_path, ed25519_key):
        """The end-to-end path the old suite never exercised."""
        paths = write_key_pair(ed25519_key, tmp_path)
        reloaded = load_private_key_file(paths.private_key_path)
        public = load_public_key_file(paths.public_key_path)
        assert reloaded.public_key().public_bytes_raw() == public.public_bytes_raw()

    @posix_only
    def test_private_key_is_owner_only(self, tmp_path, ed25519_key):
        """Regression test for finding C2."""
        paths = write_key_pair(ed25519_key, tmp_path)
        assert stat.S_IMODE(paths.private_key_path.stat().st_mode) == SECRET_FILE_MODE

    @posix_only
    def test_public_key_is_readable(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path)
        assert stat.S_IMODE(paths.public_key_path.stat().st_mode) == PUBLIC_FILE_MODE

    @posix_only
    def test_created_directory_is_owner_only(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path / "nested" / "deep")
        assert stat.S_IMODE(paths.private_key_path.parent.stat().st_mode) == 0o700

    def test_passphrase_encrypts_the_stored_key(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path, passphrase=b"correct horse")
        assert paths.private_key_path.read_bytes().startswith(
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
        )
        with pytest.raises(Exception, match="Could not load"):
            load_private_key_file(paths.private_key_path)
        assert load_private_key_file(
            paths.private_key_path, passphrase=b"correct horse"
        )

    def test_refuses_to_clobber(self, tmp_path, ed25519_key):
        """Regression test for finding C6."""
        write_key_pair(ed25519_key, tmp_path)
        original = (tmp_path / "key.pem").read_bytes()
        with pytest.raises(KeyExistsError):
            write_key_pair(ed25519_key, tmp_path)
        assert (tmp_path / "key.pem").read_bytes() == original

    def test_force_backs_up_the_old_key(self, tmp_path, ed25519_key, rsa_key):
        write_key_pair(ed25519_key, tmp_path)
        original = (tmp_path / "key.pem").read_bytes()
        write_key_pair(rsa_key, tmp_path, overwrite=True)

        assert (tmp_path / "key.pem").read_bytes() != original
        backups = list(tmp_path.glob("key.pem.bak-*"))
        assert len(backups) == 1
        assert backups[0].read_bytes() == original

    @pytest.mark.parametrize(
        ("fmt", "private", "public"),
        [("pem", "key.pem", "key.pub.pem"), ("der", "key.der", "key.pub.der")],
    )
    def test_format_suffixes(self, tmp_path, ed25519_key, fmt, private, public):
        paths = write_key_pair(ed25519_key, tmp_path, fmt=fmt)
        assert paths.private_key_path.name == private
        assert paths.public_key_path.name == public

    def test_openssh_format_uses_bare_stem(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path, name="id_ed25519", fmt="openssh")
        assert paths.private_key_path.name == "id_ed25519"
        assert paths.public_key_path.name == "id_ed25519.pub"

    def test_no_public_key_left_when_private_write_fails(self, tmp_path, ed25519_key):
        """A stray public key would imply a private key that does not exist."""
        (tmp_path / "key.pem").write_bytes(b"pre-existing")
        with pytest.raises(KeyExistsError):
            write_key_pair(ed25519_key, tmp_path)
        assert not (tmp_path / "key.pub.pem").exists()


class TestPreflight:
    def test_rejects_colliding_destinations(self, tmp_path, ed25519_key, monkeypatch):
        """Both halves landing on one path would silently lose the public key."""
        monkeypatch.setitem(store._SUFFIXES, "pem", (".pem", ".pem"))
        with pytest.raises(KeyWriteError, match="would both be written"):
            store.write_key_pair(ed25519_key, tmp_path)

    def test_rejects_a_directory_destination(self, tmp_path, ed25519_key):
        (tmp_path / "key.pem").mkdir()
        with pytest.raises(KeyWriteError, match="is a directory"):
            store.write_key_pair(ed25519_key, tmp_path)

    def test_conflict_is_detected_before_anything_is_written(
        self, tmp_path, ed25519_key
    ):
        """Only the public half exists; the private half must stay absent."""
        (tmp_path / "key.pub.pem").write_bytes(b"pre-existing")
        with pytest.raises(KeyExistsError, match=r"key\.pub\.pem"):
            store.write_key_pair(ed25519_key, tmp_path)
        assert not (tmp_path / "key.pem").exists()


class TestPairValidation:
    def test_mismatched_public_half_is_refused(
        self, tmp_path, ed25519_key, rsa_key, monkeypatch
    ):
        """A pair that does not correspond must never reach the disk."""
        real = store.encode_public_key
        calls = {"n": 0}

        def wrong_on_first(key, **kwargs):
            # Call 1 produces the public file; later calls build the
            # comparison reference, which must stay honest.
            calls["n"] += 1
            if calls["n"] == 1:
                return real(rsa_key.public_key(), **kwargs)
            return real(key, **kwargs)

        monkeypatch.setattr(store, "encode_public_key", wrong_on_first)
        with pytest.raises(KeyPairValidationError, match="does not match"):
            store.write_key_pair(ed25519_key, tmp_path)
        assert list(tmp_path.iterdir()) == []

    def test_unparseable_serialisation_is_refused(
        self, tmp_path, ed25519_key, monkeypatch
    ):
        monkeypatch.setattr(store, "encode_private_key", lambda *a, **k: b"garbage")
        with pytest.raises(KeyPairValidationError, match="could not be parsed"):
            store.write_key_pair(ed25519_key, tmp_path)
        assert list(tmp_path.iterdir()) == []

    def test_private_half_not_matching_is_refused(
        self, tmp_path, ed25519_key, rsa_key, monkeypatch
    ):
        real = store.encode_private_key
        monkeypatch.setattr(
            store,
            "encode_private_key",
            lambda key, **kwargs: real(rsa_key, **kwargs),
        )
        with pytest.raises(KeyPairValidationError, match="does not correspond"):
            store.write_key_pair(ed25519_key, tmp_path)


class TestDescribeKey:
    @pytest.mark.parametrize(
        ("fixture", "algorithm", "size"),
        [
            ("rsa_key", "rsa", 2048),
            ("ed25519_key", "ed25519", 256),
            ("ecdsa_key", "ecdsa", 256),
        ],
    )
    def test_reports_algorithm_and_size(self, request, fixture, algorithm, size):
        key = request.getfixturevalue(fixture)
        assert store.describe_key(key) == (algorithm, size)

    def test_unknown_key_type_degrades_gracefully(self):
        assert store.describe_key(object()) == ("object", None)


class TestResultMetadata:
    def test_reports_what_was_written(self, tmp_path, rsa_key):
        result = store.write_key_pair(rsa_key, tmp_path, passphrase=b"secret")
        assert result.algorithm == "rsa"
        assert result.key_size == 2048
        assert result.fingerprint.startswith("SHA256:")
        assert result.private_key_encrypted is True
        assert result.replaced is False

    def test_reports_replacement(self, tmp_path, ed25519_key):
        store.write_key_pair(ed25519_key, tmp_path)
        result = store.write_key_pair(ed25519_key, tmp_path, overwrite=True)
        assert result.replaced is True

    def test_paths_are_absolute(self, tmp_path, ed25519_key, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = store.write_key_pair(ed25519_key, "relative")
        assert result.private_key_path.is_absolute()
        assert result.private_key_path == tmp_path / "relative" / "key.pem"
