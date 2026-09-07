"""Tests for writing key pairs to disk.

These exercise the real filesystem. Nothing here is mocked, because the
defects this replaces (world-readable keys, silent overwrites) were all
invisible to a suite that mocked ``open``.
"""

from __future__ import annotations

import stat

import pytest
from encryption_helper._io import PUBLIC_FILE_MODE, SECRET_FILE_MODE
from encryption_helper.errors import KeyExistsError
from encryption_helper.keys import load_private_key_file, load_public_key_file
from encryption_helper.keys.store import write_key_pair

from .._support import posix_only


class TestWriteKeyPair:
    def test_writes_both_halves(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path, name="service")
        assert paths.private_key == tmp_path / "service.pem"
        assert paths.public_key == tmp_path / "service.pub.pem"
        assert paths.private_key.exists()
        assert paths.public_key.exists()

    def test_written_keys_are_loadable(self, tmp_path, ed25519_key):
        """The end-to-end path the old suite never exercised."""
        paths = write_key_pair(ed25519_key, tmp_path)
        reloaded = load_private_key_file(paths.private_key)
        public = load_public_key_file(paths.public_key)
        assert reloaded.public_key().public_bytes_raw() == public.public_bytes_raw()

    @posix_only
    def test_private_key_is_owner_only(self, tmp_path, ed25519_key):
        """Regression test for finding C2."""
        paths = write_key_pair(ed25519_key, tmp_path)
        assert stat.S_IMODE(paths.private_key.stat().st_mode) == SECRET_FILE_MODE

    @posix_only
    def test_public_key_is_readable(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path)
        assert stat.S_IMODE(paths.public_key.stat().st_mode) == PUBLIC_FILE_MODE

    @posix_only
    def test_created_directory_is_owner_only(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path / "nested" / "deep")
        assert stat.S_IMODE(paths.private_key.parent.stat().st_mode) == 0o700

    def test_passphrase_encrypts_the_stored_key(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path, passphrase=b"correct horse")
        assert paths.private_key.read_bytes().startswith(
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
        )
        with pytest.raises(Exception, match="Could not load"):
            load_private_key_file(paths.private_key)
        assert load_private_key_file(paths.private_key, passphrase=b"correct horse")

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
        assert paths.private_key.name == private
        assert paths.public_key.name == public

    def test_openssh_format_uses_bare_stem(self, tmp_path, ed25519_key):
        paths = write_key_pair(ed25519_key, tmp_path, name="id_ed25519", fmt="openssh")
        assert paths.private_key.name == "id_ed25519"
        assert paths.public_key.name == "id_ed25519.pub"

    def test_no_public_key_left_when_private_write_fails(self, tmp_path, ed25519_key):
        """A stray public key would imply a private key that does not exist."""
        (tmp_path / "key.pem").write_bytes(b"pre-existing")
        with pytest.raises(KeyExistsError):
            write_key_pair(ed25519_key, tmp_path)
        assert not (tmp_path / "key.pub.pem").exists()
