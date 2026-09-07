"""Tests for the secure filesystem layer.

These are the tests that would have caught findings C2 (world-readable private
keys), C5 (the write path rejecting every valid call) and C6 (silent
destruction of an existing key).
"""

from __future__ import annotations

import os
import stat

import pytest
from encryption_helper._io import (
    PUBLIC_FILE_MODE,
    SECRET_DIR_MODE,
    SECRET_FILE_MODE,
    read_bytes,
    secure_write_bytes,
)
from encryption_helper.errors import KeyExistsError, KeyReadError, KeyWriteError

from ._support import posix_only


class TestSecureWriteBytes:
    def test_writes_the_exact_bytes(self, tmp_path):
        target = tmp_path / "payload.bin"
        secure_write_bytes(target, b"test data")
        assert target.read_bytes() == b"test data"

    def test_accepts_bytes_payloads(self, tmp_path):
        """Regression test for finding C5.

        The previous implementation validated its payload with a
        string-only emptiness check, so every call with the documented
        ``bytes`` argument raised ``Exception("One or more arguments are
        empty")``. The old suite could not see it because it mocked the
        validator out.
        """
        target = tmp_path / "out.bin"
        assert secure_write_bytes(target, b"test data") == target
        assert target.read_bytes() == b"test data"

    def test_accepts_empty_payload(self, tmp_path):
        target = tmp_path / "empty.bin"
        secure_write_bytes(target, b"")
        assert target.read_bytes() == b""

    @posix_only
    def test_secret_files_are_owner_only(self, tmp_path):
        """Regression test for finding C2."""
        target = secure_write_bytes(tmp_path / "private.pem", b"secret")
        assert stat.S_IMODE(target.stat().st_mode) == SECRET_FILE_MODE

    @posix_only
    def test_mode_is_not_subject_to_umask(self, tmp_path):
        """A permissive umask must not loosen a secret file."""
        previous = os.umask(0o000)
        try:
            target = secure_write_bytes(tmp_path / "k.pem", b"secret")
        finally:
            os.umask(previous)
        assert stat.S_IMODE(target.stat().st_mode) == SECRET_FILE_MODE

    @posix_only
    def test_public_mode_is_honoured(self, tmp_path):
        target = secure_write_bytes(
            tmp_path / "pub.pem", b"public", mode=PUBLIC_FILE_MODE
        )
        assert stat.S_IMODE(target.stat().st_mode) == PUBLIC_FILE_MODE

    @posix_only
    def test_creates_parent_directories_owner_only(self, tmp_path):
        target = secure_write_bytes(tmp_path / "a" / "b" / "k.pem", b"secret")
        assert stat.S_IMODE(target.parent.stat().st_mode) == SECRET_DIR_MODE

    def test_refuses_to_overwrite_by_default(self, tmp_path):
        """Regression test for finding C6."""
        target = tmp_path / "key.pem"
        secure_write_bytes(target, b"original")
        with pytest.raises(KeyExistsError, match="already exists"):
            secure_write_bytes(target, b"replacement")
        assert target.read_bytes() == b"original"

    def test_overwrite_preserves_a_backup(self, tmp_path):
        target = tmp_path / "key.pem"
        secure_write_bytes(target, b"original")
        secure_write_bytes(target, b"replacement", overwrite=True)

        assert target.read_bytes() == b"replacement"
        backups = list(tmp_path.glob("key.pem.bak-*"))
        assert len(backups) == 1
        assert backups[0].read_bytes() == b"original"

    @posix_only
    def test_backup_keeps_restrictive_permissions(self, tmp_path):
        target = tmp_path / "key.pem"
        secure_write_bytes(target, b"original")
        secure_write_bytes(target, b"replacement", overwrite=True)
        backup = next(iter(tmp_path.glob("key.pem.bak-*")))
        assert stat.S_IMODE(backup.stat().st_mode) == SECRET_FILE_MODE

    def test_repeated_overwrites_do_not_collide(self, tmp_path):
        target = tmp_path / "key.pem"
        secure_write_bytes(target, b"v1")
        secure_write_bytes(target, b"v2", overwrite=True)
        secure_write_bytes(target, b"v3", overwrite=True)
        assert len(list(tmp_path.glob("key.pem.bak-*"))) == 2

    @posix_only
    def test_refuses_to_write_through_a_symlink(self, tmp_path):
        """A symlink in the destination redirects key material elsewhere."""
        real = tmp_path / "elsewhere.pem"
        real.write_bytes(b"victim")
        link = tmp_path / "key.pem"
        link.symlink_to(real)

        with pytest.raises(KeyWriteError, match="symbolic link"):
            secure_write_bytes(link, b"attacker data")
        assert real.read_bytes() == b"victim"

    def test_leaves_no_temporary_files_behind(self, tmp_path):
        secure_write_bytes(tmp_path / "key.pem", b"secret")
        assert [p.name for p in tmp_path.iterdir()] == ["key.pem"]

    @posix_only
    def test_reports_unwritable_destination(self, tmp_path):
        """A failure to write surfaces as a typed error, not a raw OSError."""
        if os.geteuid() == 0:
            pytest.skip("root bypasses directory permissions")
        locked = tmp_path / "locked"
        locked.mkdir(mode=0o500)
        with pytest.raises(KeyWriteError, match="Could not write"):
            secure_write_bytes(locked / "key.pem", b"secret")


class TestReadBytes:
    def test_round_trips(self, tmp_path):
        secure_write_bytes(tmp_path / "f.bin", b"hello")
        assert read_bytes(tmp_path / "f.bin") == b"hello"

    def test_missing_file_raises_typed_error(self, tmp_path):
        with pytest.raises(KeyReadError, match="No such file"):
            read_bytes(tmp_path / "absent.bin")

    def test_directory_raises_typed_error(self, tmp_path):
        with pytest.raises(KeyReadError):
            read_bytes(tmp_path)


class TestFailurePaths:
    """Error branches, reached by injecting failures rather than by mocking
    the function under test."""

    def test_backup_names_do_not_collide_within_the_same_second(
        self, tmp_path, monkeypatch
    ):
        """Two overwrites in the same second must not clobber each other."""
        import encryption_helper._io as io_module

        monkeypatch.setattr(io_module, "_timestamp", lambda: "FIXED")
        target = tmp_path / "key.pem"
        secure_write_bytes(target, b"v1")
        secure_write_bytes(target, b"v2", overwrite=True)
        secure_write_bytes(target, b"v3", overwrite=True)

        assert (tmp_path / "key.pem.bak-FIXED").read_bytes() == b"v1"
        assert (tmp_path / "key.pem.bak-FIXED.1").read_bytes() == b"v2"
        assert target.read_bytes() == b"v3"

    def test_backup_failure_is_reported(self, tmp_path, monkeypatch):
        target = tmp_path / "key.pem"
        secure_write_bytes(target, b"v1")

        def boom(self, other):
            raise OSError(13, "Permission denied")

        monkeypatch.setattr("pathlib.Path.replace", boom)
        with pytest.raises(KeyWriteError, match="Could not back up"):
            secure_write_bytes(target, b"v2", overwrite=True)

    def test_directory_creation_failure_is_reported(self, tmp_path, monkeypatch):
        def boom(self, **kwargs):
            raise OSError(13, "Permission denied")

        monkeypatch.setattr("pathlib.Path.mkdir", boom)
        with pytest.raises(KeyWriteError, match="Could not create directory"):
            secure_write_bytes(tmp_path / "sub" / "key.pem", b"secret")

    def test_write_failure_leaves_no_temporary_file(self, tmp_path, monkeypatch):
        real_write = os.write

        def boom(fd, data):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr("pathlib.Path.replace", boom)
        with pytest.raises(KeyWriteError, match="Could not write"):
            secure_write_bytes(tmp_path / "key.pem", b"secret")
        assert list(tmp_path.iterdir()) == []
        assert real_write is os.write

    def test_generic_read_error_is_wrapped(self, tmp_path, monkeypatch):
        target = tmp_path / "f.bin"
        target.write_bytes(b"data")

        def boom(self):
            raise OSError(5, "Input/output error")

        monkeypatch.setattr("pathlib.Path.read_bytes", boom)
        with pytest.raises(KeyReadError, match="Could not read"):
            read_bytes(target)
