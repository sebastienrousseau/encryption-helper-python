# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Unit tests for the pieces :func:`secure_write_bytes` is built from.

``secure_write_bytes`` was one function doing five jobs, which could only be
tested by driving a whole write and inferring what happened. Each guard is now
a separate callable, so each can be given its exact precondition directly --
including states that are awkward to reach through the front door, such as a
displaced file whose restore target has itself been replaced.
"""

from __future__ import annotations

import stat
import sys

import pytest
from encryption_helper import _io
from encryption_helper._io import (
    PUBLIC_FILE_MODE,
    SECRET_FILE_MODE,
    WriteOutcome,
    _displace,
    _Displaced,
    _outcome,
    _reject_existing_destination,
    _write_atomically,
)
from encryption_helper.errors import KeyExistsError, KeyWriteError

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")


class TestRejectExistingDestination:
    """The exclusivity guard, isolated from the write it protects."""

    def test_absent_destination_is_not_a_replacement(self, tmp_path):
        assert _reject_existing_destination(tmp_path / "new", overwrite=False) is False

    def test_existing_destination_is_refused_without_overwrite(self, tmp_path):
        target = tmp_path / "key"
        target.write_bytes(b"old")
        with pytest.raises(KeyExistsError, match="already exists"):
            _reject_existing_destination(target, overwrite=False)

    def test_existing_destination_is_reported_with_overwrite(self, tmp_path):
        target = tmp_path / "key"
        target.write_bytes(b"old")
        assert _reject_existing_destination(target, overwrite=True) is True

    def test_the_error_names_the_opt_in(self, tmp_path):
        """A refusal has to say how to proceed, or it is a dead end."""
        target = tmp_path / "key"
        target.write_bytes(b"old")
        with pytest.raises(KeyExistsError) as excinfo:
            _reject_existing_destination(target, overwrite=False)
        assert "--force" in str(excinfo.value)


class TestWriteAtomically:
    """The write stage, with no displacement or rollback in play."""

    def test_it_creates_missing_parents(self, tmp_path):
        target = tmp_path / "a" / "b" / "key"
        _write_atomically(target, b"data", mode=SECRET_FILE_MODE, dir_mode=0o700)
        assert target.read_bytes() == b"data"

    @posix_only
    def test_it_applies_the_requested_modes(self, tmp_path):
        target = tmp_path / "nested" / "key"
        _write_atomically(target, b"data", mode=PUBLIC_FILE_MODE, dir_mode=0o700)
        assert stat.S_IMODE(target.stat().st_mode) == PUBLIC_FILE_MODE
        assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700

    def test_it_leaves_no_temporary_behind_on_success(self, tmp_path):
        _write_atomically(
            tmp_path / "key", b"data", mode=SECRET_FILE_MODE, dir_mode=0o700
        )
        assert [p.name for p in tmp_path.iterdir()] == ["key"]

    def test_it_leaves_no_temporary_behind_on_failure(self, tmp_path, monkeypatch):
        """A failed write must not litter the key directory with .tmp files."""

        def boom(*_args, **_kwargs):
            raise OSError(5, "I/O error")

        monkeypatch.setattr(_io.os, "fsync", boom)
        with pytest.raises(KeyWriteError, match="I/O error"):
            _write_atomically(
                tmp_path / "key", b"data", mode=SECRET_FILE_MODE, dir_mode=0o700
            )
        assert list(tmp_path.iterdir()) == []

    def test_an_undirectory_parent_is_a_typed_error(self, tmp_path):
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"not a directory")
        with pytest.raises(KeyWriteError, match="Could not create directory"):
            _write_atomically(
                blocker / "key", b"data", mode=SECRET_FILE_MODE, dir_mode=0o700
            )

    def test_a_failing_temporary_file_is_a_typed_error(self, tmp_path, monkeypatch):
        def boom(*_args, **_kwargs):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(_io.tempfile, "mkstemp", boom)
        with pytest.raises(KeyWriteError, match="No space left on device"):
            _write_atomically(
                tmp_path / "key", b"data", mode=SECRET_FILE_MODE, dir_mode=0o700
            )


class TestDisplaced:
    """The rollback record: a backup is only useful if it goes back."""

    @posix_only
    def test_displacing_preserves_the_original_mode(self, tmp_path):
        target = tmp_path / "key"
        target.write_bytes(b"old")
        target.chmod(0o640)
        displaced = _displace(target)
        assert displaced.mode == 0o640
        assert stat.S_IMODE(displaced.backup.stat().st_mode) == 0o640
        assert not target.exists()

    def test_restore_returns_the_contents_and_removes_the_backup(self, tmp_path):
        target = tmp_path / "key"
        target.write_bytes(b"old")
        displaced = _displace(target)
        displaced.restore()
        assert target.read_bytes() == b"old"
        assert not displaced.backup.exists()

    @posix_only
    def test_restore_returns_the_original_mode_not_the_default(self, tmp_path):
        """The mode that comes back is the displaced file's, not 0600."""
        target = tmp_path / "key"
        target.write_bytes(b"old")
        target.chmod(0o604)
        _displace(target).restore()
        assert stat.S_IMODE(target.stat().st_mode) == 0o604

    def test_restore_swallows_failure_so_it_cannot_mask_the_real_error(self, tmp_path):
        """A rollback is best effort: the write's own error must survive."""
        missing = _Displaced(
            backup=tmp_path / "gone", target=tmp_path / "key", mode=SECRET_FILE_MODE
        )
        missing.restore()  # must not raise
        assert not (tmp_path / "key").exists()

    def test_a_second_backup_in_the_same_second_does_not_collide(self, tmp_path):
        """Timestamps have one-second resolution; names must still be unique."""
        first = tmp_path / "key"
        first.write_bytes(b"one")
        backup_one = _displace(first).backup
        first.write_bytes(b"two")
        backup_two = _displace(first).backup
        assert backup_one != backup_two
        assert backup_one.read_bytes() == b"one"
        assert backup_two.read_bytes() == b"two"


class TestOutcome:
    """The reported result has to match what was actually done."""

    def test_no_displacement_reports_no_backup(self, tmp_path):
        assert _outcome(tmp_path / "key", None, replaced=False) == WriteOutcome(
            path=tmp_path / "key", backup=None, replaced=False, backup_mode=None
        )

    def test_a_displacement_is_reported_with_its_mode(self, tmp_path):
        displaced = _Displaced(
            backup=tmp_path / "key.bak", target=tmp_path / "key", mode=0o640
        )
        outcome = _outcome(tmp_path / "key", displaced, replaced=True)
        assert outcome.backup == tmp_path / "key.bak"
        assert outcome.backup_mode == 0o640
        assert outcome.replaced is True
