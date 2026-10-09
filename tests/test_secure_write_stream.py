# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""The streaming writer must keep every promise the buffered writer makes.

The CLI wrote encrypted and decrypted files through its own path, which
renamed a temporary file straight over the target. So ``--force`` destroyed
the previous file while its message promised a backup, a symlinked
destination was followed, a file created during the write was clobbered,
new directories were 0755, and the directory was never synced. All file
output now goes through :func:`secure_write_stream`.
"""

from __future__ import annotations

import os
import signal
import stat
import sys

import pytest
from encryption_helper._io import secure_write_stream
from encryption_helper.errors import KeyExistsError, KeyWriteError

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX semantics")


def _write(path, data=b"new", **kwargs):
    with secure_write_stream(path, **kwargs) as (handle, outcome):
        handle.write(data)
    return outcome[0]


def _race(target):
    """Write, while another party creates the destination mid-write."""
    with secure_write_stream(target) as (handle, _):
        handle.write(b"ours")
        target.write_bytes(b"theirs")


def _fail_midway(target):
    with secure_write_stream(target, overwrite=True) as (handle, _):
        handle.write(b"half")
        raise RuntimeError


def _terminated_midway(target):
    from encryption_helper.cli._main import _sigterm_unwinds

    with _sigterm_unwinds(), secure_write_stream(target) as (handle, _):
        handle.write(b"partial plaintext")
        os.kill(os.getpid(), signal.SIGTERM)


class TestCommit:
    def test_writes_and_reports_the_destination(self, tmp_path):
        outcome = _write(tmp_path / "out.bin", b"payload")
        assert outcome.path.read_bytes() == b"payload"
        assert outcome.replaced is False
        assert outcome.backup is None

    def test_no_temporary_file_survives_success(self, tmp_path):
        _write(tmp_path / "out.bin")
        assert [p.name for p in tmp_path.iterdir()] == ["out.bin"]

    @posix_only
    def test_file_and_new_directories_are_private(self, tmp_path):
        outcome = _write(tmp_path / "new" / "dir" / "out.bin", mode=0o600)
        assert stat.S_IMODE(outcome.path.stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "new" / "dir").stat().st_mode) == 0o700


class TestExistingDestinations:
    def test_existing_file_is_refused_without_overwrite(self, tmp_path):
        target = tmp_path / "out.bin"
        target.write_bytes(b"old")
        with pytest.raises(KeyExistsError):
            _write(target)
        assert target.read_bytes() == b"old"

    def test_overwrite_backs_up_the_previous_file(self, tmp_path):
        target = tmp_path / "out.bin"
        target.write_bytes(b"old")
        outcome = _write(target, b"new", overwrite=True)
        assert target.read_bytes() == b"new"
        assert outcome.replaced is True
        assert outcome.backup is not None
        assert outcome.backup.read_bytes() == b"old"

    def test_the_old_file_stays_in_place_until_the_new_one_is_complete(self, tmp_path):
        """Displacement happens at commit, not before a long write."""
        target = tmp_path / "out.bin"
        target.write_bytes(b"old")
        with secure_write_stream(target, overwrite=True) as (handle, _):
            handle.write(b"partial")
            assert target.read_bytes() == b"old"

    @posix_only
    def test_a_symlink_destination_is_refused(self, tmp_path):
        real = tmp_path / "elsewhere.bin"
        real.write_bytes(b"victim")
        link = tmp_path / "out.bin"
        link.symlink_to(real)
        with pytest.raises(KeyWriteError, match="symbolic link"):
            _write(link, overwrite=True)
        assert real.read_bytes() == b"victim"

    def test_a_file_created_during_the_write_is_not_clobbered(self, tmp_path):
        """The race a check-then-rename commit loses."""
        target = tmp_path / "out.bin"
        with pytest.raises(KeyExistsError):
            _race(target)
        assert target.read_bytes() == b"theirs"
        assert not list(tmp_path.glob("*.tmp"))


class TestFailures:
    def test_a_failure_in_the_body_leaves_nothing_behind(self, tmp_path):
        target = tmp_path / "out.bin"
        target.write_bytes(b"old")
        with pytest.raises(RuntimeError):
            _fail_midway(target)
        assert target.read_bytes() == b"old"
        assert [p.name for p in tmp_path.iterdir()] == ["out.bin"]

    def test_a_failed_commit_restores_the_backup(self, tmp_path, monkeypatch):
        target = tmp_path / "out.bin"
        target.write_bytes(b"old")

        def failing_commit(tmp, final):
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(
            "encryption_helper._io._commit_without_clobbering", failing_commit
        )
        with pytest.raises(KeyWriteError, match="Could not write"):
            _write(target, overwrite=True)
        monkeypatch.undo()
        assert target.read_bytes() == b"old"
        assert [p.name for p in tmp_path.iterdir()] == ["out.bin"]

    def test_an_unwritable_directory_is_a_key_write_error(self, tmp_path, monkeypatch):
        def no_temp(*_args, **_kwargs):
            raise OSError(13, "Permission denied")

        monkeypatch.setattr("encryption_helper._io.tempfile.mkstemp", no_temp)
        with pytest.raises(KeyWriteError, match="Permission denied"):
            _write(tmp_path / "out.bin")


class TestCommitWithoutHardLinks:
    """FAT and some network filesystems cannot hard-link."""

    @pytest.fixture
    def no_links(self, monkeypatch):
        def refuse(*_args, **_kwargs):
            raise OSError(1, "Operation not permitted")

        monkeypatch.setattr("encryption_helper._io.os.link", refuse)

    def test_falls_back_to_a_rename(self, tmp_path, no_links):
        outcome = _write(tmp_path / "out.bin", b"via rename")
        assert outcome.path.read_bytes() == b"via rename"
        assert not list(tmp_path.glob("*.tmp"))

    def test_the_fallback_still_refuses_a_racing_file(self, tmp_path, no_links):
        target = tmp_path / "out.bin"
        with pytest.raises(KeyExistsError):
            _race(target)
        assert target.read_bytes() == b"theirs"

    def test_cleanup_failure_after_the_commit_is_not_a_failed_write(
        self, tmp_path, monkeypatch
    ):
        """Once linked, the write is done; a leftover name must not undo it."""
        from pathlib import Path

        real_unlink = Path.unlink

        def unlink(self, *args, **kwargs):
            if self.name.endswith(".tmp") and self.exists():
                raise OSError(1, "Operation not permitted")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", unlink)
        outcome = _write(tmp_path / "out.bin", b"committed")
        assert outcome.path.read_bytes() == b"committed"


@pytest.mark.skipif(
    not hasattr(signal, "SIGTERM") or sys.platform == "win32",
    reason="needs POSIX signal delivery to the current process",
)
class TestSigtermCleansUp:
    def test_sigterm_during_a_write_removes_the_temporary_file(self, tmp_path):
        target = tmp_path / "plain.out"
        with pytest.raises(SystemExit) as excinfo:
            _terminated_midway(target)
        assert excinfo.value.code == 128 + signal.SIGTERM
        assert list(tmp_path.iterdir()) == []

    def test_the_previous_handler_is_restored(self):
        from encryption_helper.cli._main import _sigterm_unwinds

        before = signal.getsignal(signal.SIGTERM)
        with _sigterm_unwinds():
            assert signal.getsignal(signal.SIGTERM) is not before
        assert signal.getsignal(signal.SIGTERM) is before

    def test_off_the_main_thread_it_installs_nothing(self):
        import threading

        from encryption_helper.cli._main import _sigterm_unwinds

        before = signal.getsignal(signal.SIGTERM)
        seen = []

        def run():
            with _sigterm_unwinds():
                seen.append(signal.getsignal(signal.SIGTERM))

        worker = threading.Thread(target=run)
        worker.start()
        worker.join()
        assert seen == [before]


class TestCommitPrimitive:
    """The last line of defence, for a file that appears after every check."""

    def _pair(self, tmp_path):
        tmp = tmp_path / ".out.bin.x.tmp"
        tmp.write_bytes(b"ours")
        target = tmp_path / "out.bin"
        target.write_bytes(b"theirs")
        return tmp, target

    def test_a_taken_name_is_never_overwritten(self, tmp_path):
        from encryption_helper._io import _commit_without_clobbering

        tmp, target = self._pair(tmp_path)
        with pytest.raises(KeyExistsError, match="Nothing was overwritten"):
            _commit_without_clobbering(tmp, target)
        assert target.read_bytes() == b"theirs"

    def test_nor_without_hard_links(self, tmp_path, monkeypatch):
        from encryption_helper._io import _commit_without_clobbering

        def refuse(*_args, **_kwargs):
            raise OSError(1, "Operation not permitted")

        monkeypatch.setattr("encryption_helper._io.os.link", refuse)
        tmp, target = self._pair(tmp_path)
        with pytest.raises(KeyExistsError, match="Nothing was overwritten"):
            _commit_without_clobbering(tmp, target)
        assert target.read_bytes() == b"theirs"
