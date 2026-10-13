# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Regressions for the filesystem audit of :mod:`encryption_helper._io`.

Each class pins one finding:

* ``secure_write_bytes`` displaced the old key *before* writing and caught
  only ``OSError``. A SIGTERM (which the CLI turns into ``SystemExit``) or a
  Ctrl-C during the write left no file at the destination, the old key at a
  ``.bak-`` name and the new secret in a stray ``.tmp``.
* ``mkdir(parents=True, mode=...)`` applies the mode to the leaf only, so
  intermediate directories were created at the umask default.
* Backup names were predictable to the second and checked with ``exists()``,
  which follows symlinks: a dangling link at the next name was replaced.
* A rollback could replace a file another process created during the write.
* A failure to remove the temporary name after the commit was silent, though
  it leaves a second copy of the secret.
* A long file name failed with a bare "File name too long" that blamed the
  name the caller chose rather than the suffix this package adds.
* *Any* error from ``os.link`` was taken to mean "hard links unsupported",
  dropping to the racy check-then-rename commit.
"""

from __future__ import annotations

import errno
import logging
import os
import re
import stat
import sys
from pathlib import Path

import pytest
from encryption_helper import _io, _platform
from encryption_helper._io import secure_write_bytes, secure_write_stream
from encryption_helper.errors import KeyExistsError, KeyWriteError

from ._support import posix_only

windows_skip = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX name limits and symlinks"
)


def _write_bytes(target: Path, data: bytes, **kwargs: object) -> None:
    secure_write_bytes(target, data, **kwargs)  # type: ignore[arg-type]


def _write_stream(target: Path, data: bytes, **kwargs: object) -> None:
    with secure_write_stream(target, **kwargs) as (handle, _):  # type: ignore[arg-type]
        handle.write(data)


WRITERS = pytest.mark.parametrize("write", [_write_bytes, _write_stream])


class TestInterruptedWrite:
    """M1: an interruption must leave the destination exactly as it was."""

    INTERRUPTS = pytest.mark.parametrize(
        "interrupt", [KeyboardInterrupt, lambda: SystemExit(143)]
    )

    @pytest.fixture(params=["fsync", "restrict_descriptor"])
    def interrupt_at(self, request, monkeypatch):
        """Raise the given interrupt from inside the write, before the commit."""

        def install(interrupt):
            def boom(*_args, **_kwargs):
                raise interrupt()

            if request.param == "fsync":
                monkeypatch.setattr(_io.os, "fsync", boom)
            else:
                monkeypatch.setattr(_platform, "restrict_descriptor", boom)

        return install

    @INTERRUPTS
    @WRITERS
    def test_an_overwrite_interrupted_mid_write_keeps_the_original(
        self, tmp_path, interrupt_at, interrupt, write
    ):
        target = tmp_path / "key.pem"
        target.write_bytes(b"OLD-SECRET")
        interrupt_at(interrupt)
        with pytest.raises((KeyboardInterrupt, SystemExit)):
            write(target, b"NEW-SECRET", overwrite=True)
        assert target.read_bytes() == b"OLD-SECRET"
        assert [p.name for p in tmp_path.iterdir()] == ["key.pem"]

    @INTERRUPTS
    @WRITERS
    def test_a_fresh_write_interrupted_mid_write_leaves_nothing(
        self, tmp_path, interrupt_at, interrupt, write
    ):
        interrupt_at(interrupt)
        with pytest.raises((KeyboardInterrupt, SystemExit)):
            write(tmp_path / "key.pem", b"NEW-SECRET")
        assert list(tmp_path.iterdir()) == []

    @INTERRUPTS
    def test_an_interrupt_after_displacement_restores_the_original(
        self, tmp_path, monkeypatch, interrupt
    ):
        """The last window: the old file is at its backup name."""
        target = tmp_path / "key.pem"
        target.write_bytes(b"OLD-SECRET")

        real = _io._commit_without_clobbering
        calls = []

        def interrupt_the_commit(source, final):
            calls.append(source)
            if len(calls) == 1:
                raise interrupt()
            real(source, final)  # the rollback's own commit

        monkeypatch.setattr(_io, "_commit_without_clobbering", interrupt_the_commit)
        with pytest.raises((KeyboardInterrupt, SystemExit)):
            secure_write_bytes(target, b"NEW-SECRET", overwrite=True)
        monkeypatch.undo()
        assert target.read_bytes() == b"OLD-SECRET"
        assert [p.name for p in tmp_path.iterdir()] == ["key.pem"]

    @INTERRUPTS
    def test_an_interrupt_just_after_the_commit_rolls_back(
        self, tmp_path, monkeypatch, interrupt
    ):
        """The new file is in place but unreported: put the original back."""
        target = tmp_path / "key.pem"
        target.write_bytes(b"OLD-SECRET")

        def boom(*_args, **_kwargs):
            raise interrupt()

        monkeypatch.setattr(_platform, "fsync_directory", boom)
        with pytest.raises((KeyboardInterrupt, SystemExit)):
            secure_write_bytes(target, b"NEW-SECRET", overwrite=True)
        assert target.read_bytes() == b"OLD-SECRET"
        assert [p.name for p in tmp_path.iterdir()] == ["key.pem"]


@posix_only
class TestIntermediateDirectoryModes:
    """L9: every directory created, not just the last, gets ``dir_mode``."""

    @pytest.fixture(autouse=True)
    def permissive_umask(self):
        previous = os.umask(0o022)
        yield
        os.umask(previous)

    @WRITERS
    def test_each_created_level_is_owner_only(self, tmp_path, write):
        write(tmp_path / "a" / "b" / "c" / "key", b"secret")
        for level in ("a", "a/b", "a/b/c"):
            assert stat.S_IMODE((tmp_path / level).stat().st_mode) == 0o700, level

    def test_existing_directories_are_left_alone(self, tmp_path):
        existing = tmp_path / "shared"
        existing.mkdir()
        existing.chmod(0o755)
        secure_write_bytes(existing / "new" / "key", b"secret")
        assert stat.S_IMODE(existing.stat().st_mode) == 0o755
        assert stat.S_IMODE((existing / "new").stat().st_mode) == 0o700

    def test_a_requested_dir_mode_is_applied_to_every_level(self, tmp_path):
        secure_write_bytes(tmp_path / "x" / "y" / "pub", b"p", dir_mode=0o750)
        assert stat.S_IMODE((tmp_path / "x").stat().st_mode) == 0o750
        assert stat.S_IMODE((tmp_path / "x" / "y").stat().st_mode) == 0o750


@windows_skip
class TestBackupNames:
    """L7(a): a planted entry at a backup name is never replaced."""

    def test_backup_names_are_not_predictable_from_the_clock(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(_io, "_timestamp", lambda: "FIXED")
        target = tmp_path / "key.pem"
        target.write_bytes(b"v1")
        secure_write_bytes(target, b"v2", overwrite=True)
        (backup,) = tmp_path.glob("key.pem.bak-*")
        assert backup.name != "key.pem.bak-FIXED"
        assert backup.name.startswith("key.pem.bak-FIXED-")

    def test_a_dangling_symlink_at_the_candidate_name_is_skipped(
        self, tmp_path, monkeypatch
    ):
        tags = iter(["planted", "fresh"])
        monkeypatch.setattr(_io, "_timestamp", lambda: "FIXED")
        monkeypatch.setattr(_io, "_random_tag", lambda: next(tags))
        planted = tmp_path / "key.pem.bak-FIXED-planted"
        planted.symlink_to(tmp_path / "nowhere")
        target = tmp_path / "key.pem"
        target.write_bytes(b"OLD")

        outcome = secure_write_bytes(target, b"NEW", overwrite=True)

        assert planted.is_symlink(), "the planted entry was replaced"
        assert outcome.backup == tmp_path / "key.pem.bak-FIXED-fresh"
        assert outcome.backup.read_bytes() == b"OLD"
        assert not (tmp_path / "nowhere").exists()


class TestRollbackDoesNotClobber:
    """L7(d): a restore must not replace a file another process created."""

    @WRITERS
    def test_a_file_created_during_a_failed_commit_is_kept(
        self, tmp_path, monkeypatch, write
    ):
        target = tmp_path / "key.pem"
        target.write_bytes(b"OLD")

        def fail_after_someone_else_wrote(_tmp, final):
            final.write_bytes(b"theirs")
            raise OSError(errno.EIO, "Input/output error")

        monkeypatch.setattr(
            _io, "_commit_without_clobbering", fail_after_someone_else_wrote
        )
        with pytest.raises(KeyWriteError, match=r"preserved at .*\.bak-") as info:
            write(target, b"NEW", overwrite=True)
        monkeypatch.undo()

        assert target.read_bytes() == b"theirs"
        (backup,) = tmp_path.glob("key.pem.bak-*")
        assert backup.read_bytes() == b"OLD"
        assert str(backup) in str(info.value)


class TestLeftoverTemporaryIsReported:
    """L7(f): a second copy of the secret must not be left silently."""

    def test_a_failed_cleanup_after_the_commit_is_logged(
        self, tmp_path, monkeypatch, caplog
    ):
        real_unlink = Path.unlink

        def refuse_tmp(self, *args, **kwargs):
            if self.name.endswith(".tmp"):
                raise OSError(errno.EBUSY, "Device or resource busy")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", refuse_tmp)
        with caplog.at_level(logging.WARNING, logger="encryption_helper._io"):
            outcome = secure_write_bytes(tmp_path / "key.pem", b"secret")
        monkeypatch.undo()

        assert outcome.path.read_bytes() == b"secret"
        (leftover,) = tmp_path.glob("*.tmp")
        assert str(leftover) in caplog.text


@windows_skip
class TestLongNames:
    """L7(g): the error names the real cause -- the temporary suffix."""

    @WRITERS
    def test_a_name_too_long_for_the_temporary_file_says_so(self, tmp_path, write):
        with pytest.raises(KeyWriteError, match="too long") as info:
            write(tmp_path / ("k" * 250), b"secret")
        assert "temporary" in str(info.value)
        assert list(tmp_path.iterdir()) == []

    def test_a_name_too_long_for_the_backup_says_so(self, tmp_path):
        target = tmp_path / ("k" * 235)
        target.write_bytes(b"OLD")
        with pytest.raises(KeyWriteError, match="too long") as info:
            secure_write_bytes(target, b"NEW", overwrite=True)
        assert "backup" in str(info.value)
        assert target.read_bytes() == b"OLD"
        assert [p.name for p in tmp_path.iterdir()] == [target.name]


class TestLinkFallback:
    """L7(h): only "links unsupported" errors drop to the racy rename."""

    @pytest.mark.parametrize("code", [errno.EACCES, errno.ENOSPC, errno.EIO])
    def test_other_link_errors_fail_the_write(self, tmp_path, monkeypatch, code):
        renamed = []

        def refuse(*_args, **_kwargs):
            raise OSError(code, os.strerror(code))

        monkeypatch.setattr(_io.os, "link", refuse)
        real_replace = Path.replace
        monkeypatch.setattr(
            Path,
            "replace",
            lambda self, other: renamed.append(other) or real_replace(self, other),
        )
        with pytest.raises(KeyWriteError, match=re.escape(os.strerror(code))):
            secure_write_bytes(tmp_path / "key.pem", b"secret")
        assert renamed == [], "fell back to a check-then-rename commit"
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.parametrize(
        "code", sorted(_platform.LINK_UNSUPPORTED_ERRNOS - {errno.EPERM})
    )
    def test_unsupported_links_still_fall_back(self, tmp_path, monkeypatch, code):
        def refuse(*_args, **_kwargs):
            raise OSError(code, os.strerror(code))

        monkeypatch.setattr(_io.os, "link", refuse)
        outcome = secure_write_bytes(tmp_path / "key.pem", b"secret")
        assert outcome.path.read_bytes() == b"secret"

    def test_windows_unsupported_link_codes_are_recognised(self):
        error = OSError(errno.EINVAL, "Incorrect function")
        error.winerror = 1  # type: ignore[attr-defined]
        assert _platform.hard_link_unsupported(error)
        assert not _platform.hard_link_unsupported(OSError(errno.EACCES, "denied"))


def test_racing_create_during_link_fallback_still_refused(tmp_path, monkeypatch):
    """The narrowed fallback keeps its own race check."""

    def unsupported(*_args, **_kwargs):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(_io.os, "link", unsupported)
    target = tmp_path / "k"

    def race():
        with secure_write_stream(target) as (handle, _):
            handle.write(b"ours")
            target.write_bytes(b"theirs")

    with pytest.raises(KeyExistsError):
        race()
    assert target.read_bytes() == b"theirs"
