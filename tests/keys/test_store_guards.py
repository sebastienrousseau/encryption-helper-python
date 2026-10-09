# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Unit tests for the individual preflight guards in :mod:`keys.store`.

``_preflight`` ran five checks in one body. Driving them through
:func:`write_key_pair` meant generating a real key pair per case, which is
slow and conflates the guard with everything downstream of it. Each guard is
now addressed directly, so a case is a path and an expectation.
"""

from __future__ import annotations

import os
import sys

import pytest
from encryption_helper.errors import KeyExistsError, KeyWriteError
from encryption_helper.keys.store import (
    _preflight,
    _reject_aliased_pair,
    _reject_directory_destinations,
    _reject_existing_pair,
    _reject_identical_paths,
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="hard links need POSIX semantics"
)


class TestRejectIdenticalPaths:
    def test_distinct_paths_pass(self, tmp_path):
        _reject_identical_paths(tmp_path / "k", tmp_path / "k.pub")

    def test_one_name_for_both_halves_is_refused(self, tmp_path):
        with pytest.raises(KeyWriteError, match="both be written to"):
            _reject_identical_paths(tmp_path / "k", tmp_path / "k")


class TestRejectDirectoryDestinations:
    def test_absent_and_regular_paths_pass(self, tmp_path):
        (tmp_path / "file").write_bytes(b"")
        _reject_directory_destinations(tmp_path / "absent", tmp_path / "file")

    @pytest.mark.parametrize("position", [0, 1])
    def test_a_directory_is_refused_in_either_position(self, tmp_path, position):
        """Both halves are checked, not just the first."""
        directory = tmp_path / "dir"
        directory.mkdir()
        paths = [tmp_path / "file", tmp_path / "file.pub"]
        paths[position] = directory
        with pytest.raises(KeyWriteError, match="is a directory"):
            _reject_directory_destinations(*paths)


class TestRejectAliasedPair:
    def test_two_distinct_files_pass(self, tmp_path):
        for name in ("k", "k.pub"):
            (tmp_path / name).write_bytes(b"x")
        _reject_aliased_pair(tmp_path / "k", tmp_path / "k.pub")

    def test_absent_files_cannot_alias(self, tmp_path):
        """samefile() needs both to exist, so absence short-circuits."""
        _reject_aliased_pair(tmp_path / "absent", tmp_path / "also-absent")

    @posix_only
    def test_a_hard_link_between_the_halves_is_refused(self, tmp_path):
        private = tmp_path / "k"
        private.write_bytes(b"x")
        public = tmp_path / "k.pub"
        os.link(private, public)
        with pytest.raises(KeyWriteError, match="are the same file"):
            _reject_aliased_pair(private, public)

    @posix_only
    def test_a_symlink_between_the_halves_is_refused(self, tmp_path):
        private = tmp_path / "k"
        private.write_bytes(b"x")
        public = tmp_path / "k.pub"
        public.symlink_to(private)
        with pytest.raises(KeyWriteError, match="are the same file"):
            _reject_aliased_pair(private, public)

    def test_a_racing_stat_failure_is_not_treated_as_aliasing(
        self, tmp_path, monkeypatch
    ):
        """If samefile() cannot answer, the guard declines rather than guesses."""
        private = tmp_path / "k"
        private.write_bytes(b"x")
        public = tmp_path / "k.pub"
        public.write_bytes(b"y")

        def boom(*_args, **_kwargs):
            raise OSError(2, "No such file or directory")

        monkeypatch.setattr(type(private), "samefile", boom)
        _reject_aliased_pair(private, public)


class TestRejectExistingPair:
    def test_absent_destinations_pass(self, tmp_path):
        _reject_existing_pair(tmp_path / "k", tmp_path / "k.pub", overwrite=False)

    def test_overwrite_skips_the_check_entirely(self, tmp_path):
        for name in ("k", "k.pub"):
            (tmp_path / name).write_bytes(b"x")
        _reject_existing_pair(tmp_path / "k", tmp_path / "k.pub", overwrite=True)

    @pytest.mark.parametrize("present", ["k", "k.pub"])
    def test_either_half_existing_is_enough_to_refuse(self, tmp_path, present):
        (tmp_path / present).write_bytes(b"x")
        with pytest.raises(KeyExistsError) as excinfo:
            _reject_existing_pair(tmp_path / "k", tmp_path / "k.pub", overwrite=False)
        assert present in str(excinfo.value)

    def test_the_error_lists_every_file_in_the_way(self, tmp_path):
        for name in ("k", "k.pub"):
            (tmp_path / name).write_bytes(b"x")
        with pytest.raises(KeyExistsError) as excinfo:
            _reject_existing_pair(tmp_path / "k", tmp_path / "k.pub", overwrite=False)
        message = str(excinfo.value)
        assert str(tmp_path / "k") in message
        assert str(tmp_path / "k.pub") in message


class TestPreflightOrdering:
    """``_preflight`` contributes only an order; that order is the behaviour."""

    def test_a_directory_is_reported_before_an_existing_file(self, tmp_path):
        """The structural problem is the actionable one, so it wins."""
        private = tmp_path / "k"
        private.mkdir()
        (tmp_path / "k.pub").write_bytes(b"x")
        with pytest.raises(KeyWriteError, match="is a directory"):
            _preflight(private, tmp_path / "k.pub", overwrite=False)

    def test_identical_paths_are_reported_before_aliasing(self, tmp_path):
        """Equal paths get the clearer message, not the hard-link one."""
        target = tmp_path / "k"
        target.write_bytes(b"x")
        with pytest.raises(KeyWriteError, match="both be written to"):
            _preflight(target, target, overwrite=False)

    def test_clean_destinations_pass_every_guard(self, tmp_path):
        _preflight(tmp_path / "k", tmp_path / "k.pub", overwrite=False)
