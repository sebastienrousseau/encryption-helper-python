# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""The single place operating-system differences live.

Platform checks used to be scattered -- ``sys.platform`` in two modules,
``os.name`` in a third -- and a private key's directory was never examined,
so "0600 inside a 0700 directory" held only for directories this package
created itself.
"""

from __future__ import annotations

import ast
import logging
import stat
import sys
from pathlib import Path

import pytest
from encryption_helper import _platform
from encryption_helper._io import PUBLIC_FILE_MODE, secure_write_bytes
from encryption_helper.errors import KeyWriteError

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
PACKAGE = Path(_platform.__file__).parent


def test_no_other_module_tests_the_platform():
    """A platform check outside the adapter is how logic leaks back in."""
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        if path.name == "_platform.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and (
                (node.attr == "platform" and getattr(node.value, "id", "") == "sys")
                or (node.attr == "name" and getattr(node.value, "id", "") == "os")
                or node.attr in {"fchmod", "O_NOFOLLOW", "O_NONBLOCK"}
            ):
                offenders.append(f"{path.relative_to(PACKAGE)}:{node.lineno}")
    assert offenders == [], f"platform logic outside _platform.py: {offenders}"


@posix_only
class TestExposedDirectory:
    def test_an_owner_only_directory_is_fine(self, tmp_path):
        tmp_path.chmod(0o700)
        assert _platform.exposed_directory(tmp_path) is None

    def test_a_world_writable_directory_is_flagged(self, tmp_path):
        tmp_path.chmod(0o777)
        try:
            reason = _platform.exposed_directory(tmp_path)
        finally:
            tmp_path.chmod(0o700)
        assert reason is not None
        assert "0777" in reason

    def test_a_sticky_shared_directory_is_not_flagged(self, tmp_path):
        """Like /tmp: others can write, but cannot replace your files."""
        tmp_path.chmod(0o1777)
        try:
            assert _platform.exposed_directory(tmp_path) is None
        finally:
            tmp_path.chmod(0o700)

    def test_a_directory_that_cannot_be_inspected_is_not_flagged(self, tmp_path):
        assert _platform.exposed_directory(tmp_path / "absent") is None


def test_windows_never_judges_by_mode_bits(tmp_path, monkeypatch):
    monkeypatch.setattr(_platform, "WINDOWS", True)
    assert _platform.exposed_directory(tmp_path) is None
    assert _platform.group_or_world_readable(tmp_path) is None


@posix_only
class TestWarningOnSecretWrites:
    @pytest.fixture
    def exposed(self, tmp_path):
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        yield shared
        shared.chmod(0o700)

    def test_a_secret_written_to_an_exposed_directory_is_warned_about(
        self, exposed, caplog
    ):
        with caplog.at_level(logging.WARNING, logger="encryption_helper._io"):
            secure_write_bytes(exposed / "id.key", b"secret")
        assert "other users can write to it" in caplog.text

    def test_a_public_file_is_not_warned_about(self, exposed, caplog):
        with caplog.at_level(logging.WARNING, logger="encryption_helper._io"):
            secure_write_bytes(exposed / "id.pub", b"public", mode=PUBLIC_FILE_MODE)
        assert caplog.text == ""

    def test_an_owner_only_directory_is_not_warned_about(self, tmp_path, caplog):
        tmp_path.chmod(0o700)
        with caplog.at_level(logging.WARNING, logger="encryption_helper._io"):
            secure_write_bytes(tmp_path / "id.key", b"secret")
        assert caplog.text == ""


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="needs /proc")
def test_a_failing_chmod_does_not_leak_the_descriptor(tmp_path, monkeypatch):
    """The descriptor was adopted only after fchmod, so a failure leaked it."""

    def refuse(*_args, **_kwargs):
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(_platform, "restrict_descriptor", refuse)
    before = len(list(Path("/proc/self/fd").iterdir()))
    for _ in range(5):
        with pytest.raises(KeyWriteError):
            secure_write_bytes(tmp_path / "k", b"secret")
    assert len(list(Path("/proc/self/fd").iterdir())) == before
    assert list(tmp_path.iterdir()) == []


@posix_only
def test_files_are_still_written_owner_only(tmp_path):
    outcome = secure_write_bytes(tmp_path / "k", b"secret")
    assert stat.S_IMODE(outcome.path.stat().st_mode) == 0o600
