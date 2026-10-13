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
import errno
import logging
import os
import re
import stat
import sys
from pathlib import Path

import pytest
from encryption_helper import _platform
from encryption_helper._io import PUBLIC_FILE_MODE, secure_write_bytes
from encryption_helper.errors import KeyWriteError

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits")
PACKAGE = Path(_platform.__file__).parent


#: Both distributions: the MCP server once carried its own copy of the open
#: flags, which this test did not look at.
SOURCES = (PACKAGE, PACKAGE.parent / "packages" / "encryption-helper-mcp")

#: Attributes of ``os`` that only exist, or only mean something, on some
#: platforms. Reaching for one is a platform decision.
_PLATFORM_ATTRIBUTES = frozenset(
    {
        "fchmod",
        "lchmod",
        "geteuid",
        "getuid",
        "supports_fd",
        "supports_dir_fd",
        "supports_follow_symlinks",
    }
)


def _platform_checks(path: Path) -> list[int]:
    """Line numbers in ``path`` that test or depend on the platform."""
    lines = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Attribute) and (
            (node.attr == "platform" and getattr(node.value, "id", "") == "sys")
            or (node.attr == "name" and getattr(node.value, "id", "") == "os")
            or (
                node.attr.startswith("O_")
                and node.attr not in {"O_RDONLY", "O_WRONLY", "O_RDWR"}
            )
            or node.attr in _PLATFORM_ATTRIBUTES
        ):
            lines.append(node.lineno)
        # getattr(os, "O_NOFOLLOW", 0): the same flag, spelled as a string.
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", "") == "getattr"
            and len(node.args) >= 2
            and getattr(node.args[0], "id", "") == "os"
            and isinstance(node.args[1], ast.Constant)
        ):
            lines.append(node.lineno)
    return lines


def test_no_other_module_tests_the_platform():
    """A platform check outside the adapter is how logic leaks back in."""
    offenders = [
        f"{path.relative_to(PACKAGE.parent)}:{line}"
        for source in SOURCES
        for path in sorted(source.rglob("*.py"))
        if path.name != "_platform.py" and "tests" not in path.parts
        for line in _platform_checks(path)
    ]
    assert offenders == [], f"platform logic outside _platform.py: {offenders}"


def test_the_check_sees_every_spelling(tmp_path):
    """The detector itself must catch the forms that once slipped past it."""
    sample = tmp_path / "leak.py"
    sample.write_text(
        "import os, sys\n"
        "a = sys.platform\n"
        "b = getattr(os, 'O_NOFOLLOW', 0)\n"
        "c = os.O_DIRECTORY\n"
        "d = os.scandir in os.supports_fd\n"
        "e = os.O_RDONLY\n",
        encoding="utf-8",
    )
    assert _platform_checks(sample) == [2, 3, 4, 5]


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


@posix_only
class TestRestrictPathDoesNotFollowLinks:
    """``os.chmod`` follows a link, so a link swapped in for a backup or a
    restored key moved its target's permissions instead."""

    @pytest.mark.parametrize("lchmod", [True, False])
    def test_a_symlink_target_keeps_its_mode(self, tmp_path, monkeypatch, lchmod):
        if lchmod and os.chmod not in os.supports_follow_symlinks:
            pytest.skip("no lchmod on this platform")
        if not lchmod:
            monkeypatch.setattr(_platform.os, "supports_follow_symlinks", set())
        victim = tmp_path / "victim"
        victim.write_bytes(b"x")
        victim.chmod(0o644)
        link = tmp_path / "link"
        link.symlink_to(victim)
        if lchmod:
            _platform.restrict_path(link, 0o600)  # changes the link itself
        else:
            with pytest.raises(
                OSError, match=re.escape(os.strerror(errno.ELOOP))
            ) as info:
                _platform.restrict_path(link, 0o600)
            assert info.value.errno == errno.ELOOP
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644

    def test_a_regular_file_is_still_restricted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_platform.os, "supports_follow_symlinks", set())
        target = tmp_path / "f"
        target.write_bytes(b"x")
        target.chmod(0o644)
        _platform.restrict_path(target, 0o600)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_the_unopenable_fallback_still_refuses_a_symlink(
        self, tmp_path, monkeypatch
    ):
        """Where the no-follow open is unavailable, chmod must not follow."""
        monkeypatch.setattr(_platform.os, "supports_follow_symlinks", set())

        def denied(*_args, **_kwargs):
            raise PermissionError(errno.EACCES, "Permission denied")

        victim = tmp_path / "victim"
        victim.write_bytes(b"x")
        victim.chmod(0o644)
        link = tmp_path / "link"
        link.symlink_to(victim)
        monkeypatch.setattr(_platform.os, "open", denied)
        with pytest.raises(OSError, match=re.escape(os.strerror(errno.ELOOP))):
            _platform.restrict_path(link, 0o600)
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644

    def test_a_file_its_owner_cannot_open_is_still_restricted(
        self, tmp_path, monkeypatch
    ):
        """No read or write bit for the owner: fall back to a checked chmod."""
        if os.geteuid() == 0:
            pytest.skip("root opens anything")
        monkeypatch.setattr(_platform.os, "supports_follow_symlinks", set())
        target = tmp_path / "f"
        target.write_bytes(b"x")
        target.chmod(0o000)
        _platform.restrict_path(target, 0o600)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
