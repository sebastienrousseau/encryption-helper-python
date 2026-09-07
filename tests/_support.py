"""Shared markers and helpers for the test suite."""

from __future__ import annotations

import sys

import pytest

#: Permission assertions are meaningless on Windows, where access is governed
#: by ACLs rather than mode bits.
posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits are not meaningful on Windows",
)
