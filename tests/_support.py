# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Shared markers and helpers for the test suite."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

#: Permission assertions are meaningless on Windows, where access is governed
#: by ACLs rather than mode bits.
posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits are not meaningful on Windows",
)


def _in_source_tree() -> bool:
    """Whether the suite is running inside the git working tree.

    The release gate installs the wheel and runs the tests from a scratch
    directory, so repository-hygiene checks -- which shell out to git against
    the source tree -- have nothing to inspect there. They are skipped rather
    than failing, because they assert something about the repository, not
    about the package.
    """
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:  # pragma: no cover - git absent
        return False
    if completed.returncode != 0:
        return False
    return (Path(completed.stdout.strip()) / "pyproject.toml").is_file()


#: Repository-hygiene checks that only make sense in the source tree.
source_tree_only = pytest.mark.skipif(
    not _in_source_tree(),
    reason="repository-hygiene check; not applicable to an installed wheel",
)
