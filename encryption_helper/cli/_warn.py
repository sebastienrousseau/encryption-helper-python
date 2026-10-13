# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Advisory warnings that do not stop the operation."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def _warn_if_inside_git_worktree(directory: Path) -> None:
    """Warn when key material is about to be written inside a git checkout.

    ``.gitignore`` is not a security boundary -- it can be bypassed with
    ``git add -f`` -- so the useful defence is to tell the user before the key
    exists, not after it is committed.
    """
    for candidate in [directory, *directory.parents]:
        if (candidate / ".git").exists():
            print(
                f"warning: {directory} is inside the git repository at "
                f"{candidate}.\n"
                "         Private keys should not live in a working tree. "
                "Use --out-dir to\n"
                "         write them somewhere outside it.",
                file=sys.stderr,
            )
            return
