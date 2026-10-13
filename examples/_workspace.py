# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""A temporary directory that removes itself when the example exits.

Every example writes real key material, so every example has to clean up
after itself. Leaving a private key in a temporary directory is a poor habit
for a reader to copy, and on a constrained temporary filesystem repeated runs
eventually fill it.

Registered with :mod:`atexit` rather than written as a context manager so an
example's body stays flat and readable, which is the point of an example.
"""

from __future__ import annotations

import atexit
import shutil
import tempfile
from pathlib import Path

__all__ = ["workspace"]


def workspace() -> Path:
    """Create a temporary directory, removed when the process exits.

    Returns:
        Path to a new empty directory.

    Example:
        >>> workspace().is_dir()
        True
    """
    path = Path(tempfile.mkdtemp(prefix="encryption-helper-example-"))
    atexit.register(shutil.rmtree, path, ignore_errors=True)
    return path
