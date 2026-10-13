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
    """Whether this suite is the one living in the git working tree.

    The release gate copies ``tests/`` to a scratch directory and runs it
    against an installed wheel, so repository-hygiene checks -- which shell out
    to git against the source tree -- have nothing meaningful to inspect there.

    Merely being *inside* a git repository is not enough to decide this: the
    scratch directory may itself sit under the repository. The precise
    question is whether this file sits directly beside the package source, so
    that is what is asked.
    """
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
            cwd=Path(__file__).resolve().parent,
        )
    except OSError:  # pragma: no cover - git absent
        return False
    if completed.returncode != 0:
        return False

    toplevel = Path(completed.stdout.strip()).resolve()
    here = Path(__file__).resolve()
    return here.parents[1] == toplevel and (toplevel / "encryption_helper").is_dir()


#: Repository-hygiene checks that only make sense in the source tree.
source_tree_only = pytest.mark.skipif(
    not _in_source_tree(),
    reason="repository-hygiene check; not applicable to an installed wheel",
)


def envelope(text: str) -> dict:
    """Parse a CLI JSON document, asserting the envelope contract holds.

    Every assertion here is part of the published contract in
    ``docs/schemas/cli-output-v1.json``. Checking it at each call site rather
    than once means a command that forgets the envelope fails the test that
    reads its output, not a separate test somewhere else.
    """
    import json

    document = json.loads(text)
    assert document["schema_version"] == 1, document
    assert document["status"] in {"ok", "error"}, document
    assert document["tool"]["name"] == "encryption-helper", document
    assert isinstance(document["tool"]["version"], str), document
    return document


def result_of(text: str) -> dict:
    """Return the ``result`` body of a successful CLI JSON document."""
    document = envelope(text)
    assert document["status"] == "ok", document
    return document["result"]


def error_of(text: str) -> dict:
    """Return the ``error`` body of a failed CLI JSON document."""
    document = envelope(text)
    assert document["status"] == "error", document
    return document["error"]
