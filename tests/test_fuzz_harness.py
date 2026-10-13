# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""The fuzz harness must at least import and run.

It lives outside the package and the test paths, so when the CLI was split
into a package and `_strip_one_trailing_newline` moved, `fuzz/targets.py`
failed at import and nothing in the main suite noticed -- only the separate
CI fuzz job, which then failed on every run. Running each target a few times
here makes a broken harness a unit-test failure, found locally.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

FUZZ_DIR = Path(__file__).resolve().parent.parent / "fuzz"


@pytest.fixture(scope="module")
def targets():
    sys.path.insert(0, str(FUZZ_DIR))
    try:
        import targets as module

        yield module
    finally:
        sys.path.remove(str(FUZZ_DIR))
        sys.modules.pop("targets", None)


def test_every_target_survives_a_few_inputs(targets):
    rng = random.Random(0)  # noqa: S311 - seeded for reproducibility, not crypto
    for name, target in targets.TARGETS.items():
        for size in (0, 1, 10, 64, 200):
            target(rng.randbytes(size))
        assert name


def test_the_streaming_reader_has_its_own_targets(targets):
    assert {"decrypt_stream", "decrypt_stream_mutated"} <= set(targets.TARGETS)
