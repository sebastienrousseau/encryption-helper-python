#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Atheris entry point for the envelope decryption target.

Run:
    pip install atheris
    python fuzz/fuzz_decrypt.py -atheris_runs=100000
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from targets import TARGETS


def main() -> None:
    """Hand the decrypt targets to Atheris."""
    import atheris

    def one_input(data: bytes) -> None:
        TARGETS["decrypt"](data)
        TARGETS["decrypt_mutated"](data)

    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
