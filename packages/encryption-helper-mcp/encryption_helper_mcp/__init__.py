# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Read-only Model Context Protocol server for encryption-helper.

Exposes the assessment side of :mod:`encryption_helper` to an assistant:
which algorithms stop being acceptable and when, what protects a given
encrypted file, and what cryptographic material exists under a path.

It deliberately exposes nothing that acts. Key generation, encryption,
decryption and signing are absent by design, because routing private key
material through a model's context window would contradict the purpose of a
tool whose job is to keep that material on the operator's machine. The
command-line interface remains the way to perform those operations.
"""

from __future__ import annotations

__all__ = ["__version__"]

#: Kept in step with the core package by ``tests/test_packaging.py``.
__version__ = "0.0.2"
