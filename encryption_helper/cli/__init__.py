# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Command-line interface for :mod:`encryption_helper`.

This module owns everything to do with presentation: argument parsing, logging
configuration, human- and machine-readable output, and process exit codes. The
library modules underneath it do none of those things.

Exit codes:

===  ============================================================
0    Success.
1    An error occurred.
2    Usage error -- bad or missing arguments.
3    A destination file already exists and ``--force`` was not given.
4    Decryption or signature verification failed.
===  ============================================================

Passphrases are never accepted as a command-line value. Process arguments are
visible to every user on the system through ``/proc`` and are recorded in shell
history, so ``--passphrase-env`` and ``--passphrase-file`` are the only ways to
supply one.

The implementation is split across private submodules: :mod:`._parser` builds
the parser, :mod:`._commands` holds one function per subcommand, and the
layers underneath (:mod:`._passphrase`, :mod:`._streams`, :mod:`._progress`)
are independent of :mod:`argparse`, so they can be unit tested directly.
This module is the only supported import surface.
"""

from __future__ import annotations

from ._constants import (
    DEFAULT_MAX_INPUT_BYTES,
    EXIT_CRYPTO_FAILURE,
    EXIT_ERROR,
    EXIT_KEY_EXISTS,
    EXIT_OK,
    EXIT_USAGE,
    JSON_SCHEMA_VERSION,
    MAX_PASSPHRASE_FILE_BYTES,
)
from ._main import main
from ._parser import build_parser

__all__ = [
    "DEFAULT_MAX_INPUT_BYTES",
    "EXIT_CRYPTO_FAILURE",
    "EXIT_ERROR",
    "EXIT_KEY_EXISTS",
    "EXIT_OK",
    "EXIT_USAGE",
    "JSON_SCHEMA_VERSION",
    "MAX_PASSPHRASE_FILE_BYTES",
    "build_parser",
    "main",
]
