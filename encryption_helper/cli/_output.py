# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Logging setup, result emission, and usage failure -- the CLI's output side."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, NoReturn

from ._constants import _STDIO, EXIT_USAGE

logger = logging.getLogger(__name__)


class _VersionAction(argparse.Action):
    """Print the version, resolved only when the flag is actually used.

    `action="version"` needs its string at parser-construction time, which
    would defeat the lazy metadata lookup for every other invocation.
    """

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        _namespace: argparse.Namespace,
        _values: object,
        _option_string: str | None = None,
    ) -> None:
        """Print and exit."""
        from .. import __version__  # noqa: PLC0415

        print(f"{parser.prog} {__version__}")
        parser.exit()


def _configure_logging(args: argparse.Namespace) -> None:
    """Set up logging for the process from the parsed global flags."""
    if args.quiet:
        level = logging.ERROR
    elif args.log_level:
        level = getattr(logging, args.log_level)
    elif args.verbose >= 2:  # noqa: PLR2004 - -vv means debug
        level = logging.DEBUG
    elif args.verbose == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _emit(args: argparse.Namespace, human: str, payload: dict[str, Any]) -> None:
    """Write a result as either human text or JSON.

    JSON normally goes to stdout so it can be piped. The exception is when
    stdout is already carrying the command's binary output (``--out -``):
    interleaving a JSON object with ciphertext leaves neither parseable, so
    the report moves to stderr and stdout stays pure.
    """
    if args.json:
        stream = sys.stderr if getattr(args, "output", None) == _STDIO else sys.stdout
        print(json.dumps(payload, indent=2, sort_keys=True), file=stream)
    elif not args.quiet:
        print(human)


def _fail_usage(message: str) -> NoReturn:
    """Print a usage error to stderr and exit with :data:`EXIT_USAGE`."""
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(EXIT_USAGE)
