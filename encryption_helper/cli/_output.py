# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Logging setup, result emission, and usage failure -- the CLI's output side."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from typing import Any, NoReturn

from ._constants import (
    _STDIO,
    ERROR_CODES,
    EXIT_USAGE,
    JSON_SCHEMA_VERSION,
)

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


@dataclass
class _OutputMode:
    """Whether JSON was requested, and for which command.

    Held at module level because a failure can be reported from a layer that
    has no access to the parsed arguments -- :func:`_fail_usage` is called
    from deep inside argument validation. :func:`record_output_mode` sets it
    once, immediately after parsing.
    """

    json: bool = False
    command: str | None = None


_mode = _OutputMode()


def record_output_mode(args: argparse.Namespace) -> None:
    """Record the output mode so failures can be reported in the same format.

    Both fields are always assigned, so a previous invocation in the same
    process cannot leave the mode set.
    """
    _mode.json = bool(getattr(args, "json", False))
    _mode.command = getattr(args, "command", None)


def runtime_version() -> str:
    """Return the installed distribution version, or a placeholder.

    Read from installed metadata rather than imported, so emitting a result
    does not pull in the package's own ``__init__``.
    """
    from importlib.metadata import PackageNotFoundError, version  # noqa: PLC0415

    try:
        return version("encryption-helper")
    except PackageNotFoundError:  # pragma: no cover - only when not installed
        return "unknown"


def envelope(
    command: str | None, body: dict[str, Any], *, status: str
) -> dict[str, Any]:
    """Wrap a result or an error in the versioned output contract.

    The envelope exists so a consumer can tell success from failure, and one
    command's output from another's, without inspecting which fields happen
    to be present. ``schema_version`` lets it detect a breaking change rather
    than misread one.
    """
    document: dict[str, Any] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "status": status,
        "command": command,
        "tool": {"name": "encryption-helper", "version": runtime_version()},
    }
    document["result" if status == "ok" else "error"] = body
    return document


def _write_json(document: dict[str, Any], stream: Any) -> None:
    """Write one JSON document, sorted so output is byte-stable."""
    print(json.dumps(document, indent=2, sort_keys=True), file=stream)


def _emit(args: argparse.Namespace, human: str, payload: dict[str, Any]) -> None:
    """Write a result as either human text or JSON.

    JSON normally goes to stdout so it can be piped. The exception is when
    stdout is already carrying the command's binary output (``--out -``):
    interleaving a JSON object with ciphertext leaves neither parseable, so
    the report moves to stderr and stdout stays pure.
    """
    if args.json:
        stream = sys.stderr if getattr(args, "output", None) == _STDIO else sys.stdout
        _write_json(
            envelope(getattr(args, "command", None), payload, status="ok"), stream
        )
    elif not args.quiet:
        print(human)


def emit_error(message: str, exit_code: int) -> None:
    """Report a failure on stderr, as JSON when ``--json`` was requested.

    Always stderr, in both formats: a caller redirecting stdout to a file
    gets the data or nothing, never an error document mixed into it.
    """
    if _mode.json:
        _write_json(
            envelope(
                _mode.command,
                {
                    "code": ERROR_CODES.get(exit_code, "error"),
                    "message": message,
                    "exit_code": exit_code,
                },
                status="error",
            ),
            sys.stderr,
        )
    else:
        print(f"error: {message}", file=sys.stderr)


def _fail_usage(message: str) -> NoReturn:
    """Report a usage error and exit with :data:`EXIT_USAGE`."""
    emit_error(message, EXIT_USAGE)
    raise SystemExit(EXIT_USAGE)
