# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Logging setup, result emission, and usage failure -- the CLI's output side."""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import sys
from collections.abc import Iterator, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Any, Final, NoReturn

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


#: Same layout ``basicConfig`` produced, so log lines look as they always did.
_LOG_FORMAT: Final = "%(levelname)s %(name)s: %(message)s"


def _log_level(args: argparse.Namespace) -> int:
    """Map the parsed global flags to a log level."""
    if args.quiet:
        return logging.ERROR
    if args.log_level:
        level: int = getattr(logging, args.log_level)
        return level
    if args.verbose >= 2:  # noqa: PLR2004 - -vv means debug
        return logging.DEBUG
    if args.verbose == 1:
        return logging.INFO
    return logging.WARNING


@contextlib.contextmanager
def _logging_configured(args: argparse.Namespace) -> Iterator[None]:
    """Log to stderr at the requested level for one invocation, then undo it.

    This used ``logging.basicConfig``, which does nothing once the root
    logger has a handler: a host calling :func:`~._main.main` twice kept the
    first call's level, and a host with logging already set up never got
    the level asked for at all. A dedicated handler is added instead, and
    it and the root level are put back afterwards, so each call honours its
    own flags and the host's configuration is left as it was. The root
    logger is still process-wide, so concurrent calls from several threads
    share one level -- the last to start wins until it finishes.
    """
    root = logging.getLogger()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    previous = root.level
    root.addHandler(handler)
    root.setLevel(_log_level(args))
    try:
        yield
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)
        handler.close()


@dataclass(frozen=True)
class _OutputMode:
    """Whether JSON was requested, and for which command.

    Needed by a layer that has no access to the parsed arguments --
    :func:`_fail_usage` is called from deep inside argument validation, and
    :class:`JsonAwareParser` before there are any parsed arguments at all.
    """

    json: bool = False
    command: str | None = None


#: The mode of the invocation in progress. A context variable rather than a
#: module-level object, so it is scoped to one :func:`~._main.main` call:
#: :func:`output_mode` resets it on the way out, and a thread or task
#: running its own invocation sees its own value. Outside any call it is
#: the default -- plain text.
_mode: ContextVar[_OutputMode] = ContextVar(
    "encryption_helper_cli_output_mode",
    default=_OutputMode(),  # noqa: B039 - frozen, so it cannot be mutated
)


@contextlib.contextmanager
def output_mode(*, json: bool) -> Iterator[None]:
    """Scope the output mode to one invocation, starting from what is known.

    Before parsing, only ``--json`` is known (see :func:`json_requested`),
    and it is needed already, so an argument error is reported in the
    requested format. :func:`record_output_mode` refines it once parsing
    succeeds. Whatever was in effect before is restored on exit, however
    the invocation ends.
    """
    token = _mode.set(_OutputMode(json=json))
    try:
        yield
    finally:
        _mode.reset(token)


def record_output_mode(args: argparse.Namespace) -> None:
    """Record the parsed output mode so failures are reported in that format."""
    _mode.set(
        _OutputMode(
            json=bool(getattr(args, "json", False)),
            command=getattr(args, "command", None),
        )
    )


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


def json_requested(argv: Sequence[str]) -> bool:
    """Whether ``--json`` appears among the options, before any parsing.

    Parsing is what fails on a usage error, so the output mode it would
    have produced is not available when that error is reported. Scanning
    the raw arguments is the only way to honour ``--json`` there. Tokens
    after ``--`` are operands, not options, so they are not consulted.
    """
    for arg in argv:
        if arg == "--":
            return False
        if arg == "--json":
            return True
    return False


class JsonAwareParser(argparse.ArgumentParser):
    """An argument parser whose usage errors follow ``--json``.

    argparse prints its usage line and message as plain text and exits 2.
    Without ``--json`` that is kept exactly; with it, the same message is
    reported through :func:`emit_error` as the documented error document, so
    automation can branch on ``error.code`` for every failure rather than
    special-casing the ones argparse catches. Subparsers inherit the class,
    because ``add_subparsers`` defaults to the parent's type.
    """

    def error(self, message: str) -> NoReturn:
        """Report a parse failure, as JSON when that was requested."""
        if not _mode.get().json:
            super().error(message)
        # A subparser's prog is "<root> <command>"; naming the command lets
        # a consumer tell which invocation failed. The root parser has none.
        _mode.set(replace(_mode.get(), command=self.prog.partition(" ")[2] or None))
        _fail_usage(message)


def _write_json(document: dict[str, Any], stream: Any) -> None:
    """Write one JSON document, sorted so output is byte-stable."""
    print(json.dumps(document, indent=2, sort_keys=True), file=stream)


def _emit(args: argparse.Namespace, human: str, payload: dict[str, Any]) -> None:
    """Write a result as either human text or JSON.

    Reports normally go to stdout so they can be piped. The exception is when
    stdout is already carrying the command's data (``--out -``, or no
    ``--out`` at all, which means the same for every command that produces
    data): appending a report to ciphertext, plaintext, a signature or a
    key corrupts it, so the report moves to stderr and stdout stays pure.
    This applies to the human-readable line exactly as it does to JSON --
    ``encrypt > file.enc`` is the documented pipeline, and it must produce
    a decryptable file without ``-q``.
    """
    # A command without --out has no `output` at all; one with it holds
    # None (the default, stdout) or the value given.
    carries_data = "output" in vars(args) and args.output in {None, _STDIO}
    stream = sys.stderr if carries_data else sys.stdout
    if args.json:
        _write_json(
            envelope(getattr(args, "command", None), payload, status="ok"), stream
        )
    elif not args.quiet:
        print(human, file=stream)


def emit_error(message: str, exit_code: int) -> None:
    """Report a failure on stderr, as JSON when ``--json`` was requested.

    Always stderr, in both formats: a caller redirecting stdout to a file
    gets the data or nothing, never an error document mixed into it.
    """
    mode = _mode.get()
    if mode.json:
        _write_json(
            envelope(
                mode.command,
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
