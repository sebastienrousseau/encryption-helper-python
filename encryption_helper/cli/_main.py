# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Process entry point: parse, dispatch, map errors to exit codes.

Exit codes (the package docstring of :mod:`encryption_helper.cli` holds
the full table, and :mod:`._constants` the values):

* 0 success; 1 error; 2 usage; 3 destination exists; 4 decryption or
  verification failed; 5 ``scan --fail-on-finding`` found something;
* 141 (:data:`~._constants.EXIT_BROKEN_PIPE`) -- stdout was closed by its
  reader before the output was complete, following the shell's 128 +
  SIGPIPE convention so a pipeline using ``pipefail`` notices.
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import sys
import threading
from collections.abc import Iterator, Sequence
from types import FrameType

from ..errors import (
    DecryptionError,
    EncryptionHelperError,
    KeyExistsError,
    SignatureVerificationError,
)
from ._constants import (
    EXIT_BROKEN_PIPE,
    EXIT_CRYPTO_FAILURE,
    EXIT_ERROR,
    EXIT_KEY_EXISTS,
)
from ._output import (
    _configure_logging,
    begin_output_mode,
    emit_error,
    json_requested,
    record_output_mode,
)
from ._parser import build_parser

logger = logging.getLogger(__name__)


def _terminate(signum: int, _frame: FrameType | None) -> None:
    """Turn SIGTERM into an exception, so cleanup code actually runs.

    The default disposition kills the process outright, skipping every
    ``finally`` and ``except`` block -- so a `decrypt --out file` stopped by
    a container runtime or `kill` left its hidden temporary file, holding
    partial plaintext, in the destination directory for good. Raising
    instead unwinds through the writers, which remove it.
    """
    raise SystemExit(128 + signum)


@contextlib.contextmanager
def _sigterm_unwinds() -> Iterator[None]:
    """Install :func:`_terminate` for the duration of one command.

    Only from the main thread, where Python permits it, and the previous
    handler is restored afterwards, so embedding :func:`main` in a host
    process does not leave that process's signal handling changed.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.signal(signal.SIGTERM, _terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _describe_os_error(exc: OSError) -> str:
    """Say what the operating system refused, and where, in one line."""
    reason = exc.strerror or type(exc).__name__
    if exc.filename is not None:
        return f"{reason}: {exc.filename}"
    return reason


def _classify(exc: Exception) -> tuple[str, int]:
    """Map a failure to the message the user sees and the exit code.

    Every branch is a promise about what the user is told:

    * this library's own errors carry messages written for the user;
    * an OSError -- a full disk, a read-only directory, a missing
      permission -- is the environment, not a bug, and was reported as
      "unexpected internal error ... please report this" with a traceback;
    * anything else may quote a path or value the user never meant to
      surface, so it gets a fixed message, and the traceback is logged at
      DEBUG only. (``logger.exception`` logs at ERROR, which is shown by
      default, so it used to print the traceback on every run.)
    """
    if isinstance(exc, KeyExistsError):
        return str(exc), EXIT_KEY_EXISTS
    if isinstance(exc, DecryptionError | SignatureVerificationError):
        return str(exc), EXIT_CRYPTO_FAILURE
    if isinstance(exc, EncryptionHelperError):
        return str(exc), EXIT_ERROR
    if isinstance(exc, OSError):
        logger.debug("Operating system error", exc_info=exc)
        return _describe_os_error(exc), EXIT_ERROR
    logger.debug("Unexpected internal error", exc_info=exc)
    return (
        "unexpected internal error. Re-run with --log-level DEBUG for "
        "details, and please report this.",
        EXIT_ERROR,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv` when omitted.

    Returns:
        A process exit code. See the module docstring for their meanings.
    """
    arguments = sys.argv[1:] if argv is None else list(argv)
    # Known before parsing, so a usage error argparse raises is reported in
    # the requested format too; see JsonAwareParser.
    begin_output_mode(json=json_requested(arguments))
    parser = build_parser()
    args = parser.parse_args(arguments)
    record_output_mode(args)
    _configure_logging(args)

    try:
        with _sigterm_unwinds():
            result: int = args.func(args)
    except BrokenPipeError:  # pragma: no cover - runs in a subprocess under test
        # A downstream `head` closing the pipe is not this tool failing, so
        # nothing is printed -- but the output *was* cut short, and exiting
        # 0 told `set -o pipefail` that a truncated plaintext was complete.
        # os._exit skips the interpreter's final flush of stdout, which
        # would hit the same closed pipe and print "Exception ignored".
        os._exit(EXIT_BROKEN_PIPE)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        emit_error("interrupted", EXIT_ERROR)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - every failure gets an exit code
        message, code = _classify(exc)
        emit_error(message, code)
        return code
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
