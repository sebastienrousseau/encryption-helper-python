# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Process entry point: parse, dispatch, map errors to exit codes."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
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
    EXIT_CRYPTO_FAILURE,
    EXIT_ERROR,
    EXIT_KEY_EXISTS,
    EXIT_OK,
)
from ._output import (
    _configure_logging,
    emit_error,
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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv` when omitted.

    Returns:
        A process exit code. See the module docstring for their meanings.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    record_output_mode(args)
    _configure_logging(args)

    try:
        with _sigterm_unwinds():
            result: int = args.func(args)
    except KeyExistsError as exc:
        emit_error(str(exc), EXIT_KEY_EXISTS)
        return EXIT_KEY_EXISTS
    except (DecryptionError, SignatureVerificationError) as exc:
        emit_error(str(exc), EXIT_CRYPTO_FAILURE)
        return EXIT_CRYPTO_FAILURE
    except EncryptionHelperError as exc:
        emit_error(str(exc), EXIT_ERROR)
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - depends on the consumer
        # A downstream `head` closing the pipe is not an error.
        os._exit(EXIT_OK)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        emit_error("interrupted", EXIT_ERROR)
        return EXIT_ERROR
    except Exception:
        # An unexpected exception's text may quote a path, an argument, or a
        # value the user never meant to surface. Print a fixed message and
        # send the detail to the log, which the operator controls.
        logger.exception("Unexpected internal error")
        emit_error(
            "unexpected internal error. Re-run with --log-level DEBUG for "
            "details, and please report this.",
            EXIT_ERROR,
        )
        return EXIT_ERROR
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
