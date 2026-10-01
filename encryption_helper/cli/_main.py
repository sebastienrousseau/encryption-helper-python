# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Process entry point: parse, dispatch, map errors to exit codes."""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Sequence

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
from ._output import _configure_logging
from ._parser import build_parser

logger = logging.getLogger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv` when omitted.

    Returns:
        A process exit code. See the module docstring for their meanings.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args)

    try:
        result: int = args.func(args)
    except KeyExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_KEY_EXISTS
    except (DecryptionError, SignatureVerificationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CRYPTO_FAILURE
    except EncryptionHelperError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - depends on the consumer
        # A downstream `head` closing the pipe is not an error.
        os._exit(EXIT_OK)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception:
        # An unexpected exception's text may quote a path, an argument, or a
        # value the user never meant to surface. Print a fixed message and
        # send the detail to the log, which the operator controls.
        logger.exception("Unexpected internal error")
        print(
            "error: unexpected internal error. Re-run with --log-level DEBUG "
            "for details, and please report this.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
