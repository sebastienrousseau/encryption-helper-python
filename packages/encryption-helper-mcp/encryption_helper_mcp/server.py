# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""A Model Context Protocol server over stdio, with no dependencies.

The protocol is JSON-RPC 2.0 carried as newline-delimited JSON on standard
input and output. It is implemented here directly rather than through an SDK,
for two reasons that matter more than convenience: the method set this server
needs is small enough to read in one sitting, and a tool whose purpose is
handling key material should not acquire a dependency tree in order to answer
questions about it. The only import outside the standard library is
``encryption_helper`` itself.

Standard output carries protocol messages only. Diagnostics go to standard
error, because a log line written to standard output would be parsed as a
malformed message and end the session.

Supported methods
-----------------

``initialize``, ``notifications/initialized``, ``ping``, ``tools/list`` and
``tools/call``. Anything else receives a ``method not found`` error, which is
the correct response rather than a silent success.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import IO, Any, Final, cast

from . import __version__
from ._tools import ToolError, call, default_root, descriptors

__all__ = ["main", "serve"]

logger = logging.getLogger(__name__)

#: Protocol revision this server implements. Reported during initialisation
#: so a client can decline rather than guess.
PROTOCOL_VERSION: Final = "2025-06-18"

#: JSON-RPC 2.0 error codes, from the specification.
PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603

#: Largest single message accepted. A malformed or hostile client could
#: otherwise stream an unbounded line and exhaust memory before any parse is
#: attempted.
MAX_MESSAGE_BYTES: Final = 4 * 1024 * 1024


def _result(request_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    """Build a successful JSON-RPC response."""
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    """Build a JSON-RPC error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap a tool's output in the content shape ``tools/call`` returns.

    The payload is sent as formatted JSON text. ``structuredContent``
    carries the same data in machine-readable form for clients that support
    it; the text block is what a client without that support displays.
    """
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "structuredContent": payload,
        "isError": False,
    }


def _tool_failure(message: str) -> dict[str, Any]:
    """Report a tool failure as a result rather than a protocol error.

    A bad argument is the model's mistake to correct, not a transport fault.
    Returning it as ``isError`` lets the client show it and retry, whereas a
    JSON-RPC error would surface as a broken connection.
    """
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _handle_initialize(_root: Path, _params: dict[str, Any]) -> dict[str, Any]:
    """Report the protocol revision and what this server offers."""
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "encryption-helper-mcp", "version": __version__},
        "instructions": (
            "Read-only tools for assessing cryptographic material against the "
            "NIST IR 8547 post-quantum migration timetable. This server "
            "cannot generate, encrypt, decrypt, sign, or write anything, and "
            "it never accepts a passphrase or reads a private key. Where an "
            "operation is needed rather than an answer, use the "
            "encryption-helper command-line tool directly so that key "
            "material stays on the operator's machine."
        ),
    }


def _handle_tools_list(_root: Path, _params: dict[str, Any]) -> dict[str, Any]:
    """List the available tools."""
    return {"tools": descriptors()}


def _handle_tools_call(root: Path, params: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a tool call and wrap the outcome."""
    name = params.get("name")
    if not isinstance(name, str):
        msg = "'name' is required and must be a string."
        raise ToolError(msg)
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        msg = "'arguments' must be an object when given."
        raise ToolError(msg)
    try:
        return _tool_result(call(root, name, arguments))
    except ToolError as exc:
        return _tool_failure(str(exc))


def _handle_ping(_root: Path, _params: dict[str, Any]) -> dict[str, Any]:
    """Answer a liveness check."""
    return {}


_METHODS: Final = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
    "ping": _handle_ping,
}

#: Notifications carry no ``id`` and must not be answered.
_IGNORED_NOTIFICATIONS: Final = frozenset(
    {"notifications/initialized", "notifications/cancelled"}
)


def _reject_malformed(message: object) -> dict[str, Any] | None:
    """Return an error response if ``message`` is not a usable request.

    Kept apart from :func:`dispatch` so that validating a message's shape and
    routing it are separate concerns.
    """
    if not isinstance(message, dict):
        return _error(None, INVALID_REQUEST, "A message must be a JSON object.")
    if not isinstance(message.get("method"), str):
        return _error(message.get("id"), INVALID_REQUEST, "'method' is required.")
    params = message.get("params")
    if params is not None and not isinstance(params, dict):
        return _error(message.get("id"), INVALID_PARAMS, "'params' must be an object.")
    return None


def dispatch(root: Path, message: object) -> dict[str, Any] | None:
    """Handle one parsed message.

    Args:
        root: Directory the server is confined to.
        message: The decoded JSON-RPC message.

    Returns:
        The response to write, or :data:`None` where the message was a
        notification and the protocol forbids a reply.
    """
    invalid = _reject_malformed(message)
    if invalid is not None:
        return invalid
    # _reject_malformed has established the shape; mypy cannot see through it.
    request = cast("dict[str, Any]", message)

    method: str = request["method"]
    request_id = request.get("id")

    if request_id is None:
        # A notification. Unknown ones are ignored rather than answered,
        # because replying to a notification is itself a protocol violation.
        if method not in _IGNORED_NOTIFICATIONS:
            logger.debug("ignoring unknown notification %s", method)
        return None

    handler = _METHODS.get(method)
    if handler is None:
        return _error(request_id, METHOD_NOT_FOUND, f"Unknown method {method!r}.")

    try:
        return _result(request_id, handler(root, request.get("params") or {}))
    except ToolError as exc:
        return _error(request_id, INVALID_PARAMS, str(exc))
    except Exception:
        # The text of an unexpected exception may quote a path or a value the
        # operator never meant to expose to a model. Log the detail locally
        # and return a fixed message.
        logger.exception("unhandled error in %s", method)
        return _error(request_id, INTERNAL_ERROR, "Internal error.")


def serve(
    root: Path, source: IO[str] | None = None, sink: IO[str] | None = None
) -> int:
    """Read messages until the input closes, writing each response.

    Args:
        root: Directory the server is confined to.
        source: Message source, defaulting to standard input.
        sink: Response destination, defaulting to standard output.

    Returns:
        A process exit code.
    """
    source = source if source is not None else sys.stdin
    sink = sink if sink is not None else sys.stdout

    for line in source:
        response: dict[str, Any] | None
        if len(line) > MAX_MESSAGE_BYTES:
            response = _error(None, INVALID_REQUEST, "Message too large.")
        elif not line.strip():
            continue
        else:
            try:
                response = dispatch(root, json.loads(line))
            except json.JSONDecodeError as exc:
                response = _error(None, PARSE_ERROR, f"Invalid JSON: {exc.msg}.")
        if response is None:
            continue
        sink.write(json.dumps(response) + "\n")
        sink.flush()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="encryption-helper-mcp",
        description=(
            "Read-only Model Context Protocol server for assessing "
            "cryptographic material. Speaks JSON-RPC 2.0 over stdio."
        ),
        epilog=(
            "This server answers questions. It cannot generate, encrypt, "
            "decrypt or sign, and it never reads a private key or accepts a "
            "passphrase. Use the encryption-helper command directly for "
            "operations on key material."
        ),
    )
    parser.add_argument(
        "--root",
        metavar="DIR",
        help=(
            "Directory the server may read within. Paths outside it are "
            "refused, including by way of a symbolic link. Defaults to the "
            "working directory."
        ),
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="WARNING",
        help="Diagnostic verbosity on stderr (default: WARNING).",
    )
    parser.add_argument(
        "--version", action="version", version=f"encryption-helper-mcp {__version__}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the server.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv`.

    Returns:
        A process exit code.
    """
    args = build_parser().parse_args(argv)
    # Diagnostics must never reach stdout: a log line there would be read as
    # a malformed protocol message.
    logging.basicConfig(
        level=getattr(logging, args.log_level), stream=sys.stderr, format="%(message)s"
    )

    root = Path(args.root).expanduser().resolve() if args.root else default_root()
    if not root.is_dir():
        # Written directly rather than logged: nothing is listening yet,
        # and stdout must carry protocol messages only.
        sys.stderr.write(f"error: {root} is not a directory\n")
        return 2

    logger.info("serving read-only tools, confined to %s", root)
    try:
        return serve(root)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
