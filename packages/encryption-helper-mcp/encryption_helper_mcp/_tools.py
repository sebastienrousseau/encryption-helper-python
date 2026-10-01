# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""The tools this server exposes, and the boundary around them.

Every tool here answers a question. None of them performs an action, holds a
secret, or writes to disk. That is the whole design: an assistant asking
"which of these keys needs migrating" is a reasonable thing to automate,
whereas routing a private key through a model's context window is not, since
that context is transmitted to a third party, logged, and retained.

Two properties are enforced rather than documented:

* **Read-only by construction.** This module imports the assessment and
  inspection functions and nothing else. It cannot generate, encrypt,
  decrypt, sign or write a key, because those names are not in scope.
  ``test_boundary.py`` asserts that, so adding such an import fails the
  build rather than quietly widening the server.
* **Path confinement.** Every filesystem argument is resolved and checked to
  be inside the configured root. Resolution happens before the check, so a
  symbolic link inside the root that points outside it is rejected rather
  than followed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from encryption_helper.crypto.metadata import HEADER_SIZE, describe_container
from encryption_helper.errors import EncryptionHelperError
from encryption_helper.inventory import scan, summarise
from encryption_helper.keys import fingerprint_sha256, load_public_key_file
from encryption_helper.policy import assess, horizon, inventory

__all__ = ["TOOLS", "Tool", "ToolError", "call", "descriptors"]


class ToolError(Exception):
    """A tool was called with arguments it cannot act on.

    Distinct from an internal failure: the message is intended to be shown to
    the caller so it can correct the request.
    """


@dataclass(frozen=True)
class Tool:
    """One callable question.

    Attributes:
        name: Identifier the client calls.
        description: What the tool answers. Written for a model deciding
            whether to call it, so it states the limits as well as the use.
        schema: JSON Schema for the arguments.
        handler: Implementation, taking the resolved root and the arguments.
    """

    name: str
    description: str
    schema: dict[str, Any]
    handler: Callable[[Path, dict[str, Any]], dict[str, Any]]


def _resolve_within(root: Path, candidate: str) -> Path:
    """Resolve ``candidate`` and confirm it lies inside ``root``.

    Resolution is deliberate and happens first: a symbolic link inside the
    root pointing at ``/etc`` resolves outside the root and is then rejected,
    whereas checking the unresolved path would have admitted it.

    Args:
        root: Directory the server is confined to.
        candidate: Path from the request, absolute or relative to the root.

    Returns:
        The resolved path.

    Raises:
        ToolError: If the path escapes the root, or does not exist.
    """
    if not candidate:
        msg = "A path is required."
        raise ToolError(msg)
    requested = Path(candidate).expanduser()
    base = requested if requested.is_absolute() else root / requested
    try:
        target = base.resolve(strict=True)
    except OSError as exc:
        msg = f"{candidate}: {exc.strerror or 'cannot be read'}."
        raise ToolError(msg) from exc
    if target != root and root not in target.parents:
        msg = (
            f"{candidate} resolves outside the permitted root {root}. "
            "This server only reads inside the directory it was started with; "
            "restart it with --root to widen that."
        )
        raise ToolError(msg)
    return target


def _pq_horizon(_root: Path, _arguments: dict[str, Any]) -> dict[str, Any]:
    """Return the migration timetable and the publications behind it."""
    return horizon()


def _assess_algorithm(_root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    """Assess one algorithm choice against the timetable."""
    algorithm = arguments.get("algorithm")
    if not isinstance(algorithm, str):
        msg = "argument 'algorithm' is required and must be a string."
        raise ToolError(msg)
    key_size = arguments.get("key_size")
    if key_size is not None and not isinstance(key_size, int):
        msg = "argument 'key_size' must be an integer when given."
        raise ToolError(msg)
    purpose = arguments.get("purpose")
    if purpose is not None and purpose not in {"encrypt", "sign"}:
        msg = "argument 'purpose' must be 'encrypt' or 'sign' when given."
        raise ToolError(msg)
    try:
        posture = assess(algorithm, key_size=key_size, purpose=purpose)
    except EncryptionHelperError as exc:
        raise ToolError(str(exc)) from exc
    return posture.as_dict()


def _algorithm_inventory(_root: Path, _arguments: dict[str, Any]) -> dict[str, Any]:
    """Return the posture of every algorithm this library supports."""
    return {"algorithms": inventory(), "horizon": horizon()}


def _inspect_container(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    """Describe an encrypted file from its header."""
    path = _resolve_within(root, str(arguments.get("path", "")))
    try:
        with path.open("rb") as handle:
            header = handle.read(HEADER_SIZE)
    except OSError as exc:
        msg = f"{path}: {exc.strerror or 'cannot be read'}."
        raise ToolError(msg) from exc
    try:
        info = describe_container(header)
    except EncryptionHelperError as exc:
        raise ToolError(str(exc)) from exc
    return {"path": str(path), **info.as_dict()}


def _scan_directory(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    """Inventory cryptographic material under a path."""
    path = _resolve_within(root, str(arguments.get("path", ".")))
    findings = scan([path])
    return {
        "root": str(path),
        "summary": summarise(findings),
        "findings": [finding.as_dict() for finding in findings],
        "horizon": horizon(),
    }


def _fingerprint_public_key(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    """Return the fingerprint of a public key file."""
    path = _resolve_within(root, str(arguments.get("path", "")))
    try:
        key = load_public_key_file(path)
    except EncryptionHelperError as exc:
        raise ToolError(str(exc)) from exc
    return {"path": str(path), "fingerprint": fingerprint_sha256(key)}


_PATH_SCHEMA: Final = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": (
                "Path to read, relative to the server's root or absolute "
                "within it. Paths outside the root are refused."
            ),
        }
    },
    "required": ["path"],
    "additionalProperties": False,
}

TOOLS: Final = (
    Tool(
        name="pq_horizon",
        description=(
            "Return the post-quantum migration timetable: the years from "
            "which NIST IR 8547 deprecates and then disallows classical "
            "public-key algorithms, the publications those dates come from, "
            "and the validation note that must accompany any report quoting "
            "them. Takes no arguments and reads nothing from disk."
        ),
        schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_pq_horizon,
    ),
    Tool(
        name="assess_algorithm",
        description=(
            "Report whether one algorithm choice is vulnerable to a quantum "
            "computer, when it stops being acceptable, and what to migrate "
            "to. Supply key_size for RSA, where the judgement depends on the "
            "modulus. Supply purpose ('encrypt' or 'sign') for RSA, which can "
            "do both and therefore has two possible successors. Reads nothing "
            "from disk."
        ),
        schema={
            "type": "object",
            "properties": {
                "algorithm": {
                    "type": "string",
                    "description": (
                        "One of rsa, ecdsa, ed25519, ed448, x25519, mlkem, mldsa."
                    ),
                },
                "key_size": {
                    "type": "integer",
                    "description": "RSA modulus in bits, or parameter set.",
                },
                "purpose": {
                    "enum": ["encrypt", "sign"],
                    "description": "What the key is used for, where known.",
                },
            },
            "required": ["algorithm"],
            "additionalProperties": False,
        },
        handler=_assess_algorithm,
    ),
    Tool(
        name="algorithm_inventory",
        description=(
            "Return the full table of supported algorithms with each one's "
            "quantum status, deadlines, permitted purposes and successor. Use "
            "this to answer a question about several algorithms in one call "
            "rather than calling assess_algorithm repeatedly. Reads nothing "
            "from disk."
        ),
        schema={"type": "object", "properties": {}, "additionalProperties": False},
        handler=_algorithm_inventory,
    ),
    Tool(
        name="inspect_container",
        description=(
            "Report which algorithms protect an encrypted file, reading only "
            "its 10-byte header. No private key is required or accepted, and "
            "no plaintext is recovered, so this can be used on data the "
            "caller is not entitled to read."
        ),
        schema=_PATH_SCHEMA,
        handler=_inspect_container,
    ),
    Tool(
        name="scan_directory",
        description=(
            "Inventory the keys, certificates and encrypted files under a "
            "path and report which use algorithms that stop being acceptable, "
            "with a summary. Classification is by file contents, not by "
            "filename. Symbolic links are not followed and no passphrase is "
            "requested, so an encrypted private key is reported as needing "
            "manual review rather than being unlocked. Gate on "
            "summary.needs_attention rather than summary.action_required."
        ),
        schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Directory or file to examine, relative to the "
                        "server's root. Defaults to the root itself."
                    ),
                }
            },
            "additionalProperties": False,
        },
        handler=_scan_directory,
    ),
    Tool(
        name="fingerprint_public_key",
        description=(
            "Return the SHA-256 fingerprint of a public key file, for "
            "confirming that two parties hold the same key. Public keys only; "
            "this cannot read a private key."
        ),
        schema=_PATH_SCHEMA,
        handler=_fingerprint_public_key,
    ),
)

_BY_NAME: Final = {tool.name: tool for tool in TOOLS}


def descriptors() -> list[dict[str, Any]]:
    """Return the tool list in the shape ``tools/list`` expects."""
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.schema,
        }
        for tool in TOOLS
    ]


def call(root: Path, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a tool call.

    Args:
        root: Directory the server is confined to.
        name: Tool name.
        arguments: Arguments from the request.

    Returns:
        The tool's result, as a JSON-serialisable mapping.

    Raises:
        ToolError: If the tool is unknown, or its arguments are unusable.
    """
    tool = _BY_NAME.get(name)
    if tool is None:
        known = ", ".join(sorted(_BY_NAME))
        msg = f"Unknown tool {name!r}. Available tools: {known}."
        raise ToolError(msg)
    return tool.handler(root, arguments)


def default_root() -> Path:
    """Return the root to use when none was given: the current directory."""
    return Path.cwd().resolve()
