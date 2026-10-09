# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Talk to the read-only MCP server the way an AI assistant would.

``encryption-helper-mcp`` lets an assistant help scope a post-quantum
migration: which keys and certificates are affected, by when, and what
replaces them. It speaks JSON-RPC 2.0 over standard input and output, so this
example starts it as a subprocess and sends the same messages an MCP client
sends.

It also demonstrates the server's boundary. No tool generates, decrypts or
signs anything, and none accepts a passphrase, because an assistant's context
leaves the operator's machine. Paths outside ``--root`` are refused.

Run (from a source checkout, or with ``encryption-helper-mcp`` installed):
    python examples/11_mcp_assistant_session.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from _workspace import workspace
from encryption_helper import encode_public_key, generate_mlkem, generate_rsa

#: Where the server package lives in a source checkout.
_SOURCE_PACKAGE = (
    Path(__file__).resolve().parents[1] / "packages" / ("encryption-helper-mcp")
)


def server_environment() -> dict[str, str]:
    """Return an environment in which ``encryption_helper_mcp`` imports.

    Uses the installed package where there is one, and the source checkout
    otherwise. Fails loudly if neither exists: an example that skips itself
    silently would hide a broken install.
    """
    env = dict(os.environ)
    if importlib.util.find_spec("encryption_helper_mcp") is not None:
        return env
    if _SOURCE_PACKAGE.is_dir():
        env["PYTHONPATH"] = os.pathsep.join(
            filter(None, [str(_SOURCE_PACKAGE), env.get("PYTHONPATH")])
        )
        return env
    msg = "encryption-helper-mcp is not installed: pip install encryption-helper-mcp"
    raise SystemExit(msg)


def session(root: Path, messages: list[dict[str, Any]]) -> dict[Any, Any]:
    """Send ``messages`` to a fresh server and return responses keyed by id."""
    stdin = "".join(json.dumps(message) + "\n" for message in messages)
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "encryption_helper_mcp", "--root", str(root)],
        input=stdin,
        capture_output=True,
        text=True,
        env=server_environment(),
        check=True,
        timeout=60,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line]
    return {response["id"]: response for response in responses}


def call(request_id: int, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Build a ``tools/call`` request."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def main() -> int:
    """List the tools, scan a directory, and probe the boundary."""
    root = workspace()
    # Material of the kind a migration scoping exercise turns up.
    (root / "legacy-partner.pub.pem").write_bytes(
        encode_public_key(generate_rsa(key_size=2048).public_key())
    )
    (root / "new-partner.pub.pem").write_bytes(
        encode_public_key(generate_mlkem(level=768).public_key())
    )

    responses = session(
        root,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "example", "version": "0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            call(3, "scan_directory", {}),
            call(4, "assess_algorithm", {"algorithm": "rsa", "key_size": 2048}),
            call(5, "scan_directory", {"path": "../../etc"}),
        ],
    )

    server = responses[1]["result"]["serverInfo"]
    print(f"connected to {server['name']} {server['version']}")

    tools = [tool["name"] for tool in responses[2]["result"]["tools"]]
    print(f"tools offered: {', '.join(tools)}")
    for verb in ("generate", "encrypt", "decrypt", "sign"):
        if any(verb in name for name in tools):  # pragma: no cover - boundary
            msg = f"a tool can {verb}; the server must be read-only"
            raise AssertionError(msg)
    print("no tool can generate, encrypt, decrypt or sign")

    scan = responses[3]["result"]["structuredContent"]
    print()
    print(
        f"scan: {scan['summary']['examined']} examined, "
        f"{scan['summary']['needs_attention']} needing attention"
    )
    for finding in scan["findings"]:
        action = ", ".join(finding["replacements"]) or "none"
        print(
            f"  {Path(finding['path']).name:<24} {finding['algorithm']:<6} "
            f"migrate to: {action}"
        )

    posture = responses[4]["result"]["structuredContent"]
    print()
    print(f"assess rsa-2048: {posture['rationale']}")

    refused = responses[5]["result"]
    print()
    print(f"path outside the root refused: {refused['isError']}")
    if not refused["isError"]:  # pragma: no cover - boundary
        msg = "the server read outside its root"
        raise AssertionError(msg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
