# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Drive the command-line interface from a script, using the JSON contract.

Automation should not parse human-readable output, which is not stable. With
``--json`` every command emits a versioned envelope -- ``schema_version``,
``status``, ``command``, ``tool``, then ``result`` or ``error`` -- specified
in ``docs/schemas/cli-output-v1.json``.

This example shows the three things a caller needs: reading a result,
handling a failure without matching on message text, and gating on a scan.

Run:
    python examples/09_automation_with_json.py
"""

from __future__ import annotations

import json
import subprocess
import sys

from _workspace import workspace

#: Invoking the module rather than the installed script, so the example works
#: from a source checkout without the entry point on PATH.
CLI = [sys.executable, "-m", "encryption_helper"]


def run(*arguments: str) -> tuple[int, dict]:
    """Run the CLI with --json and return the exit code and parsed document.

    The report moves to stderr whenever stdout is carrying the command's own
    data, so both streams are considered.
    """
    completed = subprocess.run(  # noqa: S603
        [*CLI, "--json", *arguments], capture_output=True, text=True, check=False
    )
    source = completed.stdout if completed.stdout.strip() else completed.stderr
    return completed.returncode, json.loads(source)


def main() -> int:
    """Generate a key, inspect a container, and gate on a scan."""
    directory = workspace()

    # --- Reading a result --------------------------------------------------
    code, document = run(
        "-q",
        "keygen",
        "--out-dir",
        str(directory),
        "--algorithm",
        "mlkem",
        "--no-passphrase",
    )
    if document["status"] != "ok":  # pragma: no cover - would be a defect
        msg = f"keygen failed: {document['error']}"
        raise AssertionError(msg)

    result = document["result"]
    print(f"schema version   {document['schema_version']}")
    print(f"command          {document['command']}")
    print(f"tool             {document['tool']['name']} {document['tool']['version']}")
    print(
        f"algorithm        {result['algorithm']} (post-quantum: "
        f"{result['post_quantum']})"
    )
    print(f"fingerprint      {result['fingerprint']}")
    print(f"exit code        {code}")
    print()

    # --- Handling a failure -----------------------------------------------
    # Branch on `error.code`, which is stable. `error.message` is written for
    # a person and may be reworded in any release.
    code, document = run("fingerprint", str(directory / "no-such-key.pem"))
    error = document["error"]
    print(f"failure code     {error['code']}   (branch on this)")
    print(f"failure message  {error['message']}")
    print(f"exit code        {code}")
    print()

    # --- Gating a pipeline -------------------------------------------------
    # `--fail-on-finding` makes a scan exit non-zero when anything needs
    # migrating or manual review, so it can stop a deployment.
    code, document = run("scan", "--fail-on-finding", str(directory))
    summary = document["result"]["summary"]
    print(f"scan examined    {summary['examined']}")
    print(f"needs attention  {summary['needs_attention']}")
    print(f"exit code        {code}  (0 because the key is post-quantum)")
    print()
    print("Gate on summary.needs_attention rather than action_required: an")
    print("encrypted private key reports action_required as false only")
    print("because its algorithm could not be read without the passphrase.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
