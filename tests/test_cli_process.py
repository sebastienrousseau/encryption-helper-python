# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""How :func:`main` behaves as a process: pipes, re-entry, and imports.

These are properties of the entry point rather than of any one command. A
truncated pipeline must not report success, a second in-process call must
not inherit the first call's flags, and building the parser must not drag
in every command's dependencies.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
from encryption_helper.cli import EXIT_BROKEN_PIPE, EXIT_OK, main

posix_pipes = pytest.mark.skipif(
    sys.platform == "win32",
    reason="SIGPIPE and the 128+N exit convention are POSIX",
)


@posix_pipes
class TestTruncatedPipeline:
    """``decrypt big | head -c 10`` lost data; it must not exit 0."""

    def test_a_reader_closing_early_is_reported_as_sigpipe(self, tmp_path):
        assert (
            main(
                [
                    "-q",
                    "keygen",
                    "--algorithm",
                    "x25519",
                    "--out-dir",
                    str(tmp_path),
                    "--no-passphrase",
                ]
            )
            == EXIT_OK
        )
        source = tmp_path / "big.bin"
        # Far larger than any pipe buffer, so the writer is still writing
        # when the reader goes away.
        source.write_bytes(b"\0" * (8 * 1024 * 1024))
        container = tmp_path / "big.enc"
        assert (
            main(
                [
                    "-q",
                    "encrypt",
                    "--public-key",
                    str(tmp_path / "key.pub.pem"),
                    "--in",
                    str(source),
                    "--out",
                    str(container),
                ]
            )
            == EXIT_OK
        )

        process = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "encryption_helper",
                "decrypt",
                "--private-key",
                str(tmp_path / "key.pem"),
                "--in",
                str(container),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        assert len(process.stdout.read(10)) == 10
        process.stdout.close()
        stderr = process.stderr.read()
        process.stderr.close()
        assert process.wait(timeout=60) == EXIT_BROKEN_PIPE == 141
        # Quiet, as before: no traceback, no "Exception ignored" noise.
        assert stderr == b""
