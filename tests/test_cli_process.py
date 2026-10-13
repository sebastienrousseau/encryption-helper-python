# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""How :func:`main` behaves as a process: pipes, re-entry, and imports.

These are properties of the entry point rather than of any one command. A
truncated pipeline must not report success, a second in-process call must
not inherit the first call's flags, and building the parser must not drag
in every command's dependencies.
"""

from __future__ import annotations

import logging
import subprocess
import sys

import pytest
from encryption_helper.cli import EXIT_BROKEN_PIPE, EXIT_OK, main

from ._support import envelope

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


class TestRepeatedInProcessCalls:
    """Each :func:`main` call honours its own flags and leaves nothing behind.

    The output mode was a module-level object and logging was configured
    with ``basicConfig``, which does nothing once the root logger has a
    handler -- so a host calling ``main`` twice kept the first call's log
    level, and the JSON mode outlived the call that asked for it.
    """

    @pytest.fixture
    def probe(self, monkeypatch):
        """Record the effective log level while a command runs."""
        from encryption_helper.cli import _commands

        seen: list[int] = []
        real = _commands._capabilities

        def capabilities():
            seen.append(logging.getLogger("encryption_helper").getEffectiveLevel())
            logging.getLogger("encryption_helper.probe").debug("probe-debug")
            return real()

        monkeypatch.setattr(_commands, "_capabilities", capabilities)
        return seen

    def test_each_call_gets_its_own_log_level(self, probe, capsys):
        assert main(["-vv", "capabilities"]) == EXIT_OK
        first = capsys.readouterr().err
        assert main(["capabilities"]) == EXIT_OK
        second = capsys.readouterr().err
        assert probe == [logging.DEBUG, logging.WARNING]
        assert "DEBUG encryption_helper.probe: probe-debug" in first
        assert "probe-debug" not in second

    def test_logging_is_restored_after_the_call(self, probe):
        root = logging.getLogger()
        package = logging.getLogger("encryption_helper")

        def state():
            return (
                root.level,
                list(root.handlers),
                package.level,
                list(package.handlers),
                package.propagate,
            )

        before = state()
        assert main(["-vv", "capabilities"]) == EXIT_OK
        assert state() == before

    def test_a_host_with_logging_configured_sees_each_record_once(self, probe, capsys):
        """The CLI's handler and the host's must not both print a record.

        Adding a handler to the root logger, beside one the host had already
        installed, printed every record twice. The CLI now configures only
        the package's own logger, and stops propagation while it runs.
        """
        records: list[logging.LogRecord] = []

        class Host(logging.Handler):
            def emit(self, record):
                records.append(record)

        host = Host()
        root = logging.getLogger()
        root.addHandler(host)
        try:
            assert main(["-vv", "capabilities"]) == EXIT_OK
        finally:
            root.removeHandler(host)
        err = capsys.readouterr().err
        assert err.count("probe-debug") == 1
        assert not [r for r in records if r.getMessage() == "probe-debug"]
        assert root.level == logging.WARNING

    def test_json_mode_does_not_outlive_its_call(self, tmp_path, capsys):
        from encryption_helper.cli._output import emit_error

        missing = str(tmp_path / "absent.pub")
        main(["--json", "fingerprint", missing])
        assert envelope(capsys.readouterr().err)["status"] == "error"
        main(["fingerprint", missing])
        assert capsys.readouterr().err.startswith("error: ")
        main(["--json", "fingerprint", missing])
        capsys.readouterr()
        # Reported from outside any call: the default, plain text.
        emit_error("after the call", 1)
        assert capsys.readouterr().err == "error: after the call\n"


class TestParserImportsNoCommands:
    """Building the parser does not load the command implementations.

    ``_parser`` imported all ten ``_cmd_*`` handlers, so constructing the
    parser -- for ``--help``, for a usage error, for documentation tests --
    loaded every command's dependencies whether or not one would run.
    """

    def test_importing_the_parser_leaves_the_commands_unloaded(self):
        probe = (
            "import sys\n"
            "from encryption_helper.cli._parser import build_parser\n"
            "build_parser().parse_args(['capabilities'])\n"
            "loaded = [m for m in ('encryption_helper.cli._commands',\n"
            "    'encryption_helper.cli._passphrase',\n"
            "    'encryption_helper.cli._streams') if m in sys.modules]\n"
            "print(loaded)\n"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "[]"

    def test_every_subcommand_names_a_real_handler(self):
        import argparse

        from encryption_helper.cli import _commands, build_parser

        (subparsers,) = (
            action
            for action in build_parser()._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        for name, subparser in subparsers.choices.items():
            handler = subparser.get_default("func")
            assert callable(handler), name
            assert handler.resolve() is getattr(_commands, f"_cmd_{name}"), name

    def test_args_func_still_runs_the_command(self, capsys):
        from encryption_helper.cli import build_parser

        args = build_parser().parse_args(["--json", "capabilities"])
        assert args.func(args) == EXIT_OK
        assert envelope(capsys.readouterr().out)["command"] == "capabilities"

    def test_a_handler_patched_after_parsing_is_the_one_that_runs(self, monkeypatch):
        """Resolution is at dispatch, so the module's current function runs."""
        from encryption_helper.cli import _commands

        calls = []
        monkeypatch.setattr(
            _commands, "_cmd_capabilities", lambda args: calls.append(args) or 7
        )
        assert main(["capabilities"]) == 7
        assert len(calls) == 1
