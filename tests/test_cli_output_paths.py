# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests that every command reports a destination a caller can actually use.

`sign` and `convert` reported

    Wrote 64-byte signature to WriteOutcome(path=PosixPath('/tmp/m.sig'), ...)

because the writer returns a ``WriteOutcome`` and the caller stringified the
outcome rather than its ``path``. The same value is published as the
``output`` field of the JSON contract, so automation received a repr where it
expected a path.

No type checker could catch it: ``str()`` accepts any object and returns a
``str``, which is exactly what the annotation promised. The property that
does catch it is checked here -- the reported path must name a file that
exists -- and it is checked for every command that reports one, because the
defect was in shared code and so was never specific to one command.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from encryption_helper.cli import EXIT_OK, main

from ._support import result_of


@pytest.fixture
def keys(tmp_path):
    """Generate an RSA pair, which can both encrypt and sign."""
    directory = tmp_path / "keys"
    assert (
        main(
            [
                "-q",
                "keygen",
                "--out-dir",
                str(directory),
                "--algorithm",
                "rsa",
                "--key-size",
                "2048",
                "--no-passphrase",
            ]
        )
        == EXIT_OK
    )
    return directory


@pytest.fixture
def payload(tmp_path):
    path = tmp_path / "payload.txt"
    path.write_bytes(b"release manifest")
    return path


def _reported_output(capsys) -> str:
    return result_of(capsys.readouterr().out)["output"]


class TestReportedPathsExist:
    """The reported destination must be a path, not a description of one."""

    def test_sign(self, tmp_path, keys, payload, capsys):
        destination = tmp_path / "payload.sig"
        assert (
            main(
                [
                    "--json",
                    "sign",
                    "--private-key",
                    str(keys / "key.pem"),
                    "--in",
                    str(payload),
                    "--out",
                    str(destination),
                ]
            )
            == EXIT_OK
        )
        reported = _reported_output(capsys)
        assert Path(reported).is_file()
        assert Path(reported) == destination
        assert "WriteOutcome" not in reported

    def test_convert(self, tmp_path, keys, capsys):
        destination = tmp_path / "key.pub.der"
        assert (
            main(
                [
                    "--json",
                    "convert",
                    "--to",
                    "der",
                    "--in",
                    str(keys / "key.pub.pem"),
                    "--out",
                    str(destination),
                ]
            )
            == EXIT_OK
        )
        reported = _reported_output(capsys)
        assert Path(reported).is_file()
        assert Path(reported) == destination

    def test_encrypt(self, tmp_path, keys, payload, capsys):
        destination = tmp_path / "payload.enc"
        assert (
            main(
                [
                    "--json",
                    "encrypt",
                    "--public-key",
                    str(keys / "key.pub.pem"),
                    "--in",
                    str(payload),
                    "--out",
                    str(destination),
                ]
            )
            == EXIT_OK
        )
        reported = _reported_output(capsys)
        assert Path(reported).is_file()

    def test_decrypt(self, tmp_path, keys, payload, capsys):
        container = tmp_path / "payload.enc"
        main(
            [
                "-q",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(payload),
                "--out",
                str(container),
            ]
        )
        destination = tmp_path / "payload.out"
        assert (
            main(
                [
                    "--json",
                    "decrypt",
                    "--private-key",
                    str(keys / "key.pem"),
                    "--in",
                    str(container),
                    "--out",
                    str(destination),
                ]
            )
            == EXIT_OK
        )
        reported = _reported_output(capsys)
        assert Path(reported).is_file()
        assert Path(reported).read_bytes() == b"release manifest"

    def test_keygen_reports_both_halves(self, tmp_path, capsys):
        main(
            [
                "--json",
                "-q",
                "keygen",
                "--out-dir",
                str(tmp_path / "k"),
                "--algorithm",
                "ed25519",
                "--no-passphrase",
            ]
        )
        result = result_of(capsys.readouterr().out)
        assert Path(result["private_key"]).is_file()
        assert Path(result["public_key"]).is_file()


class TestHumanOutputNamesTheFile:
    """The same defect was visible in the human-readable line."""

    @pytest.mark.parametrize("command", ["sign", "convert"])
    def test_no_command_prints_an_object_repr(
        self, tmp_path, keys, payload, capsys, command
    ):
        if command == "sign":
            argv = [
                "sign",
                "--private-key",
                str(keys / "key.pem"),
                "--in",
                str(payload),
                "--out",
                str(tmp_path / "out.bin"),
            ]
        else:
            argv = [
                "convert",
                "--to",
                "der",
                "--in",
                str(keys / "key.pub.pem"),
                "--out",
                str(tmp_path / "out.bin"),
            ]
        assert main(argv) == EXIT_OK
        out = capsys.readouterr().out
        assert "WriteOutcome" not in out
        assert "PosixPath" not in out
        assert str(tmp_path / "out.bin") in out


class TestStdoutDestination:
    def test_stdout_is_reported_symbolically(self, keys, payload, capsysbinary):
        """`-` has no path, so the placeholder is correct rather than a bug."""
        main(
            [
                "--json",
                "sign",
                "--private-key",
                str(keys / "key.pem"),
                "--in",
                str(payload),
                "--out",
                "-",
            ]
        )
        captured = capsysbinary.readouterr()
        assert result_of(captured.err.decode())["output"] == "<stdout>"
