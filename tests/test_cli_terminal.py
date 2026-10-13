# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Secrets are not written to a terminal unless the user asks for it.

``--out`` defaults to stdout, so ``decrypt --private-key k --in f`` typed at
a shell printed the plaintext straight onto the screen -- into scrollback,
terminal logs and screen recordings -- and ``convert --private`` did the
same with a private key. A pipe or a file is what the default exists for;
a terminal is refused unless ``--out -`` says it was meant. Ciphertext,
signatures and public keys are not secrets, and are unaffected.
"""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import threading
from collections.abc import Iterator

import pytest
from encryption_helper import encrypt, load_public_key_file
from encryption_helper.cli import EXIT_OK, EXIT_USAGE, main

from ._support import error_of

PLAINTEXT = b"TERMINAL-CANARY-plaintext-3f9c"
REFUSAL = "Refusing to write decrypted plaintext to a terminal."


class _Terminal(io.TextIOWrapper):
    """A stdout that reports itself as a terminal and records what it got."""

    def __init__(self) -> None:
        super().__init__(io.BytesIO(), encoding="utf-8")

    def isatty(self) -> bool:
        return True

    @property
    def written(self) -> bytes:
        self.flush()
        raw = self.buffer
        assert isinstance(raw, io.BytesIO)
        return raw.getvalue()


@pytest.fixture
def keys(tmp_path):
    assert (
        main(
            [
                "-q",
                "keygen",
                "--algorithm",
                "x25519",
                "--out-dir",
                str(tmp_path / "keys"),
                "--no-passphrase",
            ]
        )
        == EXIT_OK
    )
    return tmp_path / "keys"


@pytest.fixture
def one_shot(tmp_path, keys):
    path = tmp_path / "one-shot.enc"
    path.write_bytes(encrypt(load_public_key_file(keys / "key.pub.pem"), PLAINTEXT))
    return path


@pytest.fixture
def streamed(tmp_path, keys):
    source = tmp_path / "plain.txt"
    source.write_bytes(PLAINTEXT)
    path = tmp_path / "streamed.enc"
    assert (
        main(
            [
                "-q",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(source),
                "--out",
                str(path),
            ]
        )
        == EXIT_OK
    )
    return path


@contextlib.contextmanager
def on_terminal() -> Iterator[_Terminal]:
    """Attach stdout to a fake terminal for the duration of the block.

    Inside the test body, not a fixture: pytest re-installs its own capture
    streams when the test call begins, replacing anything set during setup.
    """
    stdout = _Terminal()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sys, "stdout", stdout)
        yield stdout


def _decrypt(keys, container, *extra: str) -> list[str]:
    return [
        *extra,
        "decrypt",
        "--private-key",
        str(keys / "key.pem"),
        "--in",
        str(container),
    ]


class TestDecryptToATerminal:
    @pytest.mark.parametrize("container", ["one_shot", "streamed"])
    def test_the_default_output_is_refused(self, keys, container, request, capsys):
        path = request.getfixturevalue(container)
        with on_terminal() as terminal, pytest.raises(SystemExit) as raised:
            main(_decrypt(keys, path))
        assert raised.value.code == EXIT_USAGE
        assert PLAINTEXT not in terminal.written
        assert REFUSAL in capsys.readouterr().err

    def test_the_refusal_is_a_json_error_with_json(self, keys, one_shot, capsys):
        with on_terminal() as terminal, pytest.raises(SystemExit):
            main(_decrypt(keys, one_shot, "--json"))
        error = error_of(capsys.readouterr().err)
        assert error["code"] == "usage"
        assert REFUSAL in error["message"]
        assert PLAINTEXT not in terminal.written

    def test_an_explicit_dash_forces_it(self, keys, one_shot):
        with on_terminal() as terminal:
            assert main([*_decrypt(keys, one_shot), "--out", "-"]) == EXIT_OK
        assert PLAINTEXT in terminal.written

    def test_a_file_is_unaffected(self, tmp_path, keys, one_shot):
        out = tmp_path / "plain.out"
        with on_terminal():
            assert main([*_decrypt(keys, one_shot), "--out", str(out)]) == EXIT_OK
        assert out.read_bytes() == PLAINTEXT

    def test_a_pipe_is_unaffected(self, keys, one_shot, capsysbinary):
        """Not a terminal: the default still writes to stdout, as before."""
        assert main(_decrypt(keys, one_shot)) == EXIT_OK
        assert capsysbinary.readouterr().out == PLAINTEXT


class TestOtherCommandsToATerminal:
    def test_a_private_key_conversion_is_refused(self, keys, capsys):
        with on_terminal() as terminal, pytest.raises(SystemExit) as raised:
            main(
                [
                    "convert",
                    "--private",
                    "--to",
                    "der",
                    "--in",
                    str(keys / "key.pem"),
                ]
            )
        assert raised.value.code == EXIT_USAGE
        assert terminal.written == b""
        assert "Refusing to write a private key to a terminal." in (
            capsys.readouterr().err
        )

    def test_a_private_key_conversion_can_be_forced(self, keys):
        argv = ["convert", "--private", "--to", "pem", "--in", str(keys / "key.pem")]
        with on_terminal() as terminal:
            assert main([*argv, "--out", "-"]) == EXIT_OK
        assert b"PRIVATE KEY" in terminal.written

    def test_a_public_key_conversion_is_unaffected(self, keys):
        argv = ["convert", "--to", "pem", "--in", str(keys / "key.pub.pem")]
        with on_terminal() as terminal:
            assert main(argv) == EXIT_OK
        assert terminal.written.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_ciphertext_is_unaffected(self, tmp_path, keys):
        source = tmp_path / "m.txt"
        source.write_bytes(b"payload")
        argv = ["encrypt", "--public-key", str(keys / "key.pub.pem")]
        with on_terminal() as terminal:
            assert main([*argv, "--in", str(source)]) == EXIT_OK
        assert terminal.written.startswith(b"EHEV")


@pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX pseudo-terminal")
class TestRealTerminal:
    """The same, with stdout attached to an actual pseudo-terminal."""

    def _run_on_pty(self, argv: list[str]) -> tuple[int, bytes, bytes]:
        pty = pytest.importorskip("pty")
        primary, secondary = pty.openpty()
        screen = bytearray()

        def drain() -> None:
            # Read while the child runs: some platforms discard what is left
            # in a pseudo-terminal once its last writer closes.
            while True:
                try:
                    chunk = os.read(primary, 65536)
                except OSError:  # EIO: the terminal's other end is closed
                    return
                if not chunk:
                    return
                screen.extend(chunk)

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            process = subprocess.Popen(  # noqa: S603
                [sys.executable, "-m", "encryption_helper", *argv],
                stdin=subprocess.DEVNULL,
                stdout=secondary,
                stderr=subprocess.PIPE,
            )
        finally:
            os.close(secondary)
        _, stderr = process.communicate(timeout=60)
        reader.join(timeout=10)
        os.close(primary)
        return process.returncode, bytes(screen), stderr

    def test_decrypt_refuses_a_real_terminal(self, keys, one_shot):
        code, screen, stderr = self._run_on_pty(_decrypt(keys, one_shot))
        assert code == EXIT_USAGE
        assert PLAINTEXT not in screen
        assert REFUSAL.encode() in stderr

    def test_an_explicit_dash_writes_to_a_real_terminal(self, keys, one_shot):
        code, screen, _ = self._run_on_pty([*_decrypt(keys, one_shot), "--out", "-"])
        assert code == EXIT_OK
        assert PLAINTEXT in screen


class TestTerminalDetection:
    """A replaced or closed stdout is not a terminal, and does not crash."""

    def test_a_stream_without_isatty_is_not_a_terminal(self, monkeypatch):
        from encryption_helper.cli._streams import _stdout_is_terminal

        monkeypatch.setattr(sys, "stdout", object())
        assert _stdout_is_terminal() is False

    def test_a_closed_stream_is_not_a_terminal(self, monkeypatch):
        from encryption_helper.cli._streams import _stdout_is_terminal

        closed = io.StringIO()
        closed.close()
        monkeypatch.setattr(sys, "stdout", closed)
        assert _stdout_is_terminal() is False
