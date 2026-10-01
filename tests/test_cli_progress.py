# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for `--progress`.

A multi-gigabyte operation with no output is indistinguishable from a hang.
These check the reporting is useful, throttled enough not to cost anything,
and never on the stream carrying the command's output.
"""

from __future__ import annotations

import io

import pytest
from encryption_helper.cli import EXIT_OK, main
from encryption_helper.cli._format import _format_bytes, _format_duration
from encryption_helper.cli._progress import _ProgressReporter

from ._support import posix_only


def keygen(tmp_path, *extra: str) -> list[str]:
    return [
        "keygen",
        "--out-dir",
        str(tmp_path),
        "--algorithm",
        "x25519",
        "--no-passphrase",
        *extra,
    ]


@pytest.fixture
def setup(tmp_path):
    """A key pair and a payload spanning several segments."""
    keys = tmp_path / "k"
    main(keygen(keys))
    payload = tmp_path / "m.bin"
    payload.write_bytes(b"p" * 40000)
    return keys, payload


class TestFormatting:
    @pytest.mark.parametrize(
        ("count", "expected"),
        [
            (0, "0 B"),
            (512, "512 B"),
            (1024, "1.0 KiB"),
            (1536, "1.5 KiB"),
            (1048576, "1.0 MiB"),
            (1073741824, "1.0 GiB"),
            (5 * 1073741824, "5.0 GiB"),
        ],
    )
    def test_byte_counts(self, count, expected):
        assert _format_bytes(count) == expected

    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [(0, "0s"), (1.4, "1s"), (59, "59s"), (60, "1m00s"), (3725, "62m05s")],
    )
    def test_durations(self, seconds, expected):
        assert _format_duration(seconds) == expected


class TestReporter:
    def test_throttles_updates(self):
        """At 1.5 GB/s there are ~6,000 callbacks a second; printing each
        would cost more than the encryption."""
        stream = io.StringIO()
        reporter = _ProgressReporter(1000, stream=stream)
        for n in range(1, 1001):
            reporter(n)
        # The first call is throttled against a zero timestamp, so at most a
        # couple of lines appear for a thousand rapid callbacks.
        assert stream.getvalue().count("\n") <= 2

    def test_final_line_is_always_emitted(self):
        stream = io.StringIO()
        reporter = _ProgressReporter(1000, stream=stream)
        reporter.finish(1000)
        assert "1000" in stream.getvalue() or "1.0 KiB" in stream.getvalue()

    def test_percentage_and_eta_when_the_size_is_known(self):
        stream = io.StringIO()
        reporter = _ProgressReporter(1000, stream=stream)
        reporter._last = 0.0
        reporter(500)
        out = stream.getvalue()
        assert "50.0%" in out
        assert "ETA" in out

    def test_no_percentage_when_the_size_is_unknown(self):
        """Reading from a pipe, the total cannot be known."""
        stream = io.StringIO()
        reporter = _ProgressReporter(None, stream=stream)
        reporter._last = 0.0
        reporter(500)
        out = stream.getvalue()
        assert "%" not in out
        assert "ETA" not in out
        assert "/s" in out

    def test_final_line_reports_elapsed_not_eta(self):
        stream = io.StringIO()
        reporter = _ProgressReporter(1000, stream=stream)
        reporter.finish(1000)
        out = stream.getvalue()
        assert "in " in out
        assert "ETA" not in out

    def test_percentage_is_capped_at_one_hundred(self):
        stream = io.StringIO()
        reporter = _ProgressReporter(100, stream=stream)
        reporter.finish(250)
        assert "100.0%" in stream.getvalue()


class TestCliIntegration:
    def test_progress_goes_to_stderr_not_stdout(self, setup, tmp_path, capsys):
        """stdout may be carrying the ciphertext."""
        keys, payload = setup
        capsys.readouterr()
        main(
            [
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(payload),
                "--out",
                str(tmp_path / "o.bin"),
                "--progress",
                "--segment-size",
                "4096",
            ]
        )
        captured = capsys.readouterr()
        assert "/s" in captured.err
        assert "/s" not in captured.out

    def test_quiet_suppresses_progress(self, setup, tmp_path, capsys):
        keys, payload = setup
        capsys.readouterr()
        main(
            [
                "--quiet",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(payload),
                "--out",
                str(tmp_path / "o.bin"),
                "--progress",
            ]
        )
        assert capsys.readouterr().err == ""

    def test_absent_by_default(self, setup, tmp_path, capsys):
        keys, payload = setup
        capsys.readouterr()
        main(
            [
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(payload),
                "--out",
                str(tmp_path / "o.bin"),
            ]
        )
        assert "/s" not in capsys.readouterr().err

    def test_progress_on_decrypt(self, setup, tmp_path, capsys):
        keys, payload = setup
        main(
            [
                "-q",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(payload),
                "--out",
                str(tmp_path / "o.bin"),
                "--segment-size",
                "4096",
            ]
        )
        capsys.readouterr()
        assert (
            main(
                [
                    "decrypt",
                    "--private-key",
                    str(keys / "key.pem"),
                    "--in",
                    str(tmp_path / "o.bin"),
                    "--out",
                    str(tmp_path / "o.out"),
                    "--progress",
                ]
            )
            == EXIT_OK
        )
        assert "/s" in capsys.readouterr().err

    def test_progress_from_a_pipe_has_no_percentage(
        self, setup, tmp_path, monkeypatch, capsys
    ):
        keys, _ = setup
        capsys.readouterr()
        monkeypatch.setattr(
            "sys.stdin", type("S", (), {"buffer": io.BytesIO(b"q" * 20000)})()
        )
        main(
            [
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                "-",
                "--out",
                str(tmp_path / "o.bin"),
                "--progress",
                "--segment-size",
                "4096",
            ]
        )
        err = capsys.readouterr().err
        assert "/s" in err
        assert "%" not in err


@posix_only
class TestNonRegularDestinations:
    """`--out /dev/null` is a legitimate way to discard output, and renaming a
    temporary file over /dev/null would destroy the device node.

    POSIX only: Windows has no /dev/null path, and the equivalent (NUL) has
    different semantics, so this is skipped rather than faked.
    """

    def test_writing_to_dev_null_succeeds(self, setup):
        keys, payload = setup
        assert (
            main(
                [
                    "-q",
                    "encrypt",
                    "--public-key",
                    str(keys / "key.pub.pem"),
                    "--in",
                    str(payload),
                    "--out",
                    "/dev/null",
                ]
            )
            == EXIT_OK
        )

    def test_dev_null_remains_a_character_device(self, setup):
        import stat as stat_module

        keys, payload = setup
        main(
            [
                "-q",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(payload),
                "--out",
                "/dev/null",
            ]
        )
        mode = __import__("os").stat("/dev/null").st_mode
        assert stat_module.S_ISCHR(mode), "the device node was replaced"

    def test_no_force_needed_for_a_device(self, setup):
        """The don't-clobber guard is about regular files."""
        keys, payload = setup
        for _ in range(2):
            assert (
                main(
                    [
                        "-q",
                        "encrypt",
                        "--public-key",
                        str(keys / "key.pub.pem"),
                        "--in",
                        str(payload),
                        "--out",
                        "/dev/null",
                    ]
                )
                == EXIT_OK
            )

    def test_unwritable_device_is_reported_cleanly(self, setup, monkeypatch, capsys):
        """A device we cannot open must surface a typed error, not an OSError.

        The CLI converts it to an exit code at its boundary, so the
        observable behaviour is a non-zero status and a readable message.
        """
        keys, payload = setup
        real_open = __import__("pathlib").Path.open

        def refuse(self, *args, **kwargs):
            if str(self) == "/dev/null":
                raise OSError(13, "Permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr("pathlib.Path.open", refuse)
        code = main(
            [
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(payload),
                "--out",
                "/dev/null",
            ]
        )
        assert code != EXIT_OK
        assert "Could not write" in capsys.readouterr().err


class TestInteractiveRendering:
    def test_terminal_output_overwrites_in_place(self):
        """On a TTY the line is rewritten; in a log, lines accumulate."""

        class FakeTty(io.StringIO):
            def isatty(self) -> bool:
                return True

        stream = FakeTty()
        reporter = _ProgressReporter(1000, stream=stream)
        reporter._last = 0.0
        reporter(500)
        reporter.finish(1000)
        out = stream.getvalue()
        assert "\r" in out, "a terminal update should return to column zero"
        assert out.endswith("\n"), "the final line should terminate"

    def test_redirected_output_appends_lines(self):
        stream = io.StringIO()
        reporter = _ProgressReporter(1000, stream=stream)
        reporter._last = 0.0
        reporter(500)
        assert "\r" not in stream.getvalue()
        assert stream.getvalue().endswith("\n")
