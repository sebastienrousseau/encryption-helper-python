"""Tests for the command-line interface.

Most cases drive ``main()`` in-process so failures are readable, but the
console script is also exercised through a real subprocess: an entry point that
works when imported and fails when installed is a common and embarrassing bug.
"""

from __future__ import annotations

import json
import stat
import subprocess
import sys

import pytest
from encryption_helper.cli import (
    EXIT_CRYPTO_FAILURE,
    EXIT_ERROR,
    EXIT_KEY_EXISTS,
    EXIT_OK,
    EXIT_USAGE,
    main,
)

from ._support import posix_only


@pytest.fixture
def keypair(tmp_path):
    """A generated RSA key pair on disk, plus its directory."""
    assert main(["keygen", "--out-dir", str(tmp_path), "--key-size", "2048"]) == EXIT_OK
    return tmp_path / "key.pem", tmp_path / "key.pub.pem"


class TestKeygen:
    def test_writes_a_usable_pair(self, tmp_path, capsys):
        assert main(["keygen", "--out-dir", str(tmp_path)]) == EXIT_OK
        assert (tmp_path / "key.pem").exists()
        assert (tmp_path / "key.pub.pem").exists()
        assert "Fingerprint: SHA256:" in capsys.readouterr().out

    def test_never_prints_the_private_key(self, tmp_path, capsys):
        """Regression test for finding C3.

        Version 0.0.1 printed the full PEM private key to stdout on every run.
        """
        main(["keygen", "--out-dir", str(tmp_path)])
        captured = capsys.readouterr()
        assert "BEGIN PRIVATE KEY" not in captured.out
        assert "BEGIN PRIVATE KEY" not in captured.err
        assert "BEGIN RSA PRIVATE KEY" not in captured.out

    def test_warns_that_the_key_is_secret(self, tmp_path, capsys):
        main(["keygen", "--out-dir", str(tmp_path)])
        assert "PRIVATE KEY" in capsys.readouterr().out

    def test_warns_when_the_key_is_unencrypted(self, tmp_path, capsys):
        main(["keygen", "--out-dir", str(tmp_path)])
        assert "NOT encrypted" in capsys.readouterr().out

    @posix_only
    def test_private_key_is_owner_only(self, tmp_path):
        """Regression test for finding C2."""
        main(["keygen", "--out-dir", str(tmp_path)])
        assert stat.S_IMODE((tmp_path / "key.pem").stat().st_mode) == 0o600

    def test_does_not_write_into_the_current_directory_by_surprise(
        self, tmp_path, monkeypatch
    ):
        """0.0.1 always created ./keys/pem relative to the process cwd."""
        monkeypatch.chdir(tmp_path)
        main(["keygen"])
        assert not (tmp_path / "keys").exists()
        assert (tmp_path / "key.pem").exists()

    @pytest.mark.parametrize("algorithm", ["rsa", "ed25519", "ecdsa"])
    def test_algorithms(self, tmp_path, algorithm):
        args = ["keygen", "--out-dir", str(tmp_path), "--algorithm", algorithm]
        if algorithm == "rsa":
            args += ["--key-size", "2048"]
        assert main(args) == EXIT_OK

    def test_rejects_weak_key_size(self, tmp_path, capsys):
        code = main(["keygen", "--out-dir", str(tmp_path), "--key-size", "512"])
        assert code == EXIT_ERROR
        assert "too small" in capsys.readouterr().err

    def test_existing_key_exits_three(self, tmp_path, capsys):
        """Regression test for finding C6."""
        main(["keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        original = (tmp_path / "key.pem").read_bytes()

        code = main(["keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        assert code == EXIT_KEY_EXISTS
        assert "already exists" in capsys.readouterr().err
        assert (tmp_path / "key.pem").read_bytes() == original

    def test_force_replaces_and_backs_up(self, tmp_path):
        main(["keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        original = (tmp_path / "key.pem").read_bytes()
        code = main(
            ["keygen", "--out-dir", str(tmp_path), "--key-size", "2048", "--force"]
        )
        assert code == EXIT_OK
        assert (tmp_path / "key.pem").read_bytes() != original
        assert len(list(tmp_path.glob("key.pem.bak-*"))) == 1

    def test_passphrase_from_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EH_TEST_PASS", "correct horse")
        code = main(
            [
                "keygen",
                "--out-dir",
                str(tmp_path),
                "--key-size",
                "2048",
                "--passphrase-env",
                "EH_TEST_PASS",
            ]
        )
        assert code == EXIT_OK
        assert (
            (tmp_path / "key.pem")
            .read_bytes()
            .startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        )

    def test_missing_environment_variable_is_a_usage_error(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "keygen",
                    "--out-dir",
                    str(tmp_path),
                    "--passphrase-env",
                    "EH_DEFINITELY_UNSET",
                ]
            )
        assert excinfo.value.code == EXIT_USAGE
        assert "unset or empty" in capsys.readouterr().err

    def test_passphrase_from_file(self, tmp_path):
        secret = tmp_path / "pass.txt"
        secret.write_bytes(b"correct horse\n")
        code = main(
            [
                "keygen",
                "--out-dir",
                str(tmp_path),
                "--key-size",
                "2048",
                "--passphrase-file",
                str(secret),
            ]
        )
        assert code == EXIT_OK

    def test_empty_passphrase_file_is_a_usage_error(self, tmp_path):
        secret = tmp_path / "pass.txt"
        secret.write_bytes(b"   \n")
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "keygen",
                    "--out-dir",
                    str(tmp_path),
                    "--passphrase-file",
                    str(secret),
                ]
            )
        assert excinfo.value.code == EXIT_USAGE

    def test_passphrase_sources_are_mutually_exclusive(self, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "keygen",
                    "--passphrase-env",
                    "A",
                    "--passphrase-file",
                    "b",
                ]
            )
        assert excinfo.value.code == EXIT_USAGE

    def test_json_output(self, tmp_path, capsys):
        main(["--json", "keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["fingerprint"].startswith("SHA256:")
        assert payload["encrypted"] is False
        assert payload["private_key"].endswith("key.pem")


class TestEncryptDecrypt:
    def test_round_trip_through_files(self, tmp_path, keypair):
        private, public = keypair
        (tmp_path / "msg.txt").write_bytes(b"attack at dawn")

        assert (
            main(
                [
                    "encrypt",
                    "--public-key",
                    str(public),
                    "--in",
                    str(tmp_path / "msg.txt"),
                    "--out",
                    str(tmp_path / "msg.bin"),
                ]
            )
            == EXIT_OK
        )
        assert (
            main(
                [
                    "decrypt",
                    "--private-key",
                    str(private),
                    "--in",
                    str(tmp_path / "msg.bin"),
                    "--out",
                    str(tmp_path / "out.txt"),
                ]
            )
            == EXIT_OK
        )
        assert (tmp_path / "out.txt").read_bytes() == b"attack at dawn"

    @posix_only
    def test_decrypted_output_is_owner_only(self, tmp_path, keypair):
        """Plaintext recovered from a ciphertext is itself likely a secret."""
        private, public = keypair
        (tmp_path / "m.txt").write_bytes(b"secret")
        main(
            [
                "encrypt",
                "--public-key",
                str(public),
                "--in",
                str(tmp_path / "m.txt"),
                "--out",
                str(tmp_path / "m.bin"),
            ]
        )
        main(
            [
                "decrypt",
                "--private-key",
                str(private),
                "--in",
                str(tmp_path / "m.bin"),
                "--out",
                str(tmp_path / "m.out"),
            ]
        )
        assert stat.S_IMODE((tmp_path / "m.out").stat().st_mode) == 0o600

    def test_tampered_ciphertext_exits_four(self, tmp_path, keypair, capsys):
        private, public = keypair
        (tmp_path / "m.txt").write_bytes(b"secret")
        main(
            [
                "encrypt",
                "--public-key",
                str(public),
                "--in",
                str(tmp_path / "m.txt"),
                "--out",
                str(tmp_path / "m.bin"),
            ]
        )
        blob = bytearray((tmp_path / "m.bin").read_bytes())
        blob[-1] ^= 0x01
        (tmp_path / "m.bin").write_bytes(bytes(blob))

        code = main(
            [
                "decrypt",
                "--private-key",
                str(private),
                "--in",
                str(tmp_path / "m.bin"),
                "--out",
                str(tmp_path / "m.out"),
            ]
        )
        assert code == EXIT_CRYPTO_FAILURE
        assert "integrity check" in capsys.readouterr().err
        assert not (tmp_path / "m.out").exists()

    def test_missing_key_file_exits_one(self, tmp_path, capsys):
        (tmp_path / "src.txt").write_bytes(b"payload")
        code = main(
            [
                "encrypt",
                "--public-key",
                str(tmp_path / "absent.pem"),
                "--in",
                str(tmp_path / "src.txt"),
                "--out",
                str(tmp_path / "o.bin"),
            ]
        )
        assert code == EXIT_ERROR
        assert "No such file" in capsys.readouterr().err


class TestSignVerify:
    def test_round_trip(self, tmp_path, keypair):
        private, public = keypair
        (tmp_path / "m.txt").write_bytes(b"contract")
        assert (
            main(
                [
                    "sign",
                    "--private-key",
                    str(private),
                    "--in",
                    str(tmp_path / "m.txt"),
                    "--out",
                    str(tmp_path / "m.sig"),
                ]
            )
            == EXIT_OK
        )
        assert (
            main(
                [
                    "verify",
                    "--public-key",
                    str(public),
                    "--signature",
                    str(tmp_path / "m.sig"),
                    "--in",
                    str(tmp_path / "m.txt"),
                ]
            )
            == EXIT_OK
        )

    def test_altered_message_exits_four(self, tmp_path, keypair, capsys):
        private, public = keypair
        (tmp_path / "m.txt").write_bytes(b"transfer 100")
        main(
            [
                "sign",
                "--private-key",
                str(private),
                "--in",
                str(tmp_path / "m.txt"),
                "--out",
                str(tmp_path / "m.sig"),
            ]
        )
        (tmp_path / "m.txt").write_bytes(b"transfer 900")

        code = main(
            [
                "verify",
                "--public-key",
                str(public),
                "--signature",
                str(tmp_path / "m.sig"),
                "--in",
                str(tmp_path / "m.txt"),
            ]
        )
        assert code == EXIT_CRYPTO_FAILURE
        assert "verification failed" in capsys.readouterr().err


class TestFingerprintCommand:
    def test_prints_a_fingerprint(self, keypair, capsys):
        _, public = keypair
        assert main(["fingerprint", str(public)]) == EXIT_OK
        assert capsys.readouterr().out.strip().startswith("SHA256:")

    def test_json_form(self, keypair, capsys):
        _, public = keypair
        main(["--json", "fingerprint", str(public)])
        assert json.loads(capsys.readouterr().out)["fingerprint"].startswith("SHA256:")


class TestConvert:
    def test_public_pem_to_openssh(self, tmp_path, keypair):
        _, public = keypair
        code = main(
            [
                "convert",
                "--to",
                "openssh",
                "--in",
                str(public),
                "--out",
                str(tmp_path / "id.pub"),
            ]
        )
        assert code == EXIT_OK
        assert (tmp_path / "id.pub").read_bytes().startswith(b"ssh-rsa ")

    @posix_only
    def test_converted_private_key_is_owner_only(self, tmp_path, keypair):
        private, _ = keypair
        main(
            [
                "convert",
                "--private",
                "--to",
                "der",
                "--in",
                str(private),
                "--out",
                str(tmp_path / "k.der"),
            ]
        )
        assert stat.S_IMODE((tmp_path / "k.der").stat().st_mode) == 0o600


class TestGlobalBehaviour:
    def test_no_command_is_a_usage_error(self):
        with pytest.raises(SystemExit) as excinfo:
            main([])
        assert excinfo.value.code == EXIT_USAGE

    def test_unknown_command_is_a_usage_error(self):
        with pytest.raises(SystemExit) as excinfo:
            main(["nonsense"])
        assert excinfo.value.code == EXIT_USAGE

    def test_quiet_suppresses_normal_output(self, tmp_path, capsys):
        main(["--quiet", "keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        assert capsys.readouterr().out == ""

    def test_overwriting_output_requires_force(self, tmp_path, keypair, capsys):
        _, public = keypair
        (tmp_path / "taken.bin").write_bytes(b"existing")
        (tmp_path / "src.txt").write_bytes(b"payload")
        code = main(
            [
                "encrypt",
                "--public-key",
                str(public),
                "--in",
                str(tmp_path / "src.txt"),
                "--out",
                str(tmp_path / "taken.bin"),
            ]
        )
        assert code == EXIT_KEY_EXISTS
        assert (tmp_path / "taken.bin").read_bytes() == b"existing"


class TestInstalledConsoleScript:
    """Exercise the real entry point, not just the imported function."""

    def _run(self, *args, **kwargs):
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", "encryption_helper", *args],
            capture_output=True,
            check=False,
            **kwargs,
        )

    def test_version(self):
        result = self._run("--version")
        assert result.returncode == EXIT_OK
        assert b"encryption-helper" in result.stdout

    def test_help(self):
        result = self._run("--help")
        assert result.returncode == EXIT_OK
        for command in (b"keygen", b"encrypt", b"decrypt", b"sign", b"verify"):
            assert command in result.stdout

    def test_keygen_end_to_end(self, tmp_path):
        result = self._run("keygen", "--out-dir", str(tmp_path), "--key-size", "2048")
        assert result.returncode == EXIT_OK
        assert b"BEGIN PRIVATE KEY" not in result.stdout
        assert (tmp_path / "key.pem").exists()

    def test_streaming_round_trip_through_pipes(self, tmp_path):
        assert (
            self._run("keygen", "--out-dir", str(tmp_path), "--key-size", "2048")
        ).returncode == EXIT_OK

        encrypted = self._run(
            "--quiet",
            "encrypt",
            "--public-key",
            str(tmp_path / "key.pub.pem"),
            "--in",
            "-",
            "--out",
            "-",
            input=b"piped secret",
        )
        assert encrypted.returncode == EXIT_OK

        decrypted = self._run(
            "--quiet",
            "decrypt",
            "--private-key",
            str(tmp_path / "key.pem"),
            "--in",
            "-",
            "--out",
            "-",
            input=encrypted.stdout,
        )
        assert decrypted.returncode == EXIT_OK
        assert decrypted.stdout == b"piped secret"

    def test_passphrase_is_never_taken_from_argv(self):
        """Process arguments are world-readable; a literal flag must not exist."""
        result = self._run("keygen", "--help")
        assert b"--passphrase-env" in result.stdout
        assert b"--passphrase-file" in result.stdout
        assert b"--passphrase " not in result.stdout.replace(b"--passphrase-", b"")

    @posix_only
    def test_exit_code_for_existing_key(self, tmp_path):
        self._run("keygen", "--out-dir", str(tmp_path), "--key-size", "2048")
        result = self._run("keygen", "--out-dir", str(tmp_path), "--key-size", "2048")
        assert result.returncode == EXIT_KEY_EXISTS


class TestLoggingFlags:
    @pytest.mark.parametrize(
        ("argv", "expected"),
        [
            (["--log-level", "DEBUG"], "DEBUG"),
            (["-v"], "INFO"),
            (["-vv"], "DEBUG"),
            (["--quiet"], "ERROR"),
        ],
    )
    def test_verbosity_maps_to_a_level(self, tmp_path, argv, expected, monkeypatch):
        import logging as logging_module

        captured = {}

        def fake_basic_config(**kwargs):
            captured["level"] = logging_module.getLevelName(kwargs["level"])

        monkeypatch.setattr(logging_module, "basicConfig", fake_basic_config)
        main([*argv, "keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        assert captured["level"] == expected


class TestStdio:
    def test_reads_input_from_stdin(self, tmp_path, keypair, monkeypatch, capsysbinary):
        import io

        _, public = keypair
        monkeypatch.setattr(
            sys, "stdin", type("S", (), {"buffer": io.BytesIO(b"from stdin")})()
        )
        assert (
            main(
                [
                    "--quiet",
                    "encrypt",
                    "--public-key",
                    str(public),
                    "--in",
                    "-",
                    "--out",
                    str(tmp_path / "o.bin"),
                ]
            )
            == EXIT_OK
        )
        assert (tmp_path / "o.bin").exists()

    def test_show_public_writes_the_public_key(self, tmp_path, capsysbinary):
        main(
            [
                "keygen",
                "--out-dir",
                str(tmp_path),
                "--key-size",
                "2048",
                "--show-public",
            ]
        )
        out = capsysbinary.readouterr().out
        assert b"-----BEGIN PUBLIC KEY-----" in out
        assert b"BEGIN PRIVATE KEY" not in out
