# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Security invariants that must never regress.

Every test here encodes a property that version 0.0.1 violated. They are kept
in one file, separate from the functional suite, so that a reviewer can read
the project's security contract in a single sitting and CI has an obvious
gate to point at.

The central invariant:

    Private key material and passphrases may exist in cryptographic objects,
    in serialised bytes, and in the file they were explicitly written to.
    They may NEVER reach stdout, stderr, a log record at any level, or an
    exception message.
"""

from __future__ import annotations

import logging
import stat

import pytest
from encryption_helper.cli import EXIT_OK, EXIT_USAGE, main
from encryption_helper.errors import EncryptionHelperError
from encryption_helper.keys import load_private_key_file

from ._support import posix_only

#: Distinctive markers. If either appears anywhere it should not, the
#: assertion failure names the exact leak.
SECRET_PASSPHRASE = "VERY-SECRET-TEST-PASSPHRASE-8f3a1c"
PEM_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
)

ALL_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def _private_key_body(path) -> str:
    """Return the base64 body of a stored private key, minus its armour."""
    text = path.read_text()
    return "".join(
        line for line in text.splitlines() if not line.startswith("-----")
    ).strip()


class TestPrivateKeyNeverDisclosed:
    """Regression tests for finding C3.

    0.0.1 printed the complete PEM private key to stdout and logged it at
    DEBUG on every single run.
    """

    @pytest.mark.parametrize("level", ALL_LOG_LEVELS)
    def test_private_key_absent_from_output_at_every_log_level(
        self, tmp_path, capsys, caplog, level
    ):
        caplog.set_level(logging.DEBUG)
        code = main(
            [
                "--log-level",
                level,
                "keygen",
                "--out-dir",
                str(tmp_path),
                "--key-size",
                "2048",
                "--no-passphrase",
            ]
        )
        assert code == EXIT_OK

        captured = capsys.readouterr()
        logged = "\n".join(record.getMessage() for record in caplog.records)
        haystacks = {"stdout": captured.out, "stderr": captured.err, "logs": logged}

        body = _private_key_body(tmp_path / "key.pem")
        assert body, "the test needs a non-empty key to be meaningful"

        for where, text in haystacks.items():
            for marker in PEM_MARKERS:
                assert marker not in text, f"PEM armour leaked into {where}"
            assert body not in text, f"private key body leaked into {where}"

    @pytest.mark.parametrize("level", ALL_LOG_LEVELS)
    def test_passphrase_absent_from_output_at_every_log_level(
        self, tmp_path, capsys, caplog, monkeypatch, level
    ):
        monkeypatch.setenv("EH_SECRET", SECRET_PASSPHRASE)
        caplog.set_level(logging.DEBUG)
        code = main(
            [
                "--log-level",
                level,
                "keygen",
                "--out-dir",
                str(tmp_path),
                "--key-size",
                "2048",
                "--passphrase-env",
                "EH_SECRET",
            ]
        )
        assert code == EXIT_OK

        captured = capsys.readouterr()
        logged = "\n".join(record.getMessage() for record in caplog.records)
        for where, text in (
            ("stdout", captured.out),
            ("stderr", captured.err),
            ("logs", logged),
        ):
            assert SECRET_PASSPHRASE not in text, f"passphrase leaked into {where}"

    def test_passphrase_absent_from_exception_messages(self, tmp_path, ed25519_key):
        """A wrong passphrase must not be echoed back in the error."""
        from encryption_helper.keys import encode_private_key

        path = tmp_path / "k.pem"
        path.write_bytes(encode_private_key(ed25519_key, passphrase=b"right"))

        with pytest.raises(EncryptionHelperError) as excinfo:
            load_private_key_file(path, passphrase=SECRET_PASSPHRASE.encode())
        assert SECRET_PASSPHRASE not in str(excinfo.value)
        assert SECRET_PASSPHRASE not in repr(excinfo.value)

    def test_result_object_carries_no_secret(self, tmp_path, ed25519_key):
        """Regression for the old API, which returned the private PEM bytes."""
        from encryption_helper.keys import write_key_pair

        result = write_key_pair(
            ed25519_key, tmp_path, passphrase=SECRET_PASSPHRASE.encode()
        )
        rendered = repr(result)
        assert SECRET_PASSPHRASE not in rendered
        for marker in PEM_MARKERS:
            assert marker not in rendered
        # It reports *that* the key is encrypted, never the secret itself.
        assert result.private_key_encrypted is True


class TestUnencryptedKeysRequireConsent:
    """A plaintext private key must be an explicit choice, not a default."""

    def test_refuses_to_write_unencrypted_without_opt_in(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        assert excinfo.value.code == EXIT_USAGE
        assert "unencrypted" in capsys.readouterr().err
        assert not (tmp_path / "key.pem").exists()

    def test_no_passphrase_flag_permits_it(self, tmp_path):
        code = main(
            [
                "keygen",
                "--out-dir",
                str(tmp_path),
                "--key-size",
                "2048",
                "--no-passphrase",
            ]
        )
        assert code == EXIT_OK
        assert (
            (tmp_path / "key.pem")
            .read_bytes()
            .startswith(b"-----BEGIN PRIVATE KEY-----")
        )

    def test_interactive_session_prompts_for_a_passphrase(self, tmp_path, monkeypatch):
        monkeypatch.setattr("encryption_helper.cli._interactive", lambda: True)
        monkeypatch.setattr("getpass.getpass", lambda _prompt: SECRET_PASSPHRASE)
        code = main(["keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        assert code == EXIT_OK
        assert (
            (tmp_path / "key.pem")
            .read_bytes()
            .startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        )

    def test_mismatched_confirmation_is_rejected(self, tmp_path, monkeypatch):
        answers = iter([SECRET_PASSPHRASE, "something else"])
        monkeypatch.setattr("encryption_helper.cli._interactive", lambda: True)
        monkeypatch.setattr("getpass.getpass", lambda _prompt: next(answers))
        with pytest.raises(SystemExit) as excinfo:
            main(["keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        assert excinfo.value.code == EXIT_USAGE
        assert not (tmp_path / "key.pem").exists()

    def test_empty_prompt_response_is_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr("encryption_helper.cli._interactive", lambda: True)
        monkeypatch.setattr("getpass.getpass", lambda _prompt: "   ")
        with pytest.raises(SystemExit) as excinfo:
            main(["keygen", "--out-dir", str(tmp_path), "--key-size", "2048"])
        assert excinfo.value.code == EXIT_USAGE

    def test_encrypted_key_cannot_be_loaded_without_the_passphrase(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("EH_SECRET", SECRET_PASSPHRASE)
        main(
            [
                "keygen",
                "--out-dir",
                str(tmp_path),
                "--key-size",
                "2048",
                "--passphrase-env",
                "EH_SECRET",
            ]
        )
        path = tmp_path / "key.pem"
        with pytest.raises(EncryptionHelperError):
            load_private_key_file(path)
        with pytest.raises(EncryptionHelperError):
            load_private_key_file(path, passphrase=b"wrong")
        assert load_private_key_file(path, passphrase=SECRET_PASSPHRASE.encode())


class TestDestinationHandling:
    def test_tilde_is_expanded_not_taken_literally(self, tmp_path, monkeypatch):
        """Regression: `--out-dir ~/keys` created a directory named `~`."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)
        code = main(
            [
                "keygen",
                "--out-dir",
                "~/mykeys",
                "--key-size",
                "2048",
                "--no-passphrase",
            ]
        )
        assert code == EXIT_OK
        assert (tmp_path / "mykeys" / "key.pem").exists()
        assert not (tmp_path / "~").exists()

    def test_warns_when_writing_inside_a_git_worktree(self, tmp_path, capsys):
        """.gitignore is not a security boundary; warn before the key exists."""
        (tmp_path / ".git").mkdir()
        target = tmp_path / "nested"
        main(
            [
                "keygen",
                "--out-dir",
                str(target),
                "--key-size",
                "2048",
                "--no-passphrase",
            ]
        )
        assert "git repository" in capsys.readouterr().err


class TestPairIntegrity:
    def test_written_pair_is_cryptographically_matched(self, tmp_path):
        """The old suite asserted on b"fake_private_key" and proved nothing."""
        from encryption_helper.keys import load_public_key_file

        main(
            [
                "keygen",
                "--out-dir",
                str(tmp_path),
                "--key-size",
                "2048",
                "--no-passphrase",
            ]
        )
        private = load_private_key_file(tmp_path / "key.pem")
        public = load_public_key_file(tmp_path / "key.pub.pem")
        assert private.key_size == 2048
        assert private.public_key().public_numbers() == public.public_numbers()

    def test_failed_public_write_leaves_no_orphan_private_key(
        self, tmp_path, ed25519_key, monkeypatch
    ):
        """A private key with no public counterpart must never survive."""
        from encryption_helper.keys import store

        real = store.secure_write_bytes
        calls = {"n": 0}

        def fail_on_second(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(28, "No space left on device")
            return real(*args, **kwargs)

        monkeypatch.setattr(store, "secure_write_bytes", fail_on_second)
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(ed25519_key, tmp_path)

        assert not (tmp_path / "key.pem").exists(), "orphaned private key survived"
        assert not (tmp_path / "key.pub.pem").exists()

    def test_failed_public_write_restores_the_previous_private_key(
        self, tmp_path, ed25519_key, rsa_key, monkeypatch
    ):
        """A failed replacement must not destroy the key it was replacing."""
        from encryption_helper.keys import store

        store.write_key_pair(ed25519_key, tmp_path)
        original = (tmp_path / "key.pem").read_bytes()

        real = store.secure_write_bytes
        calls = {"n": 0}

        def fail_on_second(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(28, "No space left on device")
            return real(*args, **kwargs)

        monkeypatch.setattr(store, "secure_write_bytes", fail_on_second)
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(rsa_key, tmp_path, overwrite=True)

        assert (tmp_path / "key.pem").read_bytes() == original


class TestPermissions:
    @posix_only
    @pytest.mark.parametrize("algorithm", ["rsa", "ed25519", "ecdsa"])
    def test_private_key_is_owner_only_for_every_algorithm(self, tmp_path, algorithm):
        args = [
            "keygen",
            "--out-dir",
            str(tmp_path),
            "--algorithm",
            algorithm,
            "--no-passphrase",
        ]
        if algorithm == "rsa":
            args += ["--key-size", "2048"]
        assert main(args) == EXIT_OK
        assert stat.S_IMODE((tmp_path / "key.pem").stat().st_mode) == 0o600
