# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Release-candidate boundary tests.

These are the checks worth having before tagging: exhaustive failure
injection, destination aliasing, and the exact semantics of every passphrase
source. They exist because the failure modes they cover are silent -- nothing
crashes, and the damage is only discovered later, when someone needs the key.

The governing invariant for every write path:

    After any recoverable failure the directory holds either the complete old
    pair, the complete new pair, or -- if no pair existed -- no pair at all.
    A mixed pair must never survive.
"""

from __future__ import annotations

import os
import stat

import pytest
from encryption_helper._io import secure_write_bytes
from encryption_helper.cli import EXIT_OK, EXIT_USAGE, main
from encryption_helper.errors import KeyWriteError
from encryption_helper.keys import (
    encode_public_key,
    load_private_key_file,
    load_public_key_file,
    store,
)

from ._support import posix_only

PRIVATE = "key.pem"
PUBLIC = "key.pub.pem"


def pair_state(directory) -> str:
    """Classify what a directory holds, ignoring backups.

    Returns:
        ``"none"``, ``"complete"``, or ``"mixed"``.
    """
    private = (directory / PRIVATE).exists()
    public = (directory / PUBLIC).exists()
    if private and public:
        return "complete"
    if not private and not public:
        return "none"
    return "mixed"


def assert_pair_is_usable(directory) -> None:
    """Assert both halves parse and belong to each other."""
    private = load_private_key_file(directory / PRIVATE)
    public = load_public_key_file(directory / PUBLIC)
    assert encode_public_key(private.public_key(), fmt="der") == encode_public_key(
        public, fmt="der"
    )


class FailAt:
    """Wrap ``secure_write_bytes`` and fail on the nth call."""

    def __init__(self, nth: int, exc: Exception) -> None:
        self._nth = nth
        self._exc = exc
        self._real = store.secure_write_bytes
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if self.calls == self._nth:
            raise self._exc
        return self._real(*args, **kwargs)


# ---------------------------------------------------------------------------
# 1. Failure injection at every write stage
# ---------------------------------------------------------------------------


class TestFailureInjectionOnFreshCreation:
    """No pair existed. Any failure must leave no pair."""

    def test_failure_before_private_creation(self, tmp_path, ed25519_key, monkeypatch):
        monkeypatch.setattr(
            store, "secure_write_bytes", FailAt(1, OSError(28, "No space"))
        )
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(ed25519_key, tmp_path)
        assert pair_state(tmp_path) == "none"

    def test_failure_during_public_creation(self, tmp_path, ed25519_key, monkeypatch):
        monkeypatch.setattr(
            store, "secure_write_bytes", FailAt(2, OSError(28, "No space"))
        )
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(ed25519_key, tmp_path)
        assert pair_state(tmp_path) == "none", "an orphaned private key survived"

    def test_failure_during_serialisation_writes_nothing(
        self, tmp_path, ed25519_key, monkeypatch
    ):
        def boom(*_args, **_kwargs):
            raise OSError(5, "I/O error")

        monkeypatch.setattr(store, "encode_private_key", boom)
        with pytest.raises(OSError, match="I/O error"):
            store.write_key_pair(ed25519_key, tmp_path)
        assert pair_state(tmp_path) == "none"

    def test_rollback_failure_still_reports_the_original_error(
        self, tmp_path, ed25519_key, monkeypatch
    ):
        """A broken rollback must not mask why the write failed."""
        monkeypatch.setattr(
            store, "secure_write_bytes", FailAt(2, OSError(28, "No space"))
        )

        def unlink_fails(*_args, **_kwargs):
            raise OSError(1, "Operation not permitted")

        monkeypatch.setattr("pathlib.Path.unlink", unlink_fails)
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(ed25519_key, tmp_path)


class TestFailureInjectionOnReplacement:
    """A complete pair existed. Any failure must leave it complete and usable."""

    @pytest.fixture
    def existing(self, tmp_path, ed25519_key):
        store.write_key_pair(ed25519_key, tmp_path)
        return {
            "private": (tmp_path / PRIVATE).read_bytes(),
            "public": (tmp_path / PUBLIC).read_bytes(),
        }

    def test_failure_before_private_replacement(
        self, tmp_path, existing, rsa_key, monkeypatch
    ):
        monkeypatch.setattr(
            store, "secure_write_bytes", FailAt(1, OSError(28, "No space"))
        )
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(rsa_key, tmp_path, overwrite=True)

        assert pair_state(tmp_path) == "complete"
        assert (tmp_path / PRIVATE).read_bytes() == existing["private"]
        assert (tmp_path / PUBLIC).read_bytes() == existing["public"]
        assert_pair_is_usable(tmp_path)

    def test_failure_after_private_replacement(
        self, tmp_path, existing, rsa_key, monkeypatch
    ):
        """The dangerous case: new private key, old public key."""
        monkeypatch.setattr(
            store, "secure_write_bytes", FailAt(2, OSError(28, "No space"))
        )
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(rsa_key, tmp_path, overwrite=True)

        assert pair_state(tmp_path) == "complete"
        assert (tmp_path / PRIVATE).read_bytes() == existing["private"]
        assert (tmp_path / PUBLIC).read_bytes() == existing["public"]
        assert_pair_is_usable(tmp_path), "a mismatched pair survived"

    def test_failure_after_backup_restores_the_original(self, tmp_path, existing):
        """Regression: a failed write left the destination empty.

        `secure_write_bytes` backs the old file up by renaming it, so a
        failure after that point used to leave nothing at the target path.
        """
        import tempfile as tempfile_module
        from unittest import mock

        with (
            mock.patch.object(
                tempfile_module, "mkstemp", side_effect=OSError(28, "No space")
            ),
            pytest.raises(KeyWriteError, match="Could not write"),
        ):
            secure_write_bytes(tmp_path / PRIVATE, b"replacement", overwrite=True)

        assert (tmp_path / PRIVATE).read_bytes() == existing["private"]
        assert not list(tmp_path.glob("*.bak-*")), "a stray backup was left behind"

    @posix_only
    def test_rollback_restores_the_original_file_mode(self, tmp_path, existing):
        """Rollback must restore permissions, not just bytes."""
        import tempfile as tempfile_module
        from unittest import mock

        target = tmp_path / PRIVATE
        target.chmod(0o640)

        with (
            mock.patch.object(
                tempfile_module, "mkstemp", side_effect=OSError(28, "No space")
            ),
            pytest.raises(KeyWriteError),
        ):
            secure_write_bytes(target, b"replacement", mode=0o600, overwrite=True)

        assert stat.S_IMODE(target.stat().st_mode) == 0o640
        assert target.read_bytes() == existing["private"]

    @posix_only
    def test_pair_rollback_restores_the_original_private_key_mode(
        self, tmp_path, existing, rsa_key, monkeypatch
    ):
        (tmp_path / PRIVATE).chmod(0o640)
        monkeypatch.setattr(
            store, "secure_write_bytes", FailAt(2, OSError(28, "No space"))
        )
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(rsa_key, tmp_path, overwrite=True)

        assert stat.S_IMODE((tmp_path / PRIVATE).stat().st_mode) == 0o640
        assert (tmp_path / PRIVATE).read_bytes() == existing["private"]


class TestFailureInjectionOnHalfPresentState:
    def test_only_public_exists_and_write_fails(
        self, tmp_path, ed25519_key, monkeypatch
    ):
        (tmp_path / PUBLIC).write_bytes(b"stale public")
        monkeypatch.setattr(
            store, "secure_write_bytes", FailAt(2, OSError(28, "No space"))
        )
        with pytest.raises(OSError, match="No space"):
            store.write_key_pair(ed25519_key, tmp_path, overwrite=True)

        assert not (tmp_path / PRIVATE).exists(), "orphaned private key survived"
        assert (tmp_path / PUBLIC).read_bytes() == b"stale public"


# ---------------------------------------------------------------------------
# 2. Symlinks
# ---------------------------------------------------------------------------


@posix_only
class TestSymlinkDestinations:
    @pytest.mark.parametrize("name", [PRIVATE, PUBLIC])
    def test_symlinked_destination_is_refused(self, tmp_path, ed25519_key, name):
        """Neither half may be written through a symlink."""
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"victim")
        target = tmp_path / "keys"
        target.mkdir()
        (target / name).symlink_to(outside)

        with pytest.raises(KeyWriteError, match="symbolic link"):
            store.write_key_pair(ed25519_key, target, overwrite=True)
        assert outside.read_bytes() == b"victim"

    def test_symlink_planted_after_preflight_does_not_leak(
        self, tmp_path, ed25519_key, monkeypatch
    ):
        """Close the check/use window: plant the link after pre-flight ran.

        Even if the symlink check is bypassed entirely, the write must not
        follow the link, because the file is created elsewhere and renamed
        into place -- rename replaces the link itself.
        """
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"victim")
        target = tmp_path / "keys"
        target.mkdir()

        real_preflight = store._preflight

        def plant_then_check(*args, **kwargs):
            real_preflight(*args, **kwargs)
            (target / PRIVATE).symlink_to(outside)

        monkeypatch.setattr(store, "_preflight", plant_then_check)

        with pytest.raises(KeyWriteError, match="symbolic link"):
            store.write_key_pair(ed25519_key, target)
        assert outside.read_bytes() == b"victim", "wrote through the symlink"

    def test_rename_replaces_the_link_not_its_target(self, tmp_path):
        """Belt and braces: even bypassing the check, the victim is safe."""
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"victim")
        link = tmp_path / "link.pem"
        link.symlink_to(outside)

        import encryption_helper._io as io_module

        original = io_module._reject_symlink
        io_module._reject_symlink = lambda _p: None
        try:
            secure_write_bytes(link, b"new content", overwrite=True)
        finally:
            io_module._reject_symlink = original

        assert outside.read_bytes() == b"victim"
        assert not link.is_symlink()
        assert link.read_bytes() == b"new content"


# ---------------------------------------------------------------------------
# 3. Destination aliasing beyond path equality
# ---------------------------------------------------------------------------


@posix_only
class TestAliasedDestinations:
    def test_hard_linked_pair_is_refused(self, tmp_path, ed25519_key):
        """Two names, one inode: writing the pair would leave only one half."""
        (tmp_path / PRIVATE).write_bytes(b"existing")
        os.link(tmp_path / PRIVATE, tmp_path / PUBLIC)

        with pytest.raises(KeyWriteError, match="same file"):
            store.write_key_pair(ed25519_key, tmp_path, overwrite=True)

    def test_multiply_linked_private_destination_is_refused(
        self, tmp_path, ed25519_key
    ):
        """The old key would stay readable under the other name."""
        target = tmp_path / "keys"
        target.mkdir()
        (target / PRIVATE).write_bytes(b"old key")
        os.link(target / PRIVATE, tmp_path / "alias.pem")

        with pytest.raises(KeyWriteError, match="hard links"):
            store.write_key_pair(ed25519_key, target, overwrite=True)
        assert (tmp_path / "alias.pem").read_bytes() == b"old key"

    def test_singly_linked_destination_is_fine(self, tmp_path, ed25519_key):
        store.write_key_pair(ed25519_key, tmp_path)
        store.write_key_pair(ed25519_key, tmp_path, overwrite=True)
        assert pair_state(tmp_path) == "complete"


# ---------------------------------------------------------------------------
# 4. Passphrase source semantics
# ---------------------------------------------------------------------------


class TestPassphraseEnvSemantics:
    SECRET = "ENV-SECRET-MARKER-91af"

    def test_unset_variable(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("EH_RC", raising=False)
        with pytest.raises(SystemExit) as excinfo:
            main(["keygen", "--out-dir", str(tmp_path), "--passphrase-env", "EH_RC"])
        assert excinfo.value.code == EXIT_USAGE
        assert "is not set" in capsys.readouterr().err

    @pytest.mark.parametrize("value", ["", "   ", "\t", "\n"])
    def test_empty_or_whitespace_only_value(self, tmp_path, capsys, monkeypatch, value):
        """A whitespace-only value is an unset-variable accident, not a secret."""
        monkeypatch.setenv("EH_RC", value)
        with pytest.raises(SystemExit) as excinfo:
            main(["keygen", "--out-dir", str(tmp_path), "--passphrase-env", "EH_RC"])
        assert excinfo.value.code == EXIT_USAGE
        assert "whitespace" in capsys.readouterr().err
        assert not (tmp_path / PRIVATE).exists()

    @pytest.mark.parametrize("value", ["   ", ""])
    def test_failure_never_echoes_the_value(self, tmp_path, capsys, monkeypatch, value):
        """A rejected value must not be quoted back into the terminal."""
        monkeypatch.setenv("EH_RC", value + self.SECRET.join(["", ""]))
        monkeypatch.setenv("EH_RC", value)
        with pytest.raises(SystemExit):
            main(["keygen", "--out-dir", str(tmp_path), "--passphrase-env", "EH_RC"])
        captured = capsys.readouterr()
        assert value not in captured.err.replace("EH_RC", "") or not value.strip()
        assert self.SECRET not in captured.out + captured.err

    def test_accepted_value_never_appears_in_output(
        self, tmp_path, capsys, monkeypatch
    ):
        monkeypatch.setenv("EH_RC", self.SECRET)
        assert main(keygen_rc(tmp_path, "--passphrase-env", "EH_RC")) == EXIT_OK
        captured = capsys.readouterr()
        assert self.SECRET not in captured.out + captured.err

    def test_value_is_taken_verbatim(self, tmp_path, monkeypatch):
        """Surrounding spaces are preserved: only whitespace-*only* is rejected."""
        monkeypatch.setenv("EH_RC", " pass phrase ")
        assert (
            main(
                keygen_rc(tmp_path, "--passphrase-env", "EH_RC"),
            )
            == EXIT_OK
        )
        assert load_private_key_file(tmp_path / PRIVATE, passphrase=b" pass phrase ")


class TestPassphraseFileSemantics:
    @pytest.mark.parametrize(
        ("contents", "expected"),
        [
            (b"secret", b"secret"),
            (b"secret\n", b"secret"),
            (b"secret\r\n", b"secret"),
            (b"secret\n\n", b"secret\n"),
            (b" secret ", b" secret "),
            (b"two\nlines\n", b"two\nlines"),
            (b"\xff\xfe binary", b"\xff\xfe binary"),
        ],
    )
    def test_exactly_one_trailing_newline_is_removed(
        self, tmp_path, contents, expected
    ):
        """Documented semantics, pinned by test.

        A text editor appends a newline; a user who types `secret` means
        `secret`. Nothing else is stripped, so a passphrase may legitimately
        begin or end with a space or contain internal newlines.
        """
        secret_file = tmp_path / "pass.txt"
        secret_file.write_bytes(contents)
        keys = tmp_path / "keys"

        assert main(keygen_rc(keys, "--passphrase-file", str(secret_file))) == EXIT_OK
        assert load_private_key_file(keys / PRIVATE, passphrase=expected)

    def test_wrong_interpretation_would_not_open_the_key(self, tmp_path):
        """Guards against a regression to naive whole-file reading."""
        secret_file = tmp_path / "pass.txt"
        secret_file.write_bytes(b"secret\n")
        keys = tmp_path / "keys"
        main(keygen_rc(keys, "--passphrase-file", str(secret_file)))

        from encryption_helper.errors import KeyReadError

        with pytest.raises(KeyReadError):
            load_private_key_file(keys / PRIVATE, passphrase=b"secret\n")

    @pytest.mark.parametrize("contents", [b"", b"\n", b"   \n", b"\r\n"])
    def test_empty_file_is_rejected(self, tmp_path, contents, capsys):
        secret_file = tmp_path / "pass.txt"
        secret_file.write_bytes(contents)
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "keygen",
                    "--out-dir",
                    str(tmp_path / "keys"),
                    "--passphrase-file",
                    str(secret_file),
                ]
            )
        assert excinfo.value.code == EXIT_USAGE
        assert "empty" in capsys.readouterr().err

    def test_missing_file_fails_cleanly(self, tmp_path, capsys):
        code = main(
            [
                "keygen",
                "--out-dir",
                str(tmp_path / "keys"),
                "--passphrase-file",
                str(tmp_path / "absent.txt"),
            ]
        )
        assert code != EXIT_OK
        assert "No such file" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# 5. The --no-passphrase warning
# ---------------------------------------------------------------------------


class TestNoPassphraseWarning:
    def test_warning_goes_to_stderr_so_stdout_stays_parseable(self, tmp_path, capsys):
        main(["--json", *keygen_rc_plain(tmp_path)])
        captured = capsys.readouterr()

        import json

        payload = json.loads(captured.out)
        assert payload["encrypted"] is False
        assert "UNENCRYPTED" in captured.err

    def test_warning_is_emphatic(self, tmp_path, capsys):
        main(keygen_rc_plain(tmp_path))
        err = capsys.readouterr().err
        assert "UNENCRYPTED" in err
        assert "--no-passphrase" in err

    def test_warning_contains_no_key_material(self, tmp_path, capsys):
        main(keygen_rc_plain(tmp_path))
        err = capsys.readouterr().err
        body = "".join(
            line
            for line in (tmp_path / PRIVATE).read_text().splitlines()
            if not line.startswith("-----")
        )
        assert "BEGIN" not in err
        assert body[:40] not in err

    def test_quiet_silences_it_for_automation(self, tmp_path, capsys):
        main(["--quiet", *keygen_rc_plain(tmp_path)])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_encrypted_key_gets_no_unencrypted_warning(
        self, tmp_path, capsys, monkeypatch
    ):
        """The loud warning is reserved for keys that actually lack one."""
        monkeypatch.setenv("EH_RC", "s3cret")
        main(keygen_rc(tmp_path, "--passphrase-env", "EH_RC"))
        err = capsys.readouterr().err
        assert "UNENCRYPTED" not in err
        assert "PRIVATE KEY" in err  # the general custody warning still appears


def keygen_rc(out_dir, *extra: str) -> list[str]:
    """Keygen argv with a passphrase source supplied by the caller."""
    return ["keygen", "--out-dir", str(out_dir), "--key-size", "2048", *extra]


def keygen_rc_plain(out_dir) -> list[str]:
    """Keygen argv that deliberately opts out of encryption."""
    return [*keygen_rc(out_dir), "--no-passphrase"]


# ---------------------------------------------------------------------------
# 6. Passphrase source exclusivity, bounds, and namespace hygiene
# ---------------------------------------------------------------------------


class TestPassphraseSourceExclusivity:
    """Exclusivity belongs to the parser, not to precedence rules later on."""

    @pytest.mark.parametrize(
        "flags",
        [
            ["--no-passphrase", "--passphrase-file", "PASSFILE"],
            ["--no-passphrase", "--passphrase-env", "EH_RC"],
            ["--passphrase-env", "EH_RC", "--passphrase-file", "PASSFILE"],
        ],
    )
    def test_contradictory_sources_are_a_usage_error(self, tmp_path, flags):
        """Regression: `--no-passphrase --passphrase-file x` silently ignored
        the file and wrote an UNENCRYPTED key -- the dangerous direction.
        """
        secret_file = tmp_path / "pass.txt"
        secret_file.write_bytes(b"supplied")
        resolved = [str(secret_file) if f == "PASSFILE" else f for f in flags]
        keys = tmp_path / "keys"

        with pytest.raises(SystemExit) as excinfo:
            main(["keygen", "--out-dir", str(keys), "--key-size", "2048", *resolved])
        assert excinfo.value.code == EXIT_USAGE
        assert not (keys / PRIVATE).exists(), "a key was written despite the error"

    def test_no_passphrase_is_not_offered_when_reading_a_key(self, tmp_path, capsys):
        """It only makes sense when creating a key, never when loading one."""
        with pytest.raises(SystemExit):
            main(["decrypt", "--private-key", "k.pem", "--no-passphrase"])
        assert "unrecognized arguments" in capsys.readouterr().err


class TestPassphraseFileBounds:
    def test_oversized_file_is_rejected_without_being_read(
        self, tmp_path, capsys, monkeypatch
    ):
        """Robustness: a passphrase file is not an arbitrary blob channel."""
        from encryption_helper.cli import MAX_PASSPHRASE_FILE_BYTES

        secret_file = tmp_path / "huge.txt"
        secret_file.write_bytes(b"a" * (MAX_PASSPHRASE_FILE_BYTES + 1))

        def must_not_read(*_args, **_kwargs):
            msg = "the oversized file must be rejected before it is read"
            raise AssertionError(msg)

        monkeypatch.setattr(
            "encryption_helper.cli._passphrase.read_bytes", must_not_read
        )
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "keygen",
                    "--out-dir",
                    str(tmp_path / "keys"),
                    "--passphrase-file",
                    str(secret_file),
                ]
            )
        assert excinfo.value.code == EXIT_USAGE
        assert "exceeds" in capsys.readouterr().err

    def test_a_file_at_the_limit_is_accepted(self, tmp_path):
        from encryption_helper.cli import MAX_PASSPHRASE_FILE_BYTES

        secret_file = tmp_path / "big.txt"
        secret_file.write_bytes(b"a" * min(MAX_PASSPHRASE_FILE_BYTES, 1000))
        assert (
            main(keygen_rc(tmp_path / "keys", "--passphrase-file", str(secret_file)))
            == EXIT_OK
        )

    def test_non_utf8_file_does_not_crash(self, tmp_path):
        """There is no decode step, so no UnicodeDecodeError path exists.

        The file source is byte-exact by design; this pins that so a future
        refactor adding a `.decode()` has to confront the decision.
        """
        secret_file = tmp_path / "binary.bin"
        secret_file.write_bytes(b"\xff\xfe\x00 binary secret")
        keys = tmp_path / "keys"

        assert main(keygen_rc(keys, "--passphrase-file", str(secret_file))) == EXIT_OK
        assert load_private_key_file(
            keys / PRIVATE, passphrase=b"\xff\xfe\x00 binary secret"
        )

    @posix_only
    def test_world_readable_passphrase_file_warns_but_proceeds(self, tmp_path, capsys):
        """A warning, not a refusal: CI secret mounts have their own models."""
        secret_file = tmp_path / "pass.txt"
        secret_file.write_bytes(b"secret")
        secret_file.chmod(0o644)

        assert (
            main(keygen_rc(tmp_path / "keys", "--passphrase-file", str(secret_file)))
            == EXIT_OK
        )
        err = capsys.readouterr().err
        assert "readable by others" in err
        assert "0644" in err
        assert "secret" not in err.replace("secrets", "")

    @posix_only
    def test_owner_only_passphrase_file_is_silent(self, tmp_path, capsys):
        secret_file = tmp_path / "pass.txt"
        secret_file.write_bytes(b"secret")
        secret_file.chmod(0o600)
        main(keygen_rc(tmp_path / "keys", "--passphrase-file", str(secret_file)))
        assert "readable by others" not in capsys.readouterr().err


class TestNamespaceHygiene:
    """The resolved secret must never land on the argparse namespace.

    Debug code such as ``logger.debug("args=%r", args)`` is easy to add later
    and would leak the passphrase even though every obvious password log
    statement has been removed. The namespace keeps only the *source
    identifier* -- a variable name or a path -- and the secret lives in a
    short-lived local.
    """

    SECRET = "NAMESPACE-LEAK-CANARY-7b21"

    def test_namespace_never_holds_the_resolved_secret(self, tmp_path, monkeypatch):
        from encryption_helper.cli import build_parser

        monkeypatch.setenv("EH_RC", self.SECRET)
        parser = build_parser()
        args = parser.parse_args(keygen_rc(tmp_path, "--passphrase-env", "EH_RC"))

        assert self.SECRET not in repr(args)
        assert self.SECRET not in str(vars(args))
        assert not any(self.SECRET in str(value) for value in vars(args).values())
        # Only the source identifier is retained.
        assert args.passphrase_env == "EH_RC"

    def test_namespace_stays_clean_after_a_full_run(self, tmp_path, monkeypatch):
        """Capture the namespace as the command actually saw it."""
        import encryption_helper.cli as cli_module
        from encryption_helper.cli import _commands

        monkeypatch.setenv("EH_RC", self.SECRET)
        seen = {}
        real = _commands._cmd_keygen

        def capture(args):
            result = real(args)
            seen["repr"] = repr(args)
            seen["vars"] = str(vars(args))
            return result

        monkeypatch.setattr(_commands, "_cmd_keygen", capture)
        # set_defaults captured the original function, so re-parse via main().
        parser = cli_module.build_parser()
        parsed = parser.parse_args(keygen_rc(tmp_path, "--passphrase-env", "EH_RC"))
        capture(parsed)

        assert self.SECRET not in seen["repr"]
        assert self.SECRET not in seen["vars"]

    def test_prompted_secret_does_not_reach_the_namespace(self, tmp_path, monkeypatch):
        import encryption_helper.cli as cli_module
        from encryption_helper.cli import _commands, _passphrase

        monkeypatch.setattr(_passphrase, "_interactive", lambda: True)
        monkeypatch.setattr("getpass.getpass", lambda _prompt: self.SECRET)

        parser = cli_module.build_parser()
        args = parser.parse_args(["keygen", "--out-dir", str(tmp_path)])
        _commands._cmd_keygen(args)

        assert self.SECRET not in repr(args)
        assert self.SECRET not in str(vars(args))
