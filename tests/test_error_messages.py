# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Errors a person reads must be about their situation, not our internals.

Before: "Cannot encrypt to a Ed25519PublicKey" (a class name, wrong article);
a full disk reported as "unexpected internal error ... please report this"
with a traceback; and an encrypted key loaded without a passphrase described
as possibly corrupt.
"""

from __future__ import annotations

import logging

import pytest
from cryptography.hazmat.primitives.asymmetric import dsa, ec, x448
from encryption_helper import encrypt, generate, sign
from encryption_helper._labels import key_label
from encryption_helper.cli import EXIT_ERROR, EXIT_OK, main
from encryption_helper.errors import (
    InvalidArgumentError,
    KeyReadError,
    UnsupportedAlgorithmError,
)
from encryption_helper.keys.load import load_private_key
from encryption_helper.keys.serialize import encode_private_key


class TestKeyLabels:
    @pytest.mark.parametrize(
        ("algorithm", "kwargs", "expected"),
        [
            ("rsa", {"key_size": 2048}, "an RSA-2048 key"),
            ("ed25519", {}, "an Ed25519 key"),
            ("ed448", {}, "an Ed448 key"),
            ("x25519", {}, "an X25519 key"),
            ("mlkem", {}, "an ML-KEM-768 key"),
            ("mldsa", {}, "an ML-DSA-65 key"),
        ],
    )
    def test_generated_keys(self, algorithm, kwargs, expected):
        key = generate(algorithm, **kwargs)
        assert key_label(key) == expected
        assert key_label(key.public_key()) == expected

    @pytest.mark.parametrize(
        ("curve", "expected"),
        [
            (ec.SECP256R1(), "P-256"),
            (ec.SECP384R1(), "P-384"),
            (ec.SECP256K1(), "secp256k1"),
        ],
    )
    def test_curves_use_their_nist_names(self, curve, expected):
        assert key_label(ec.generate_private_key(curve)) == f"an ECDSA {expected} key"

    def test_other_parameter_sets_and_types(self):
        from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

        assert key_label(mlkem.MLKEM1024PrivateKey.generate()) == "an ML-KEM-1024 key"
        assert key_label(mldsa.MLDSA44PrivateKey.generate()) == "an ML-DSA-44 key"
        assert key_label(mldsa.MLDSA87PrivateKey.generate()) == "an ML-DSA-87 key"
        assert key_label(x448.X448PrivateKey.generate()) == "an X448 key"
        assert key_label(dsa.generate_private_key(2048)) == "a DSA key"

    def test_an_unknown_object_says_so(self):
        assert key_label(object()) == "a key of unsupported type object"


class TestMessagesNameAlgorithms:
    def test_encrypting_to_a_signing_key(self):
        with pytest.raises(InvalidArgumentError) as excinfo:
            encrypt(generate("ed25519").public_key(), b"x")
        assert "Cannot encrypt to an Ed25519 key." in str(excinfo.value)
        assert "PublicKey" not in str(excinfo.value)

    def test_signing_with_an_encryption_key(self):
        with pytest.raises(UnsupportedAlgorithmError) as excinfo:
            sign(generate("x25519"), b"x")
        assert "Cannot sign with an X25519 key." in str(excinfo.value)


class TestMissingPassphrase:
    def test_an_encrypted_key_without_a_passphrase_says_so(self):
        pem = encode_private_key(generate("ed25519"), passphrase=b"secret pass")
        with pytest.raises(
            KeyReadError, match="encrypted and no passphrase was supplied"
        ):
            load_private_key(pem)

    def test_a_wrong_passphrase_stays_indistinguishable_from_corruption(self):
        """Naming "wrong passphrase" would help someone probing a stolen key."""
        pem = encode_private_key(generate("ed25519"), passphrase=b"secret pass")
        with pytest.raises(
            KeyReadError,
            match="corrupt, in an unsupported format, or protected by a different",
        ):
            load_private_key(pem, passphrase=b"guess")

    def test_a_passphrase_for_an_unencrypted_key_is_the_generic_error(self):
        pem = encode_private_key(generate("ed25519"))
        with pytest.raises(KeyReadError, match="Could not load the private key"):
            load_private_key(pem, passphrase=b"not needed")


class TestOperatingSystemErrors:
    def _argv(self, tmp_path):
        main(
            [
                "-q",
                "keygen",
                "--algorithm",
                "x25519",
                "--no-passphrase",
                "--out-dir",
                str(tmp_path / "k"),
            ]
        )
        (tmp_path / "m").write_bytes(b"payload")
        return [
            "encrypt",
            "--public-key",
            str(tmp_path / "k" / "key.pub.pem"),
            "--in",
            str(tmp_path / "m"),
            "--out",
            str(tmp_path / "m.enc"),
        ]

    def test_a_full_disk_is_one_line_not_an_internal_error(
        self, tmp_path, monkeypatch, capsys
    ):
        argv = self._argv(tmp_path)
        capsys.readouterr()

        def full(*_args, **_kwargs):
            raise OSError(28, "No space left on device", str(tmp_path / "m.enc"))

        monkeypatch.setattr("encryption_helper.cli._commands.encrypt_stream", full)
        assert main(argv) == EXIT_ERROR
        err = capsys.readouterr().err
        assert err.strip() == f"error: No space left on device: {tmp_path / 'm.enc'}"

    def test_an_os_error_without_a_filename(self, tmp_path, monkeypatch, capsys):
        argv = self._argv(tmp_path)
        capsys.readouterr()

        def denied(*_args, **_kwargs):
            raise OSError(13, "Permission denied")

        monkeypatch.setattr("encryption_helper.cli._commands.encrypt_stream", denied)
        assert main(argv) == EXIT_ERROR
        assert capsys.readouterr().err.strip() == "error: Permission denied"

    def test_unexpected_errors_keep_the_traceback_out_of_default_output(
        self, tmp_path, monkeypatch, capsys, caplog
    ):
        argv = self._argv(tmp_path)
        capsys.readouterr()

        def bug(*_args, **_kwargs):
            raise RuntimeError("internal detail /secret/path")

        monkeypatch.setattr("encryption_helper.cli._commands.encrypt_stream", bug)
        caplog.set_level(logging.WARNING)
        assert main(argv) == EXIT_ERROR
        err = capsys.readouterr().err
        assert "unexpected internal error" in err
        assert "/secret/path" not in err
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_success_is_unaffected(self, tmp_path):
        assert main(self._argv(tmp_path)) == EXIT_OK
