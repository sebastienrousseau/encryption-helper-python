# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Every read of caller-named input is bounded by bytes read, not by stat().

The CLI used to size-check with ``stat().st_size`` and then read the whole
file. A FIFO, a character device and a process substitution all report a
size of 0, so ``--in <(cmd)`` and ``--passphrase-file /dev/zero`` read
without limit, and ``--max-size -2`` turned the limit into ``read(-1)``. Key
files had no limit at all, and the KDF cost of an encrypted key was taken
from the file unchecked.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from encryption_helper._io import InputTooLargeError, read_bytes
from encryption_helper.cli import EXIT_USAGE, main
from encryption_helper.errors import KeyReadError
from encryption_helper.keys import _pkcs8, load
from encryption_helper.keys.generate import generate_ed25519
from encryption_helper.keys.load import (
    MAX_BCRYPT_ROUNDS,
    MAX_KEY_FILE_BYTES,
    load_private_key,
    load_private_key_file,
    load_public_key_file,
)

from ._support import posix_only

DEV_ZERO = "/dev/zero"


class TestReadBytesLimit:
    def test_exactly_the_limit_is_accepted(self, tmp_path):
        source = tmp_path / "f"
        source.write_bytes(b"x" * 10)
        assert read_bytes(source, limit=10) == b"x" * 10

    def test_one_byte_over_is_refused(self, tmp_path):
        source = tmp_path / "f"
        source.write_bytes(b"x" * 11)
        with pytest.raises(InputTooLargeError) as info:
            read_bytes(source, limit=10)
        assert info.value.limit == 10
        assert isinstance(info.value, KeyReadError)

    @posix_only
    def test_a_device_reporting_size_zero_is_still_bounded(self):
        with pytest.raises(InputTooLargeError):
            read_bytes(DEV_ZERO, limit=4096)

    def test_without_a_limit_behaviour_is_unchanged(self, tmp_path):
        source = tmp_path / "f"
        source.write_bytes(b"x" * 100)
        assert read_bytes(source) == b"x" * 100


class TestKeyFiles:
    def test_an_oversized_key_file_is_refused_unread(self, tmp_path):
        source = tmp_path / "huge.pem"
        source.write_bytes(b"-" * (MAX_KEY_FILE_BYTES + 1))
        with pytest.raises(InputTooLargeError):
            load_public_key_file(source)
        with pytest.raises(InputTooLargeError):
            load_private_key_file(source)

    @posix_only
    def test_a_key_path_to_dev_zero_fails_fast(self):
        with pytest.raises(InputTooLargeError):
            load_public_key_file(DEV_ZERO)


def _pkcs8_with_iterations(monkeypatch, iterations: int) -> bytes:
    der = generate_ed25519().private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    monkeypatch.setattr(_pkcs8, "PBKDF2_ITERATIONS", iterations)
    return _pkcs8.protect(der, b"passphrase")


def _no_derivation(monkeypatch):
    """Fail the test if a decryption -- and so a derivation -- is attempted."""

    def forbidden(*_args, **_kwargs):
        pytest.fail("the key derivation ran")

    for name in ("load_pem_private_key", "load_der_private_key"):
        monkeypatch.setattr(load.serialization, name, forbidden)


class TestKdfCostCeiling:
    def test_pkcs8_above_the_ceiling_is_refused_before_deriving(self, monkeypatch):
        blob = _pkcs8_with_iterations(monkeypatch, _pkcs8.MAX_ITERATIONS + 1)
        _no_derivation(monkeypatch)
        with pytest.raises(KeyReadError, match="PBKDF2 iterations"):
            load_private_key(blob, passphrase=b"passphrase")

    def test_pem_wrapped_pkcs8_is_checked_too(self, monkeypatch):
        blob = _pkcs8_with_iterations(monkeypatch, _pkcs8.MAX_ITERATIONS + 1)
        pem = _pkcs8.to_pem(blob)
        _no_derivation(monkeypatch)
        with pytest.raises(KeyReadError, match="PBKDF2 iterations"):
            load_private_key(pem, passphrase=b"passphrase")

    def test_the_default_protection_is_far_below_the_ceiling(self):
        assert _pkcs8.PBKDF2_ITERATIONS * 16 < _pkcs8.MAX_ITERATIONS

    def test_a_key_at_the_ceiling_is_parsed_not_refused(self, monkeypatch):
        """At the ceiling the check passes; only the derivation is stubbed."""
        blob = _pkcs8_with_iterations(monkeypatch, _pkcs8.MAX_ITERATIONS)
        _no_derivation(monkeypatch)
        with pytest.raises(pytest.fail.Exception, match="derivation ran"):
            load_private_key(blob, passphrase=b"passphrase")

    @staticmethod
    def _openssh(rounds: int) -> bytes:
        def string(value: bytes) -> bytes:
            return len(value).to_bytes(4, "big") + value

        options = string(b"s" * 16) + rounds.to_bytes(4, "big")
        raw = (
            b"openssh-key-v1\x00"
            + string(b"aes256-ctr")
            + string(b"bcrypt")
            + string(options)
            + (1).to_bytes(4, "big")
        )
        body = base64.b64encode(raw)
        return (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + body
            + b"\n-----END OPENSSH PRIVATE KEY-----\n"
        )

    def test_openssh_rounds_above_the_ceiling_are_refused(self, monkeypatch):
        def forbidden(*_args, **_kwargs):
            pytest.fail("bcrypt ran")

        monkeypatch.setattr(load.serialization, "load_ssh_private_key", forbidden)
        with pytest.raises(KeyReadError, match="bcrypt rounds"):
            load_private_key(
                self._openssh(MAX_BCRYPT_ROUNDS + 1), passphrase=b"passphrase"
            )

    def test_openssh_rounds_are_read_from_the_wire_format(self):
        assert load._openssh_bcrypt_rounds(self._openssh(16)) == 16
        assert load._openssh_bcrypt_rounds(b"not a key") is None

    def test_no_passphrase_means_no_derivation_and_no_check(self, monkeypatch):
        blob = _pkcs8_with_iterations(monkeypatch, _pkcs8.MAX_ITERATIONS + 1)
        with pytest.raises(KeyReadError, match="no passphrase was supplied"):
            load_private_key(blob)


@pytest.fixture
def signing_key(tmp_path) -> Path:
    assert main(["keygen", "--algorithm", "ed25519", "--out-dir", str(tmp_path),
                 "--no-passphrase"]) == 0  # fmt: skip
    return tmp_path / "key.pem"


class TestCliLimits:
    @pytest.mark.parametrize("value", ["0", "-2"])
    def test_max_size_must_be_positive(self, signing_key, tmp_path, value):
        with pytest.raises(SystemExit) as info:
            main(["sign", "--private-key", str(signing_key), "--in",
                  str(signing_key), "--out", str(tmp_path / "s"),
                  "--max-size", value])  # fmt: skip
        assert info.value.code == EXIT_USAGE

    @posix_only
    def test_input_from_a_device_is_bounded(self, signing_key, tmp_path, capsys):
        with pytest.raises(SystemExit) as info:
            main(["sign", "--private-key", str(signing_key), "--in", DEV_ZERO,
                  "--out", str(tmp_path / "s"), "--max-size", "4096"])  # fmt: skip
        assert info.value.code == EXIT_USAGE
        assert "4096-byte limit" in capsys.readouterr().err

    @posix_only
    def test_input_from_a_fifo_within_the_limit_still_works(
        self, signing_key, tmp_path
    ):
        """Bounding the read must not break the documented <(cmd) usage."""
        import threading

        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)

        def feed() -> None:
            with fifo.open("wb") as writer:
                writer.write(b"message")

        writer = threading.Thread(target=feed)
        writer.start()
        try:
            code = main(["sign", "--private-key", str(signing_key), "--in",
                         str(fifo), "--out", str(tmp_path / "s")])  # fmt: skip
        finally:
            writer.join(timeout=10)
        assert code == 0

    @posix_only
    def test_passphrase_file_from_a_device_is_bounded(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as info:
            main(["keygen", "--algorithm", "ed25519", "--out-dir", str(tmp_path),
                  "--passphrase-file", DEV_ZERO])  # fmt: skip
        assert info.value.code == EXIT_USAGE
        assert "byte limit" in capsys.readouterr().err
