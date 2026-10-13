# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Passphrase-protected keys must cost an attacker something.

``BestAvailableEncryption`` writes PKCS#8 with PBKDF2 at 2,048 iterations and
cannot be told otherwise. Keys are now written as the same standard PBES2
structure at :data:`PBKDF2_ITERATIONS`; these tests pin the parameters,
prove the output is read by independent loaders, and check that keys from
before the change still load -- with a warning that names the fix.
"""

from __future__ import annotations

import base64
import logging
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization
from encryption_helper import generate
from encryption_helper.cli import EXIT_OK, main
from encryption_helper.errors import KeyReadError
from encryption_helper.keys import _pkcs8
from encryption_helper.keys.load import load_private_key
from encryption_helper.keys.serialize import encode_private_key

PASSPHRASE = b"correct horse battery staple"
BEGIN = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
END = b"-----END ENCRYPTED PRIVATE KEY-----"
ALGORITHMS = ["rsa", "ecdsa", "ed25519", "ed448", "x25519", "mlkem", "mldsa"]


def _key(algorithm):
    return (
        generate(algorithm, key_size=2048)
        if algorithm == "rsa"
        else generate(algorithm)
    )


def _openssl_version():
    """``openssl version`` for the binary test_openssl_reads_it runs."""
    result = subprocess.run(
        ["openssl", "version"],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def _weak_pem(key):
    """A key as cryptography's default writes it: 2,048 iterations."""
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSPHRASE),
    )


class TestNewKeysAreStronglyProtected:
    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_pem_uses_the_configured_iteration_count(self, algorithm):
        pem = encode_private_key(_key(algorithm), passphrase=PASSPHRASE)
        assert pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
        der = _pkcs8.der_from_pem(pem)
        assert _pkcs8.pbkdf2_iterations(der) == _pkcs8.PBKDF2_ITERATIONS == 600_000

    def test_der_uses_the_configured_iteration_count(self):
        der = encode_private_key(_key("ed25519"), fmt="der", passphrase=PASSPHRASE)
        assert _pkcs8.pbkdf2_iterations(der) == 600_000

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_cryptographys_own_loader_reads_it_back(self, algorithm):
        """An independent decoder, not this module's, must accept the output."""
        key = _key(algorithm)
        pem = encode_private_key(key, passphrase=PASSPHRASE)
        loaded = serialization.load_pem_private_key(pem, password=PASSPHRASE)
        unencrypted = serialization.NoEncryption()
        assert loaded.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, unencrypted
        ) == key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, unencrypted
        )

    def test_a_wrong_passphrase_is_rejected(self):
        pem = encode_private_key(_key("ed25519"), passphrase=PASSPHRASE)
        with pytest.raises(KeyReadError):
            load_private_key(pem, passphrase=b"wrong")

    def test_salt_and_iv_are_fresh_each_time(self):
        key = _key("ed25519")
        first = encode_private_key(key, passphrase=PASSPHRASE)
        assert first != encode_private_key(key, passphrase=PASSPHRASE)

    def test_pem_lines_are_rfc_7468_width(self):
        pem = encode_private_key(_key("rsa"), passphrase=PASSPHRASE)
        body = pem.splitlines()[1:-1]
        assert all(len(line) <= 64 for line in body)
        assert all(len(line) == 64 for line in body[:-1])

    @pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
    @pytest.mark.parametrize("algorithm", ["rsa", "ecdsa", "ed25519"])
    def test_openssl_reads_it(self, algorithm, tmp_path):
        """The reason for PBKDF2 over scrypt: the counterparty's tools."""
        if algorithm == "ed25519" and "LibreSSL" in _openssl_version():
            # macOS ships LibreSSL 3.3 as /usr/bin/openssl, which cannot
            # parse Ed25519 keys at all, encrypted or not.
            pytest.skip("system openssl is LibreSSL, which lacks Ed25519")
        path = tmp_path / "key.pem"
        path.write_bytes(encode_private_key(_key(algorithm), passphrase=PASSPHRASE))
        result = subprocess.run(  # noqa: S603
            ["openssl", "pkey", "-in", str(path), "-passin", "env:EH_PASS", "-noout"],
            env={"EH_PASS": PASSPHRASE.decode(), "PATH": "/usr/bin:/bin"},
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


class TestExistingWeakKeys:
    def test_a_weak_key_still_loads_but_warns(self, caplog):
        caplog.set_level(logging.WARNING, logger="encryption_helper.keys.load")
        load_private_key(_weak_pem(_key("ed25519")), passphrase=PASSPHRASE)
        (record,) = caplog.records
        assert "2048 iterations" in record.getMessage()
        assert "convert --private" in record.getMessage()
        assert PASSPHRASE.decode() not in record.getMessage()

    def test_a_weak_der_key_warns_too(self, caplog):
        der = _key("ed25519").private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASSPHRASE),
        )
        caplog.set_level(logging.WARNING, logger="encryption_helper.keys.load")
        load_private_key(der, passphrase=PASSPHRASE)
        assert len(caplog.records) == 1

    @pytest.mark.parametrize("passphrase", [PASSPHRASE, None])
    def test_strong_and_unencrypted_keys_do_not_warn(self, caplog, passphrase):
        key = _key("ed25519")
        caplog.set_level(logging.WARNING, logger="encryption_helper.keys.load")
        load_private_key(
            encode_private_key(key, passphrase=passphrase), passphrase=passphrase
        )
        assert caplog.records == []

    def test_convert_upgrades_a_weak_key(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("EH_TEST_PASS", PASSPHRASE.decode())
        weak = tmp_path / "old.pem"
        weak.write_bytes(_weak_pem(_key("ed25519")))
        out = tmp_path / "new.pem"
        argv = ["-q", "convert", "--private", "--to", "pem", "--in", str(weak)]
        argv += ["--out", str(out), "--passphrase-env", "EH_TEST_PASS"]
        assert main(argv) == EXIT_OK
        der = _pkcs8.der_from_pem(out.read_bytes())
        assert _pkcs8.pbkdf2_iterations(der) == _pkcs8.PBKDF2_ITERATIONS


class TestIterationReaderNeverBreaksLoading:
    """It only feeds a warning, so it must answer None rather than raise."""

    def _strong_der(self):
        return encode_private_key(_key("ed25519"), fmt="der", passphrase=PASSPHRASE)

    @pytest.mark.parametrize("cut", [0, 1, 3, 10, 40])
    def test_truncated_input(self, cut):
        assert _pkcs8.pbkdf2_iterations(self._strong_der()[:cut]) is None

    def test_an_unencrypted_key(self):
        der = encode_private_key(_key("ed25519"), fmt="der")
        assert _pkcs8.pbkdf2_iterations(der) is None

    def test_an_absurd_length_field(self):
        assert _pkcs8.pbkdf2_iterations(b"\x30\x85\x01\x02\x03\x04\x05") is None

    def test_a_non_pbkdf2_kdf(self):
        """scrypt in place of PBKDF2: a valid key, just not one we can rate."""
        der = bytearray(self._strong_der())
        pbkdf2 = _pkcs8._oid(_pkcs8._OID_PBKDF2)
        start = bytes(der).find(pbkdf2)
        der[start + len(pbkdf2) - 1] ^= 0x01  # same length, different OID
        assert _pkcs8.pbkdf2_iterations(bytes(der)) is None

    def test_a_non_integer_iteration_field(self):
        der = bytearray(self._strong_der())
        count = _pkcs8._integer(_pkcs8.PBKDF2_ITERATIONS)
        start = bytes(der).find(count)
        der[start] = 0x04  # OCTET STRING where the INTEGER belongs
        assert _pkcs8.pbkdf2_iterations(bytes(der)) is None

    @pytest.mark.parametrize(
        "pem",
        [
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            BEGIN + b"\n!!!\n" + END,
            BEGIN + b"\n\n" + END,
            END + b"\n" + BEGIN + b"\n",
        ],
    )
    def test_pem_without_a_usable_encrypted_block(self, pem):
        assert _pkcs8.der_from_pem(pem) is None

    def test_pem_round_trip(self):
        der = self._strong_der()
        assert _pkcs8.der_from_pem(_pkcs8.to_pem(der)) == der
        assert base64.b64decode(b"".join(_pkcs8.to_pem(der).splitlines()[1:-1])) == der


class TestOpenSshKeepsItsOwnKdf:
    def test_without_bcrypt_the_error_names_the_remedy(self, monkeypatch):
        """It escaped as an untranslated exception: "unexpected internal error"."""
        from cryptography.exceptions import UnsupportedAlgorithm
        from encryption_helper.errors import UnsupportedAlgorithmError

        class NeedsBcrypt:
            def private_bytes(self, **_kwargs):
                raise UnsupportedAlgorithm("Need bcrypt module")

        with pytest.raises(UnsupportedAlgorithmError, match="pip install bcrypt"):
            encode_private_key(NeedsBcrypt(), fmt="openssh", passphrase=PASSPHRASE)

    def test_the_cli_reports_it_as_an_error_not_a_crash(
        self, tmp_path, monkeypatch, capsys
    ):
        try:
            import bcrypt  # noqa: F401
        except ImportError:
            pass
        else:  # pragma: no cover - bcrypt happens to be installed
            pytest.skip("bcrypt is installed, so the key is written")
        monkeypatch.setenv("EH_TEST_PASS", PASSPHRASE.decode())
        argv = ["keygen", "--algorithm", "ed25519", "--format", "openssh"]
        argv += ["--out-dir", str(tmp_path), "--passphrase-env", "EH_TEST_PASS"]
        assert main(argv) == 1
        err = capsys.readouterr().err
        assert "pip install bcrypt" in err
        assert "internal error" not in err


class TestNonPbes2Keys:
    def test_a_different_encryption_scheme_is_not_rated(self):
        der = bytearray(
            encode_private_key(_key("ed25519"), fmt="der", passphrase=PASSPHRASE)
        )
        pbes2 = _pkcs8._oid(_pkcs8._OID_PBES2)
        start = bytes(der).find(pbes2)
        der[start + len(pbes2) - 1] ^= 0x01  # PBES1-style: same length, other OID
        assert _pkcs8.pbkdf2_iterations(bytes(der)) is None


def _scrypt_pkcs8(  # noqa: PLR0913 - one argument per RFC 7914 parameter
    cost: int,
    block_size: int,
    parallelization: int,
    *,
    key_length: int | None = None,
    real: bool = True,
    passphrase: bytes = PASSPHRASE,
) -> bytes:
    """An RFC 7914 section 7.1 scrypt ``EncryptedPrivateKeyInfo``.

    ``cryptography`` cannot write one, so it is assembled here as OpenSSL's
    ``pkcs8 -topk8 -scrypt`` does. With ``real`` the ciphertext is a genuine
    encryption of an Ed25519 key, which costs one derivation; without it the
    ciphertext is random, for parameters too expensive to derive in a test.
    """
    import os

    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    salt, iv = os.urandom(16), os.urandom(16)
    if real:
        plain = _key("ed25519").private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key = Scrypt(
            salt=salt, length=32, n=cost, r=block_size, p=parallelization
        ).derive(passphrase)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
    else:
        ciphertext = os.urandom(64)
    fields = [
        _pkcs8._tlv(_pkcs8._TAG_OCTETS, salt),
        _pkcs8._integer(cost),
        _pkcs8._integer(block_size),
        _pkcs8._integer(parallelization),
    ]
    if key_length is not None:
        fields.append(_pkcs8._integer(key_length))
    kdf = _pkcs8._sequence(_pkcs8._oid(_pkcs8._OID_SCRYPT), _pkcs8._sequence(*fields))
    scheme = _pkcs8._sequence(
        _pkcs8._oid(_pkcs8._OID_AES256_CBC), _pkcs8._tlv(_pkcs8._TAG_OCTETS, iv)
    )
    algorithm = _pkcs8._sequence(
        _pkcs8._oid(_pkcs8._OID_PBES2), _pkcs8._sequence(kdf, scheme)
    )
    return _pkcs8._sequence(algorithm, _pkcs8._tlv(_pkcs8._TAG_OCTETS, ciphertext))


def _no_derivation(monkeypatch):
    """Fail the test if a decryption -- and so a derivation -- is attempted."""
    from encryption_helper.keys import load

    def forbidden(*_args, **_kwargs):
        pytest.fail("the key derivation ran")

    for name in ("load_pem_private_key", "load_der_private_key"):
        monkeypatch.setattr(load.serialization, name, forbidden)


# The measured abusive cases, plus one over each cap on its own.
_ABUSIVE_SCRYPT = [
    pytest.param(2**14, 8, 1000, id="p=1000"),
    pytest.param(2**16, 1024, 1, id="r=1024"),
    pytest.param(2**21, 8, 1, id="N=2**21"),
    pytest.param(2**20, 9, 1, id="N*r-just-over"),
    pytest.param(2**14, 8, 65, id="work-just-over"),
]


class TestScryptCostCeiling:
    """scrypt's cost is read from the file too, so it needs a ceiling.

    Before, only PBKDF2 was checked: N=2**14, r=8, p=1000 cost 17 s per load
    even with a wrong passphrase, and N=2**16, r=1024 cost 11 s and 8 GiB.
    """

    @pytest.mark.parametrize(("n", "r", "p"), _ABUSIVE_SCRYPT)
    @pytest.mark.parametrize("pem", [False, True], ids=["der", "pem"])
    def test_excessive_parameters_are_refused_before_deriving(
        self, monkeypatch, n, r, p, pem
    ):
        import time

        der = _scrypt_pkcs8(n, r, p, real=False)
        blob = _pkcs8.to_pem(der) if pem else der
        _no_derivation(monkeypatch)
        started = time.perf_counter()
        with pytest.raises(KeyReadError, match="scrypt N="):
            load_private_key(blob, passphrase=b"wrong")
        assert time.perf_counter() - started < 0.5

    @pytest.mark.parametrize("key_length", [None, 32])
    def test_openssl_default_parameters_load(self, key_length):
        """``openssl pkcs8 -scrypt`` writes N=16384, r=8, p=1."""
        der = _scrypt_pkcs8(2**14, 8, 1, key_length=key_length)
        assert _pkcs8.scrypt_parameters(der) == (2**14, 8, 1)
        key = load_private_key(_pkcs8.to_pem(der), passphrase=PASSPHRASE)
        assert type(key).__name__ == "Ed25519PrivateKey"
        with pytest.raises(KeyReadError, match="Could not load"):
            load_private_key(der, passphrase=b"wrong")

    @pytest.mark.parametrize(
        ("n", "r", "p"), [(2**20, 8, 1), (2**14, 8, 64), (2**13, 128, 1)]
    )
    def test_keys_at_the_ceiling_are_parsed_not_refused(self, monkeypatch, n, r, p):
        """At the caps the check passes; only the derivation is stubbed."""
        der = _scrypt_pkcs8(n, r, p, real=False)
        _no_derivation(monkeypatch)
        with pytest.raises(pytest.fail.Exception, match="derivation ran"):
            load_private_key(der, passphrase=PASSPHRASE)

    def test_memory_is_capped_on_its_own(self, monkeypatch):
        """Implied by the work cap today; enforced in case that is raised."""
        monkeypatch.setattr(_pkcs8, "MAX_SCRYPT_WORK", 2**40)
        der = _scrypt_pkcs8(2**20, 9, 1, real=False)
        _no_derivation(monkeypatch)
        with pytest.raises(KeyReadError, match="scrypt N="):
            load_private_key(der, passphrase=PASSPHRASE)

    def test_the_caps_admit_the_strong_common_choice_exactly(self):
        strong = _pkcs8.ScryptParameters(2**20, 8, 1)
        assert strong.work == _pkcs8.MAX_SCRYPT_WORK
        assert strong.memory == _pkcs8.MAX_SCRYPT_MEMORY

    def test_no_passphrase_means_no_check(self):
        der = _scrypt_pkcs8(2**14, 8, 1000, real=False)
        with pytest.raises(KeyReadError, match="no passphrase was supplied"):
            load_private_key(der)


class TestScryptReaderNeverBreaksLoading:
    """Unparseable scrypt parameters fall through to ``cryptography``."""

    def _fields(self, *values: bytes) -> bytes:
        # A scrypt key whose parameter fields are exactly ``values``.
        kdf = _pkcs8._sequence(
            _pkcs8._oid(_pkcs8._OID_SCRYPT), _pkcs8._sequence(*values)
        )
        scheme = _pkcs8._sequence(
            _pkcs8._oid(_pkcs8._OID_AES256_CBC),
            _pkcs8._tlv(_pkcs8._TAG_OCTETS, b"i" * 16),
        )
        algorithm = _pkcs8._sequence(
            _pkcs8._oid(_pkcs8._OID_PBES2), _pkcs8._sequence(kdf, scheme)
        )
        return _pkcs8._sequence(algorithm, _pkcs8._tlv(_pkcs8._TAG_OCTETS, b"c" * 64))

    @pytest.mark.parametrize("cut", [0, 1, 3, 10, 40, 60])
    def test_truncated_input(self, cut):
        der = _scrypt_pkcs8(2**14, 8, 1000, real=False)
        assert _pkcs8.scrypt_parameters(der[:cut]) is None

    def test_pbkdf2_and_unencrypted_keys_are_not_scrypt(self):
        strong = encode_private_key(_key("ed25519"), fmt="der", passphrase=PASSPHRASE)
        plain = encode_private_key(_key("ed25519"), fmt="der")
        assert _pkcs8.scrypt_parameters(strong) is None
        assert _pkcs8.scrypt_parameters(plain) is None
        assert _pkcs8.pbkdf2_iterations(_scrypt_pkcs8(2**14, 8, 1, real=False)) is None

    def test_salt_that_is_not_an_octet_string(self):
        integer = _pkcs8._integer
        der = self._fields(integer(1), integer(2**14), integer(8), integer(1))
        assert _pkcs8.scrypt_parameters(der) is None

    @pytest.mark.parametrize(
        "bad", [b"\x04\x01\x10", b"\x02\x01\xff", b"\x02\x01\x00", b"\x02\x00"]
    )
    def test_a_parameter_that_is_not_a_positive_integer(self, bad):
        salt = _pkcs8._tlv(_pkcs8._TAG_OCTETS, b"s" * 16)
        integer = _pkcs8._integer
        for position in range(3):
            fields = [integer(2**14), integer(8), integer(1000)]
            fields[position] = bad
            assert _pkcs8.scrypt_parameters(self._fields(salt, *fields)) is None

    def test_missing_parameters(self):
        salt = _pkcs8._tlv(_pkcs8._TAG_OCTETS, b"s" * 16)
        der = self._fields(salt, _pkcs8._integer(2**14))
        assert _pkcs8.scrypt_parameters(der) is None
