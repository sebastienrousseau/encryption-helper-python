# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Passphrase-protected PKCS#8 with a key-derivation cost that means something.

``cryptography``'s ``BestAvailableEncryption`` writes PKCS#8 protected by
PBKDF2-HMAC-SHA256 at **2,048 iterations**, and offers no way to raise that
for PKCS#8 (its ``encryption_builder`` covers only OpenSSH and PKCS#12). At
that cost a stolen key file can be guessed at roughly 300 times the rate the
current OWASP figure for PBKDF2-HMAC-SHA256 allows.

This module writes the same standard structure -- an RFC 5958
``EncryptedPrivateKeyInfo`` using RFC 8018 PBES2 -- with
:data:`PBKDF2_ITERATIONS` iterations. Nothing here is a new format or a new
primitive: the KDF and the cipher are ``cryptography``'s, the structure is the
one OpenSSL writes, and the output is read back by ``cryptography``'s own,
independent loader before it is ever returned to a caller (see
``keys/store.py``'s pair validation).

Why PBKDF2 and not scrypt: both load in ``cryptography``. But OpenSSL caps
scrypt at 32 MiB by default, below what a recommended scrypt cost needs, so
``openssl pkey`` -- and Java, which lacks scrypt PBES2 -- could not open the
file. A key a counterparty's tooling cannot read is not protected, it is lost.

Reading is another matter: a key protected elsewhere may use either KDF, and
both take their cost from the file. :func:`pbkdf2_iterations` and
:func:`scrypt_parameters` read that cost so the loader can refuse an absurd
one before any derivation runs (see :data:`MAX_ITERATIONS`,
:data:`MAX_SCRYPT_WORK` and :data:`MAX_SCRYPT_MEMORY`).

Secrets in memory: the passphrase, the derived key and the plaintext DER are
all immutable :class:`bytes`. Python offers no way to overwrite them, and the
interpreter may copy them, so they cannot be zeroised; they persist until the
garbage collector reuses the memory. Callers handling high-value keys should
keep the process short-lived and disable core dumps (``ulimit -c 0``,
``prctl(PR_SET_DUMPABLE, 0)``) and swap where they can.
"""

from __future__ import annotations

import base64
import os
from typing import Final, NamedTuple

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#: PBKDF2-HMAC-SHA256 iteration count for newly protected keys. The current
#: OWASP Password Storage figure for this PRF.
PBKDF2_ITERATIONS: Final = 600_000

#: Keys protected below this are reported as weak when loaded.
WEAK_ITERATIONS_BELOW: Final = 100_000

#: Keys demanding more than this are refused before any derivation runs. The
#: count is read from the file, so without a ceiling a crafted key costs its
#: loader whatever it asks: 2**31 iterations is minutes of CPU per attempt.
#: Ten million is more than sixteen times what this package writes.
MAX_ITERATIONS: Final = 10_000_000

#: scrypt work (N * r * p, in units of one BlockMix of 128 * r bytes) above
#: which a key is refused before derivation. scrypt's cost is also read from
#: the file, and unlike PBKDF2 it has two dimensions: a wrong passphrase on
#: N=2**14, r=8, p=1000 cost 17 s of CPU, and N=2**16, r=1024 cost 11 s and
#: 8 GiB. 2**23 is exactly N=2**20, r=8, p=1 -- the strongest parameters in
#: common use (the scrypt paper's file-encryption figure), about 1.5 s here
#: -- and 64 times OpenSSL's ``pkcs8 -scrypt`` default of N=16384, r=8, p=1.
MAX_SCRYPT_WORK: Final = 2**23

#: scrypt memory (128 * N * r bytes) above which a key is refused. 1 GiB is
#: what N=2**20, r=8 needs; anything beyond it is a request to exhaust the
#: loader's memory, not a protection anyone's tooling writes by default.
#: With p >= 1 the work cap already implies this one (memory <= 128 * work);
#: it is checked separately so that raising the work cap -- say, for large p
#: -- can never quietly admit a key that needs gigabytes.
MAX_SCRYPT_MEMORY: Final = 2**30

_SALT_SIZE: Final = 16
_IV_SIZE: Final = 16
_KEY_SIZE: Final = 32

_OID_PBES2: Final = "1.2.840.113549.1.5.13"
_OID_PBKDF2: Final = "1.2.840.113549.1.5.12"
_OID_SCRYPT: Final = "1.3.6.1.4.1.11591.4.11"
_OID_HMAC_SHA256: Final = "1.2.840.113549.2.9"
_OID_AES256_CBC: Final = "2.16.840.1.101.3.4.1.42"

_TAG_INTEGER: Final = 0x02
_TAG_OCTETS: Final = 0x04
_TAG_NULL: Final = 0x05
_TAG_OID: Final = 0x06
_TAG_SEQUENCE: Final = 0x30
_SHORT_FORM_LIMIT: Final = 0x80
_PEM_LINE: Final = 64


# --- DER encoding: the four types this structure needs, nothing more -----


def _length(size: int) -> bytes:
    if size < _SHORT_FORM_LIMIT:
        return bytes([size])
    body = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([_SHORT_FORM_LIMIT | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _length(len(body)) + body


def _sequence(*parts: bytes) -> bytes:
    return _tlv(_TAG_SEQUENCE, b"".join(parts))


def _integer(value: int) -> bytes:
    # One leading zero bit keeps a non-negative value non-negative in DER.
    return _tlv(_TAG_INTEGER, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def _oid(dotted: str) -> bytes:
    arcs = [int(arc) for arc in dotted.split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        remaining = arc
        chunk = [remaining & 0x7F]
        remaining >>= 7
        while remaining:
            chunk.append(0x80 | (remaining & 0x7F))
            remaining >>= 7
        body.extend(reversed(chunk))
    return _tlv(_TAG_OID, bytes(body))


def protect(pkcs8_der: bytes, passphrase: bytes) -> bytes:
    """Wrap an unencrypted PKCS#8 key as a PBES2 ``EncryptedPrivateKeyInfo``.

    Args:
        pkcs8_der: The unencrypted ``PrivateKeyInfo``, DER encoded.
        passphrase: Non-empty passphrase bytes.

    Returns:
        The DER-encoded ``EncryptedPrivateKeyInfo``.
    """
    salt = os.urandom(_SALT_SIZE)
    iv = os.urandom(_IV_SIZE)
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    ).derive(passphrase)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(pkcs8_der) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    kdf = _sequence(
        _oid(_OID_PBKDF2),
        _sequence(
            _tlv(_TAG_OCTETS, salt),
            _integer(PBKDF2_ITERATIONS),
            _sequence(_oid(_OID_HMAC_SHA256), _tlv(_TAG_NULL, b"")),
        ),
    )
    scheme = _sequence(_oid(_OID_AES256_CBC), _tlv(_TAG_OCTETS, iv))
    algorithm = _sequence(_oid(_OID_PBES2), _sequence(kdf, scheme))
    return _sequence(algorithm, _tlv(_TAG_OCTETS, ciphertext))


def to_pem(der: bytes) -> bytes:
    """PEM-encode an ``EncryptedPrivateKeyInfo``, as RFC 7468 specifies."""
    text = base64.b64encode(der).decode("ascii")
    lines = [text[i : i + _PEM_LINE] for i in range(0, len(text), _PEM_LINE)]
    body = "\n".join(lines)
    return (
        f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{body}\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n"
    ).encode("ascii")


# --- Reading back the KDF cost, for the warning and the ceiling ------------


def der_from_pem(data: bytes) -> bytes | None:
    """Return the DER inside an ``ENCRYPTED PRIVATE KEY`` PEM block, if any."""
    begin = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
    end = b"-----END ENCRYPTED PRIVATE KEY-----"
    start = data.find(begin)
    stop = data.find(end)
    if start < 0 or stop < start:
        return None
    try:
        body = b"".join(data[start + len(begin) : stop].split())
        return base64.b64decode(body, validate=True) or None
    except ValueError:
        return None


def _read(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one TLV at ``offset``; return ``(tag, body, next_offset)``.

    Raises:
        ValueError: On any malformed or truncated encoding.
    """
    if offset + 2 > len(data):
        raise ValueError
    tag = data[offset]
    first = data[offset + 1]
    offset += 2
    if first < _SHORT_FORM_LIMIT:
        size = first
    else:
        count = first & 0x7F
        if not 0 < count <= 4 or offset + count > len(data):  # noqa: PLR2004
            raise ValueError
        size = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    end = offset + size
    if end > len(data):
        raise ValueError
    return tag, data[offset:end], end


class ScryptParameters(NamedTuple):
    """The cost parameters of a scrypt-protected key (RFC 7914 section 7.1)."""

    cost: int
    block_size: int
    parallelization: int

    @property
    def work(self) -> int:
        """``N * r * p``: what one derivation costs in CPU, linearly."""
        return self.cost * self.block_size * self.parallelization

    @property
    def memory(self) -> int:
        """``128 * N * r``: the bytes one derivation must hold at once."""
        return 128 * self.cost * self.block_size


def _kdf_parameters(der: bytes, kdf_oid: str) -> bytes | None:
    """Return the PBES2 KDF parameters body if the KDF is ``kdf_oid``.

    Raises:
        ValueError: On any malformed or truncated encoding.
    """
    _, outer, _ = _read(der, 0)
    _, algorithm, _ = _read(outer, 0)
    _, scheme_oid, after = _read(algorithm, 0)
    if scheme_oid != _oid(_OID_PBES2)[2:]:
        return None
    _, params, _ = _read(algorithm, after)
    _, kdf, _ = _read(params, 0)
    _, found_oid, after = _read(kdf, 0)
    if found_oid != _oid(kdf_oid)[2:]:
        return None
    _, kdf_params, _ = _read(kdf, after)
    return kdf_params


def _positive_integer(data: bytes, offset: int) -> tuple[int | None, int]:
    """Read an INTEGER; :data:`None` if it is another type or not positive.

    Raises:
        ValueError: On any malformed or truncated encoding.
    """
    tag, body, after = _read(data, offset)
    if tag != _TAG_INTEGER or not body:
        return None, after
    value = int.from_bytes(body, "big", signed=True)
    return (value if value > 0 else None), after


def pbkdf2_iterations(der: bytes) -> int | None:
    """Return the PBKDF2 iteration count protecting a PKCS#8 key, if any.

    Feeds the weak-key warning and the cost ceiling. Returns :data:`None` for
    anything that is not PBES2 with PBKDF2 -- an unencrypted key, scrypt, or
    input it cannot parse -- rather than raising: loading the key is the
    loader's job, and this must never be the reason a valid key fails to load.
    """
    try:
        kdf_params = _kdf_parameters(der, _OID_PBKDF2)
        if kdf_params is None:
            return None
        _, _salt, after = _read(kdf_params, 0)
        tag, count, _ = _read(kdf_params, after)
    except ValueError:
        return None
    if tag != _TAG_INTEGER:
        return None
    return int.from_bytes(count, "big")


def scrypt_parameters(der: bytes) -> ScryptParameters | None:
    """Return the scrypt cost parameters protecting a PKCS#8 key, if any.

    Feeds the cost ceiling only. Like :func:`pbkdf2_iterations` it answers
    :data:`None` -- never raises -- for anything that is not PBES2 with scrypt
    or that it cannot parse, including a parameter that is not a positive
    INTEGER: ``cryptography`` rejects such a key itself, and this must never
    be the reason a key it accepts fails to load.
    """
    try:
        kdf_params = _kdf_parameters(der, _OID_SCRYPT)
        if kdf_params is None:
            return None
        tag, _salt, after = _read(kdf_params, 0)
        if tag != _TAG_OCTETS:
            return None
        cost, after = _positive_integer(kdf_params, after)
        block_size, after = _positive_integer(kdf_params, after)
        parallelization, _ = _positive_integer(kdf_params, after)
    except ValueError:
        return None
    if cost is None or block_size is None or parallelization is None:
        return None
    return ScryptParameters(cost, block_size, parallelization)
