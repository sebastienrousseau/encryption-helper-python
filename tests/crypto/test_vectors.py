# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Known-answer tests: this build must read containers written by a past one.

Every other encryption test is a round trip through the current code, so it
passes whatever the format is. That is how a change to the HKDF ``info``
string, the associated-data layout or the nonce construction could ship with
a green suite while making every container already in the field unreadable.
These vectors were written once, by the build that defined container
version 1, and are never regenerated (see ``scripts/generate_test_vectors.py``).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import load_der_private_key
from encryption_helper.crypto.envelope import (
    AEAD_AES_256_GCM,
    AEAD_AES_256_GCM_STREAM,
    KEM_MLKEM768,
    KEM_MLKEM1024,
    KEM_RSA_OAEP_SHA256,
    KEM_X25519_HKDF,
    MAGIC,
    decrypt,
)
from encryption_helper.crypto.streaming import decrypt_stream
from encryption_helper.errors import DecryptionError

_DOCUMENT = json.loads(
    (Path(__file__).parent.parent / "vectors" / "v1.json").read_text(encoding="utf-8")
)
VECTORS = _DOCUMENT["vectors"]

#: The identifiers are part of the format. Pinning them here means
#: renumbering one fails loudly instead of silently misreading old files.
EXPECTED_KEM = {
    "rsa-oaep-sha256": KEM_RSA_OAEP_SHA256,
    "ml-kem-768": KEM_MLKEM768,
    "ml-kem-1024": KEM_MLKEM1024,
    "x25519-hkdf": KEM_X25519_HKDF,
}
EXPECTED_AEAD = {"one-shot": AEAD_AES_256_GCM, "stream": AEAD_AES_256_GCM_STREAM}


def _open(vector: dict, container: bytes) -> bytes:
    key = load_der_private_key(bytes.fromhex(vector["private_key_der"]), None)
    aad = vector["associated_data"].encode()
    if vector["mode"] == "one-shot":
        return decrypt(key, container, associated_data=aad)
    out = io.BytesIO()
    decrypt_stream(key, io.BytesIO(container), out, associated_data=aad)
    return out.getvalue()


def _ids(vector: dict) -> str:
    return vector["name"]


def test_the_vector_set_covers_every_mechanism_and_mode():
    covered = {(v["name"].split("/")[0], v["mode"]) for v in VECTORS}
    assert covered == {(k, m) for k in EXPECTED_KEM for m in EXPECTED_AEAD}
    assert _DOCUMENT["container_version"] == 1


@pytest.mark.parametrize("vector", VECTORS, ids=_ids)
def test_header_identifiers_are_unchanged(vector):
    container = base64.b64decode(vector["container"])
    assert container[:4] == MAGIC
    assert container[4] == _DOCUMENT["container_version"]
    assert container[5] == EXPECTED_KEM[vector["name"].split("/")[0]]
    assert container[6] == EXPECTED_AEAD[vector["mode"]]


@pytest.mark.parametrize("vector", VECTORS, ids=_ids)
def test_vector_decrypts_to_its_known_plaintext(vector):
    plaintext = _open(vector, base64.b64decode(vector["container"]))
    if vector["mode"] == "one-shot":
        assert plaintext == vector["plaintext"].encode()
    else:
        assert len(plaintext) == vector["plaintext_size"]
        assert hashlib.sha256(plaintext).hexdigest() == vector["plaintext_sha256"]


@pytest.mark.parametrize("vector", VECTORS, ids=_ids)
def test_a_flipped_bit_in_the_last_byte_is_rejected(vector):
    """The vectors are authenticated, so they cannot pass by accident."""
    container = bytearray(base64.b64decode(vector["container"]))
    container[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        _open(vector, bytes(container))


@pytest.mark.parametrize("vector", VECTORS, ids=_ids)
def test_wrong_associated_data_is_rejected(vector):
    altered = {**vector, "associated_data": vector["associated_data"] + "!"}
    with pytest.raises(DecryptionError):
        _open(altered, base64.b64decode(vector["container"]))
