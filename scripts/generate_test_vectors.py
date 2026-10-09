# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Generate the frozen known-answer vectors in ``tests/vectors/v1.json``.

Run this ONLY when introducing a new container version. The point of the
vectors is that they never change: they are ciphertexts written by a past
build, and ``tests/crypto/test_vectors.py`` proves the current build still
reads them. Regenerating them after a change to the KDF ``info`` string, the
associated-data layout or the nonce construction would hide exactly the
regression they exist to catch -- every container already in the field
would become unreadable while the tests stayed green.

Usage::

    python scripts/generate_test_vectors.py > tests/vectors/v1.json

The private keys are generated for this file and protect nothing. They are
stored as hex DER rather than PEM so secret scanners, correctly, do not have
to be told to ignore a ``BEGIN PRIVATE KEY`` block in the repository.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sys

from cryptography.hazmat.primitives import serialization
from encryption_helper.crypto.envelope import encrypt
from encryption_helper.crypto.streaming import MIN_SEGMENT_SIZE, encrypt_stream
from encryption_helper.keys.generate import (
    generate_mlkem,
    generate_rsa,
    generate_x25519,
)

#: Three segments at the minimum size: two full and one partial, so the
#: vectors exercise the counter and the final flag, not just segment 0.
STREAM_PLAINTEXT_SIZE = 2 * MIN_SEGMENT_SIZE + 100
ONE_SHOT_PLAINTEXT = b"encryption-helper v1 known-answer vector"
ASSOCIATED_DATA = b"context: tests/vectors/v1.json"


def stream_plaintext() -> bytes:
    """Return the streaming plaintext. A formula, so it need not be stored."""
    return bytes(i % 251 for i in range(STREAM_PLAINTEXT_SIZE))


def _der_hex(private_key: object) -> str:
    return private_key.private_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).hex()


def main() -> None:
    """Write the vector document to stdout."""
    keys = {
        "rsa-oaep-sha256": generate_rsa(key_size=2048),
        "ml-kem-768": generate_mlkem(level=768),
        "ml-kem-1024": generate_mlkem(level=1024),
        "x25519-hkdf": generate_x25519(),
    }
    vectors = []
    for kem, key in keys.items():
        public = key.public_key()
        der = _der_hex(key)
        for aad in (b"", ASSOCIATED_DATA):
            vectors.append(
                {
                    "name": f"{kem}/one-shot{'/aad' if aad else ''}",
                    "mode": "one-shot",
                    "private_key_der": der,
                    "associated_data": aad.decode(),
                    "plaintext": ONE_SHOT_PLAINTEXT.decode(),
                    "container": base64.b64encode(
                        encrypt(public, ONE_SHOT_PLAINTEXT, associated_data=aad)
                    ).decode(),
                }
            )
        out = io.BytesIO()
        plaintext = stream_plaintext()
        encrypt_stream(
            public,
            io.BytesIO(plaintext),
            out,
            associated_data=ASSOCIATED_DATA,
            segment_size=MIN_SEGMENT_SIZE,
        )
        vectors.append(
            {
                "name": f"{kem}/stream/aad",
                "mode": "stream",
                "private_key_der": der,
                "associated_data": ASSOCIATED_DATA.decode(),
                "plaintext_size": len(plaintext),
                "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
                "container": base64.b64encode(out.getvalue()).decode(),
            }
        )
    document = {
        "description": (
            "Frozen encryption-helper container version 1 vectors. Never "
            "regenerate: see scripts/generate_test_vectors.py."
        ),
        "container_version": 1,
        "vectors": vectors,
    }
    json.dump(document, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
