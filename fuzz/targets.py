# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Fuzz targets shared by the standalone runner and Atheris.

Each target takes a `bytes` input and returns None, raising only if it finds a
genuine defect. Expected, typed failures are swallowed; anything else
propagates.
"""

from __future__ import annotations

import functools

from encryption_helper import (
    DecryptionError,
    KeyReadError,
    decrypt,
    encrypt,
    generate_rsa,
    load_private_key,
    load_public_key,
)
from encryption_helper.cli import _strip_one_trailing_newline

#: Generated once: RSA key generation is far too slow to do per-iteration, and
#: the key is not what is being fuzzed.
_KEY = functools.lru_cache(maxsize=1)(lambda: generate_rsa(key_size=2048))


class FuzzFindingError(AssertionError):
    """A fuzz target observed behaviour that should be impossible."""


def fuzz_decrypt(data: bytes) -> None:
    """`decrypt` must fail closed on any input, never with an untyped error."""
    try:
        decrypt(_KEY(), data)
    except DecryptionError:
        return  # Correct: fail closed.
    except Exception as exc:
        msg = (
            f"decrypt() raised {type(exc).__name__} instead of DecryptionError "
            f"for a {len(data)}-byte input"
        )
        raise FuzzFindingError(msg) from exc
    else:
        msg = (
            f"decrypt() returned a plaintext for a {len(data)}-byte input that "
            "was not produced by encrypt(). This would be a vulnerability."
        )
        raise FuzzFindingError(msg)


def fuzz_decrypt_mutated(data: bytes) -> None:
    """A real container, mutated. Must never yield plaintext."""
    if not data:
        return
    key = _KEY()
    blob = bytearray(encrypt(key.public_key(), b"canary plaintext"))

    # Use the fuzz input to drive the mutation.
    for index in range(0, len(data) - 1, 2):
        position = data[index] * 256 + data[index + 1]
        blob[position % len(blob)] ^= 0xFF

    mutated = bytes(blob)
    try:
        recovered = decrypt(key, mutated)
    except DecryptionError:
        return
    except Exception as exc:
        msg = f"mutated container raised {type(exc).__name__}, not DecryptionError"
        raise FuzzFindingError(msg) from exc

    if recovered != b"canary plaintext":
        msg = "a mutated container decrypted to different plaintext"
        raise FuzzFindingError(msg)
    # An even number of flips on the same byte restores the original, so an
    # identical plaintext here is legitimate.


def fuzz_load_public_key(data: bytes) -> None:
    """`load_public_key` must only ever raise KeyReadError."""
    try:
        load_public_key(data)
    except KeyReadError:
        return
    except Exception as exc:
        msg = f"load_public_key raised {type(exc).__name__}, not KeyReadError"
        raise FuzzFindingError(msg) from exc


def fuzz_load_private_key(data: bytes) -> None:
    """`load_private_key` must only ever raise KeyReadError."""
    try:
        load_private_key(data)
    except KeyReadError:
        return
    except Exception as exc:
        msg = f"load_private_key raised {type(exc).__name__}, not KeyReadError"
        raise FuzzFindingError(msg) from exc


def fuzz_strip_newline(data: bytes) -> None:
    """The passphrase-file normaliser is total and shortens by at most two."""
    try:
        result = _strip_one_trailing_newline(data)
    except Exception as exc:
        msg = f"_strip_one_trailing_newline raised {type(exc).__name__}"
        raise FuzzFindingError(msg) from exc

    if not 0 <= len(data) - len(result) <= 2:  # noqa: PLR2004
        msg = f"removed {len(data) - len(result)} bytes; at most 2 is allowed"
        raise FuzzFindingError(msg)
    if not data.startswith(result):
        msg = "result is not a prefix of the input"
        raise FuzzFindingError(msg)


#: Every target, by name.
TARGETS = {
    "decrypt": fuzz_decrypt,
    "decrypt_mutated": fuzz_decrypt_mutated,
    "load_public_key": fuzz_load_public_key,
    "load_private_key": fuzz_load_private_key,
    "strip_newline": fuzz_strip_newline,
}
