# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Generate, protect and use asymmetric key pairs.

``encryption_helper`` is a small library and command-line tool for the everyday
asymmetric-cryptography tasks: creating key pairs, storing them safely,
encrypting data to a public key, and signing and verifying messages.

It is built on `cryptography <https://github.com/pyca/cryptography>`_ and adds
three things on top of it:

* **Safe defaults.** Private keys are written at mode ``0600`` inside a
  ``0700`` directory, are never printed or logged, and are never silently
  overwritten.
* **Correct constructions.** Encryption is hybrid -- AES-256-GCM under a
  content key wrapped with RSA-OAEP-SHA256 -- rather than the naive direct RSA
  encryption that fails or misleads on anything but tiny inputs.
* **Typed errors.** Everything this package raises deliberately derives from
  :class:`~encryption_helper.errors.EncryptionHelperError`, and no error
  message carries secret material.

Example:
    Generate a key pair, write it to disk, and round-trip a message::

        from pathlib import Path
        from encryption_helper import (
            decrypt,
            encrypt,
            fingerprint_sha256,
            generate_rsa,
            write_key_pair,
        )

        key = generate_rsa(key_size=3072)
        paths = write_key_pair(key, Path("./secrets"), name="service")
        print(paths.private_key, fingerprint_sha256(key.public_key()))

        blob = encrypt(key.public_key(), b"database password")
        assert decrypt(key, blob) == b"database password"

Security:
    This package protects key material on disk with filesystem permissions. It
    is not a substitute for a hardware security module or a managed KMS. If
    your threat model includes an attacker with root on the host, or you need
    keys that cannot be exported, use an HSM or KMS instead.

    See ``SECURITY.md`` for how to report a vulnerability.
"""

from __future__ import annotations

import logging

from .crypto import decrypt, encrypt, is_valid_signature, sign, verify
from .crypto.metadata import ContainerInfo, describe_container, is_container
from .errors import (
    DecryptionError,
    EncryptionHelperError,
    InvalidArgumentError,
    KeyExistsError,
    KeyGenerationError,
    KeyPairValidationError,
    KeyReadError,
    KeyWriteError,
    SignatureVerificationError,
    UnsupportedAlgorithmError,
)
from .inventory import Finding, classify, scan, summarise
from .keys import (
    POST_QUANTUM,
    QUANTUM_VULNERABLE,
    KeyGenerationResult,
    encode_private_key,
    encode_public_key,
    fingerprint_sha256,
    generate,
    generate_ecdsa,
    generate_ed448,
    generate_ed25519,
    generate_mldsa,
    generate_mlkem,
    generate_rsa,
    generate_x25519,
    load_private_key,
    load_private_key_file,
    load_public_key,
    load_public_key_file,
    write_key_pair,
)
from .policy import Posture, assess, horizon


def _resolve_version() -> str:
    """Read the installed version from package metadata.

    Deferred rather than computed at import time. ``importlib.metadata``
    costs about 8 ms to import -- it pulls in ``email.message`` and ``re`` --
    which was roughly a fifth of this package's total import cost, paid by
    every caller whether or not they ever asked for the version.
    """
    from importlib import metadata  # noqa: PLC0415

    try:
        return metadata.version("encryption-helper")
    except metadata.PackageNotFoundError:  # pragma: no cover - source checkout
        return "0.0.0+unknown"


def __getattr__(name: str) -> object:
    """Resolve ``__version__`` on first access.

    Raises:
        AttributeError: For any other name, as normal.
    """
    if name == "__version__":
        version = _resolve_version()
        globals()["__version__"] = version
        return version
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


# A library configures no logging handlers of its own. Adding a NullHandler
# keeps "No handlers could be found" warnings away without imposing any output
# on the host application, which owns logging configuration.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "POST_QUANTUM",
    "QUANTUM_VULNERABLE",
    "ContainerInfo",
    "DecryptionError",
    "EncryptionHelperError",
    "Finding",
    "InvalidArgumentError",
    "KeyExistsError",
    "KeyGenerationError",
    "KeyGenerationResult",
    "KeyPairValidationError",
    "KeyReadError",
    "KeyWriteError",
    "Posture",
    "SignatureVerificationError",
    "UnsupportedAlgorithmError",
    "__version__",
    "assess",
    "classify",
    "decrypt",
    "describe_container",
    "encode_private_key",
    "encode_public_key",
    "encrypt",
    "fingerprint_sha256",
    "generate",
    "generate_ecdsa",
    "generate_ed448",
    "generate_ed25519",
    "generate_mldsa",
    "generate_mlkem",
    "generate_rsa",
    "generate_x25519",
    "horizon",
    "is_container",
    "is_valid_signature",
    "load_private_key",
    "load_private_key_file",
    "load_public_key",
    "load_public_key_file",
    "scan",
    "sign",
    "summarise",
    "verify",
    "write_key_pair",
]
