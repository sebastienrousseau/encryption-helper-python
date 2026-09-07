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
from importlib import metadata

from .crypto import decrypt, encrypt, is_valid_signature, sign, verify
from .errors import (
    DecryptionError,
    EncryptionHelperError,
    InvalidArgumentError,
    KeyExistsError,
    KeyGenerationError,
    KeyReadError,
    KeyWriteError,
    SignatureVerificationError,
    UnsupportedAlgorithmError,
)
from .keys import (
    KeyPairPaths,
    encode_private_key,
    encode_public_key,
    fingerprint_sha256,
    generate,
    generate_ecdsa,
    generate_ed25519,
    generate_rsa,
    load_private_key,
    load_private_key_file,
    load_public_key,
    load_public_key_file,
    write_key_pair,
)

try:
    __version__ = metadata.version("encryption-helper")
except metadata.PackageNotFoundError:  # pragma: no cover - source checkout
    __version__ = "0.0.0+unknown"

# A library configures no logging handlers of its own. Adding a NullHandler
# keeps "No handlers could be found" warnings away without imposing any output
# on the host application, which owns logging configuration.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "DecryptionError",
    "EncryptionHelperError",
    "InvalidArgumentError",
    "KeyExistsError",
    "KeyGenerationError",
    "KeyPairPaths",
    "KeyReadError",
    "KeyWriteError",
    "SignatureVerificationError",
    "UnsupportedAlgorithmError",
    "__version__",
    "decrypt",
    "encode_private_key",
    "encode_public_key",
    "encrypt",
    "fingerprint_sha256",
    "generate",
    "generate_ecdsa",
    "generate_ed25519",
    "generate_rsa",
    "is_valid_signature",
    "load_private_key",
    "load_private_key_file",
    "load_public_key",
    "load_public_key_file",
    "sign",
    "verify",
    "write_key_pair",
]
