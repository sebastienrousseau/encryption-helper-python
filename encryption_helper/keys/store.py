"""Writing key pairs to disk safely.

This module is the only place in the package that writes key material. It
exists so the permission and overwrite rules live in exactly one location
rather than being restated at each call site.

Private keys are written at mode ``0600`` inside a ``0700`` directory. Public
keys are written at ``0644``: they are meant to be shared, and treating them as
secret leads people to protect the wrong file.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from .._io import PUBLIC_FILE_MODE, SECRET_FILE_MODE, secure_write_bytes
from .serialize import encode_private_key, encode_public_key

__all__ = ["KeyPairPaths", "write_key_pair"]

#: Default stem for generated key files.
DEFAULT_KEY_NAME = "key"

_SUFFIXES = {
    "pem": (".pem", ".pub.pem"),
    "der": (".der", ".pub.der"),
    "openssh": ("", ".pub"),
}


class KeyPairPaths(NamedTuple):
    """Where a generated key pair was written.

    Attributes:
        private_key: Path of the private key file, mode ``0600``.
        public_key: Path of the public key file, mode ``0644``.
    """

    private_key: Path
    public_key: Path


def write_key_pair(  # noqa: PLR0913 - all but two are keyword-only options
    key: PrivateKeyTypes,
    directory: str | os.PathLike[str],
    *,
    name: str = DEFAULT_KEY_NAME,
    fmt: str = "pem",
    passphrase: bytes | None = None,
    overwrite: bool = False,
) -> KeyPairPaths:
    """Write a private key and its public half to ``directory``.

    The private key is written first. If that fails, no public key is left
    behind to imply a private key exists.

    Args:
        key: Private key to write. The public key is derived from it.
        directory: Destination directory. Created at mode ``0700`` if absent.
        name: Filename stem, for example ``"key"`` giving ``key.pem`` and
            ``key.pub.pem``.
        fmt: Output format, one of ``"pem"``, ``"der"``, ``"openssh"``.
        passphrase: Optional passphrase to encrypt the private key with.
        overwrite: Replace existing files, backing them up first. When
            :data:`False`, an existing file raises
            :class:`~encryption_helper.errors.KeyExistsError`.

    Returns:
        The paths written.

    Raises:
        KeyExistsError: If a destination exists and ``overwrite`` is false.
        KeyWriteError: If a file could not be written.
        UnsupportedAlgorithmError: If ``fmt`` is not valid for this key type.
        InvalidArgumentError: If ``passphrase`` is present but empty.
    """
    private_suffix, public_suffix = _SUFFIXES.get(fmt.strip().lower(), _SUFFIXES["pem"])
    base = Path(directory)

    private_bytes = encode_private_key(key, fmt=fmt, passphrase=passphrase)
    public_bytes = encode_public_key(key.public_key(), fmt=fmt)

    private_path = secure_write_bytes(
        base / f"{name}{private_suffix}",
        private_bytes,
        mode=SECRET_FILE_MODE,
        overwrite=overwrite,
    )
    public_path = secure_write_bytes(
        base / f"{name}{public_suffix}",
        public_bytes,
        mode=PUBLIC_FILE_MODE,
        overwrite=overwrite,
    )
    return KeyPairPaths(private_key=private_path, public_key=public_path)
