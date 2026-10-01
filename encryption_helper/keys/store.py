# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Writing key pairs to disk safely.

This module is the only place in the package that writes key material, so the
permission and overwrite rules live in exactly one auditable location.

Private keys are written at mode ``0600`` inside a ``0700`` directory. Public
keys are written at ``0644``: they are meant to be shared, and treating them as
secret teaches people to protect the wrong file.

Writing a *pair* is the interesting part. Ordinary filesystems offer no
cross-file transaction, so this module approximates one:

1. **Pre-flight.** Both destinations are checked before anything is written, so
   the common conflict is caught before any file is touched.
2. **Validation.** The serialised bytes are parsed back and the public halves
   compared, so a mismatched pair can never reach the disk.
3. **Rollback.** If the second write fails, the first is undone -- removed if it
   was new, or restored from its backup if it replaced something.

The result is that a failure leaves either the previous state or the complete
new pair, never a private key whose public counterpart is missing or stale.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    mldsa,
    mlkem,
    rsa,
    x25519,
)
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from .._io import (
    PUBLIC_FILE_MODE,
    SECRET_FILE_MODE,
    WriteOutcome,
    resolve_destination,
    secure_write_bytes,
)
from ..errors import KeyExistsError, KeyPairValidationError, KeyWriteError
from .fingerprint import fingerprint_sha256
from .load import load_private_key, load_public_key
from .serialize import encode_private_key, encode_public_key

__all__ = ["DEFAULT_KEY_NAME", "KeyGenerationResult", "write_key_pair"]

#: Default stem for generated key files.
DEFAULT_KEY_NAME = "key"

_SUFFIXES = {
    "pem": (".pem", ".pub.pem"),
    "der": (".der", ".pub.der"),
    "openssh": ("", ".pub"),
}


@dataclass(frozen=True, slots=True)
class KeyGenerationResult:
    """Where a key pair was written, and safe metadata describing it.

    Note what this deliberately does *not* contain: the private key, the
    serialised private bytes, the passphrase, or any private RSA parameter.
    A caller cannot accidentally log a secret from this object, because the
    secret is not in it.

    Attributes:
        private_key_path: Path of the private key file, mode ``0600``.
        public_key_path: Path of the public key file, mode ``0644``.
        algorithm: Algorithm name, for example ``"rsa"`` or ``"ed25519"``.
        key_size: Modulus or curve size in bits, where the concept applies.
        fingerprint: SHA-256 fingerprint of the public key, matching
            ``ssh-keygen -lf``.
        private_key_encrypted: Whether the stored private key is passphrase
            protected.
        replaced: Whether existing files were replaced.
    """

    private_key_path: Path
    public_key_path: Path
    algorithm: str
    key_size: int | None
    fingerprint: str
    private_key_encrypted: bool
    replaced: bool = False


#: Key class -> (algorithm name, size). "Size" is a modulus for RSA, a curve
#: size for ECDSA, and a parameter set for the post-quantum algorithms, which
#: is what identifies the variant and what callers display.
_KEY_DESCRIPTIONS: tuple[tuple[type, str, int | None], ...] = (
    (ed25519.Ed25519PrivateKey, "ed25519", 256),
    (ed448.Ed448PrivateKey, "ed448", 448),
    (x25519.X25519PrivateKey, "x25519", 256),
    (mlkem.MLKEM768PrivateKey, "mlkem", 768),
    (mlkem.MLKEM1024PrivateKey, "mlkem", 1024),
    (mldsa.MLDSA44PrivateKey, "mldsa", 44),
    (mldsa.MLDSA65PrivateKey, "mldsa", 65),
    (mldsa.MLDSA87PrivateKey, "mldsa", 87),
)


def describe_key(key: PrivateKeyTypes) -> tuple[str, int | None]:
    """Return the algorithm name and size for a private key.

    Args:
        key: Key to describe.

    Returns:
        An ``(algorithm, size)`` pair. ``size`` is the RSA modulus, the ECDSA
        curve size, or the post-quantum parameter set, and is :data:`None` for
        a key type this package does not recognise.

    Example:
        >>> from encryption_helper.keys.generate import generate_mldsa
        >>> describe_key(generate_mldsa(level=65))
        ('mldsa', 65)
    """
    # RSA and ECDSA carry their size on the instance, so they are asked
    # directly rather than listed in the table.
    if isinstance(key, rsa.RSAPrivateKey):
        return "rsa", key.key_size
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ecdsa", key.curve.key_size
    for cls, name, size in _KEY_DESCRIPTIONS:
        if isinstance(key, cls):
            return name, size
    return type(key).__name__.lower(), None


def _validate_pair(
    key: PrivateKeyTypes,
    private_bytes: bytes,
    public_bytes: bytes,
    passphrase: bytes | None,
    fmt: str,
) -> None:
    """Check the serialised pair parses back and matches, before committing.

    The underlying library is trusted to produce correct output; this guards
    the seam around it -- serialisation, format selection and passphrase
    handling -- where a future change could plausibly emit a mismatched pair.

    Args:
        key: The in-memory private key.
        private_bytes: Serialised private key.
        public_bytes: Serialised public key.
        passphrase: Passphrase used, if any.
        fmt: Encoding used.

    Raises:
        KeyPairValidationError: If either half fails to parse, or the two do
            not correspond to the same key.
    """
    reference = encode_public_key(key.public_key(), fmt="der")
    try:
        reloaded_private = load_private_key(private_bytes, passphrase=passphrase)
        reloaded_public = load_public_key(public_bytes)
    except Exception as exc:
        msg = (
            f"The generated {fmt} key pair could not be parsed back after "
            "serialisation; refusing to write it."
        )
        raise KeyPairValidationError(msg) from exc

    if encode_public_key(reloaded_private.public_key(), fmt="der") != reference:
        msg = (
            "The serialised private key does not correspond to the generated "
            "key; refusing to write it."
        )
        raise KeyPairValidationError(msg)

    if encode_public_key(reloaded_public, fmt="der") != reference:
        msg = (
            "The serialised public key does not match the private key; "
            "refusing to write a mismatched pair."
        )
        raise KeyPairValidationError(msg)


def _preflight(private_path: Path, public_path: Path, *, overwrite: bool) -> None:
    """Reject an impossible or destructive write before touching the disk.

    Checks aliasing rather than just path equality: two different names can
    refer to the same file through a hard link, in which case writing the pair
    would leave only whichever half was written last.

    Raises:
        KeyExistsError: If a destination exists and ``overwrite`` is false.
        KeyWriteError: If the two paths alias each other, a destination is a
            directory, or a destination is a hard link to something else.
    """
    if private_path == public_path:
        msg = (
            f"The private and public key would both be written to "
            f"{private_path}. Choose a different name or format."
        )
        raise KeyWriteError(msg)

    for path in (private_path, public_path):
        if path.is_dir():
            msg = f"{path} is a directory, not a file."
            raise KeyWriteError(msg)

    if private_path.exists() and public_path.exists():
        try:
            aliased = private_path.samefile(public_path)
        except OSError:  # pragma: no cover - raced away between checks
            aliased = False
        if aliased:
            msg = (
                f"{private_path} and {public_path} are the same file (a hard "
                "or symbolic link). Writing the pair would leave only one "
                "half. Remove the link or choose a different destination."
            )
            raise KeyWriteError(msg)

    # A private key destination with more than one link means the bytes are
    # reachable under another name we know nothing about. Replacing it here
    # would leave the old key live at that other path.
    _reject_aliased_private_key(private_path)

    if overwrite:
        return

    existing = [str(p) for p in (private_path, public_path) if p.exists()]
    if existing:
        msg = (
            f"Key files already exist: {', '.join(existing)}. Refusing to "
            "overwrite key material, because replacing it cannot be undone. "
            "Choose a different --out-dir or --name, or pass --force to "
            "replace them; the existing files will be backed up first."
        )
        raise KeyExistsError(msg)


def _reject_aliased_private_key(private_path: Path) -> None:
    """Refuse a private key destination that has more than one hard link.

    Raises:
        KeyWriteError: If the destination is a multiply-linked file.
    """
    if not private_path.exists() or private_path.is_symlink():
        return
    try:
        links = private_path.stat().st_nlink
    except OSError:  # pragma: no cover - raced away between checks
        return
    if links > 1:
        msg = (
            f"{private_path} has {links} hard links, so the same file is "
            "reachable under another name. Replacing it here would leave the "
            "old key readable at that other path. Remove the extra link, or "
            "choose a different destination."
        )
        raise KeyWriteError(msg)


def _undo(outcome: WriteOutcome) -> None:
    """Reverse a completed write during rollback.

    A failure here is swallowed: it must not mask the original error that
    triggered the rollback.
    """
    try:
        if outcome.backup is not None:
            outcome.backup.replace(outcome.path)
            if outcome.backup_mode is not None and os.name != "nt":
                outcome.path.chmod(outcome.backup_mode)
        elif not outcome.replaced:
            outcome.path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - best effort during failure handling
        pass


def write_key_pair(  # noqa: PLR0913 - all but two are keyword-only options
    key: PrivateKeyTypes,
    directory: str | os.PathLike[str],
    *,
    name: str = DEFAULT_KEY_NAME,
    fmt: str = "pem",
    passphrase: bytes | None = None,
    overwrite: bool = False,
) -> KeyGenerationResult:
    """Write a private key and its public half to ``directory``.

    Args:
        key: Private key to write. The public key is derived from it.
        directory: Destination directory. ``~`` is expanded and a relative
            path is resolved against the current working directory. Created at
            mode ``0700`` if absent.
        name: Filename stem, for example ``"key"`` giving ``key.pem`` and
            ``key.pub.pem``.
        fmt: Output format, one of ``"pem"``, ``"der"``, ``"openssh"``.
        passphrase: Optional passphrase to encrypt the private key with.
        overwrite: Replace existing files, backing them up first. When
            :data:`False`, an existing file raises
            :class:`~encryption_helper.errors.KeyExistsError`.

    Returns:
        A :class:`KeyGenerationResult` describing what was written. It contains
        no secret material.

    Raises:
        KeyExistsError: If a destination exists and ``overwrite`` is false.
        KeyWriteError: If a file could not be written.
        KeyPairValidationError: If the serialised pair fails validation.
        UnsupportedAlgorithmError: If ``fmt`` is not valid for this key type.
        InvalidArgumentError: If ``passphrase`` is present but empty.
    """
    private_suffix, public_suffix = _SUFFIXES.get(fmt.strip().lower(), _SUFFIXES["pem"])
    base = resolve_destination(directory)
    private_path = base / f"{name}{private_suffix}"
    public_path = base / f"{name}{public_suffix}"

    _preflight(private_path, public_path, overwrite=overwrite)

    private_bytes = encode_private_key(key, fmt=fmt, passphrase=passphrase)
    public_bytes = encode_public_key(key.public_key(), fmt=fmt)
    _validate_pair(key, private_bytes, public_bytes, passphrase, fmt)

    private_outcome = secure_write_bytes(
        private_path, private_bytes, mode=SECRET_FILE_MODE, overwrite=overwrite
    )
    try:
        public_outcome = secure_write_bytes(
            public_path, public_bytes, mode=PUBLIC_FILE_MODE, overwrite=overwrite
        )
    except Exception:
        # Rollback layer 2 of 2. secure_write_bytes() has already restored
        # anything it displaced internally, so by the time we get here the
        # public destination is in its original state. All that remains is to
        # undo the private write that *succeeded*, so we never leave a private
        # key whose public counterpart is missing or stale.
        _undo(private_outcome)
        raise

    algorithm, key_size = describe_key(key)
    return KeyGenerationResult(
        private_key_path=private_outcome.path,
        public_key_path=public_outcome.path,
        algorithm=algorithm,
        key_size=key_size,
        fingerprint=fingerprint_sha256(key.public_key()),
        private_key_encrypted=passphrase is not None,
        replaced=private_outcome.replaced or public_outcome.replaced,
    )
