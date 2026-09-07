"""Filesystem primitives for handling secret material safely.

The functions here exist because :func:`open` is the wrong tool for writing a
private key. ``open(path, "wb")`` creates the file using the process umask,
which on a typical system yields mode ``0644`` -- world readable. It also
truncates an existing file without warning, which for key material is silent,
unrecoverable data loss.

:func:`secure_write_bytes` addresses both: it creates files at ``0600`` inside
a ``0700`` directory, refuses to clobber an existing file unless explicitly
told to, backs up anything it does replace, and writes atomically so an
interrupted run cannot leave a truncated key behind.

.. note::
   POSIX permission bits are enforced directly. On Windows the mode argument
   is advisory -- see :func:`secure_write_bytes` for details.
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .errors import KeyExistsError, KeyReadError, KeyWriteError

__all__ = ["read_bytes", "secure_write_bytes"]

#: Mode for files containing secret material: owner read/write only.
SECRET_FILE_MODE = 0o600

#: Mode for files that are safe to publish, such as public keys.
PUBLIC_FILE_MODE = 0o644

#: Mode for directories holding secret material: owner access only.
SECRET_DIR_MODE = 0o700

_WINDOWS = sys.platform == "win32"


def _timestamp() -> str:
    """Return a filesystem-safe UTC timestamp for backup filenames."""
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _backup(path: Path, mode: int) -> Path:
    """Move ``path`` aside to a timestamped sibling and return the new path.

    Args:
        path: Existing file to preserve.
        mode: Permission bits to apply to the backup.

    Returns:
        The path the original file was moved to.

    Raises:
        KeyWriteError: If the backup could not be created.
    """
    backup = path.with_name(f"{path.name}.bak-{_timestamp()}")
    suffix = 1
    while backup.exists():
        backup = path.with_name(f"{path.name}.bak-{_timestamp()}.{suffix}")
        suffix += 1
    try:
        path.replace(backup)
        if not _WINDOWS:
            backup.chmod(mode)
    except OSError as exc:
        msg = f"Could not back up the existing file at {path}: {exc.strerror}"
        raise KeyWriteError(msg) from exc
    return backup


def _reject_symlink(path: Path) -> None:
    """Refuse to write through a symbolic link.

    Writing through a symlink lets an attacker who controls the destination
    directory redirect key material to a location of their choosing.

    Args:
        path: Destination being written to.

    Raises:
        KeyWriteError: If ``path`` is a symbolic link.
    """
    if path.is_symlink():
        msg = (
            f"Refusing to write to {path}: it is a symbolic link. "
            "Remove it or choose a different destination."
        )
        raise KeyWriteError(msg)


def secure_write_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    mode: int = SECRET_FILE_MODE,
    overwrite: bool = False,
    dir_mode: int = SECRET_DIR_MODE,
) -> Path:
    """Write ``data`` to ``path`` atomically with restrictive permissions.

    The write goes to a temporary file in the destination directory, which is
    then renamed over the target. A crash mid-write therefore leaves either the
    old file or the new one, never a half-written key.

    Args:
        path: Destination file path.
        data: Bytes to write.
        mode: Permission bits for the resulting file. Defaults to ``0600``.
        overwrite: If :data:`False` (the default), an existing destination is
            an error. If :data:`True`, the existing file is moved aside to a
            timestamped ``.bak-`` sibling before being replaced.
        dir_mode: Permission bits for any parent directories created.

    Returns:
        The resolved path that was written.

    Raises:
        KeyExistsError: If the destination exists and ``overwrite`` is
            :data:`False`.
        KeyWriteError: If the destination is a symlink, or the write fails.

    Note:
        On Windows the ``mode`` and ``dir_mode`` arguments are advisory:
        NTFS permissions are governed by ACLs, which :func:`os.chmod` does not
        express. The file is still created exclusively and replaced
        atomically. Restrict the containing directory's ACL to the current
        user for equivalent protection.

    Example:
        >>> import tempfile, pathlib
        >>> d = pathlib.Path(tempfile.mkdtemp())
        >>> p = secure_write_bytes(d / "secret.bin", b"payload")
        >>> p.read_bytes()
        b'payload'
    """
    target = Path(path)
    _reject_symlink(target)

    if target.exists():
        if not overwrite:
            msg = (
                f"{target} already exists. Refusing to overwrite it, because "
                "replacing key material cannot be undone. Pass overwrite=True "
                "(or --force on the command line) to replace it; the existing "
                "file will be backed up first."
            )
            raise KeyExistsError(msg)
        _backup(target, mode)

    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=dir_mode)
    except OSError as exc:
        msg = f"Could not create directory {parent}: {exc.strerror}"
        raise KeyWriteError(msg) from exc

    try:
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=parent
        )
    except OSError as exc:
        msg = f"Could not write to {target}: {exc.strerror}"
        raise KeyWriteError(msg) from exc

    tmp_path = Path(tmp_name)
    try:
        if not _WINDOWS:
            os.fchmod(tmp_fd, mode)
        with os.fdopen(tmp_fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(target)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        msg = f"Could not write to {target}: {exc.strerror}"
        raise KeyWriteError(msg) from exc

    return target


def read_bytes(path: str | os.PathLike[str]) -> bytes:
    """Read a file in binary mode, raising a typed error on failure.

    Args:
        path: File to read.

    Returns:
        The file's contents.

    Raises:
        KeyReadError: If the file is missing, is a directory, or cannot be
            read.

    Example:
        >>> import tempfile, pathlib
        >>> d = pathlib.Path(tempfile.mkdtemp())
        >>> _ = secure_write_bytes(d / "data.bin", b"hello")
        >>> read_bytes(d / "data.bin")
        b'hello'
    """
    source = Path(path)
    try:
        return source.read_bytes()
    except FileNotFoundError as exc:
        msg = f"No such file: {source}"
        raise KeyReadError(msg) from exc
    except IsADirectoryError as exc:
        msg = f"Expected a file but {source} is a directory"
        raise KeyReadError(msg) from exc
    except OSError as exc:
        msg = f"Could not read {source}: {exc.strerror}"
        raise KeyReadError(msg) from exc
