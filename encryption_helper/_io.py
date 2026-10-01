# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
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
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from .errors import KeyExistsError, KeyReadError, KeyWriteError

__all__ = ["WriteOutcome", "read_bytes", "resolve_destination", "secure_write_bytes"]

#: Mode for files containing secret material: owner read/write only.
SECRET_FILE_MODE = 0o600

#: Mode for files that are safe to publish, such as public keys.
PUBLIC_FILE_MODE = 0o644

#: Mode for directories holding secret material: owner access only.
SECRET_DIR_MODE = 0o700

_WINDOWS = sys.platform == "win32"


class WriteOutcome(NamedTuple):
    """What :func:`secure_write_bytes` actually did.

    Callers writing more than one file need this to undo a partial write: it
    records whether a previous file was displaced, and where it went.

    Attributes:
        path: The file that was written.
        backup: Where the previous contents were moved, or :data:`None` if
            nothing was displaced.
        replaced: Whether an existing file was replaced.
        backup_mode: The displaced file's original permission bits, so a
            rollback can restore them exactly.
    """

    path: Path
    backup: Path | None
    replaced: bool
    backup_mode: int | None = None


def resolve_destination(path: str | os.PathLike[str]) -> Path:
    """Expand and absolutise a destination path.

    ``~`` is expanded and a relative path is made absolute against the current
    working directory, so ``--out-dir ~/keys`` writes to the user's home
    directory rather than creating a directory literally named ``~``.

    The *parent* is resolved, following any symlinks along the way, but the
    final component is deliberately left alone: resolving it would silently
    follow a symlink planted at the destination, which is exactly what
    :func:`secure_write_bytes` refuses to do.

    Args:
        path: A path, possibly relative or containing ``~``.

    Returns:
        An absolute path with a resolved parent.

    Example:
        >>> resolve_destination("~/keys").is_absolute()
        True
    """
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate.parent.resolve() / candidate.name


def _fsync_directory(directory: Path) -> None:
    """Flush a directory entry so a rename survives a crash.

    Renaming a file is atomic, but on many filesystems the *directory entry*
    recording it is not durable until the directory itself is synced. Failure
    is ignored: not every platform or filesystem supports this, and it is a
    durability improvement rather than a correctness requirement.
    """
    if _WINDOWS:  # pragma: no cover - Windows cannot open a directory
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:  # pragma: no cover - unusual filesystem
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - unusual filesystem
        pass
    finally:
        os.close(fd)


def _timestamp() -> str:
    """Return a filesystem-safe UTC timestamp for backup filenames."""
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _backup(path: Path) -> tuple[Path, int]:
    """Move ``path`` aside to a timestamped sibling.

    The backup keeps the *original* file's permission bits, not the bits of
    whatever is about to replace it. A rollback must restore what was there,
    mode included.

    Args:
        path: Existing file to preserve.

    Returns:
        A ``(backup_path, original_mode)`` pair.

    Raises:
        KeyWriteError: If the backup could not be created.
    """
    try:
        original_mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:  # pragma: no cover - raced away between checks
        original_mode = SECRET_FILE_MODE

    backup = path.with_name(f"{path.name}.bak-{_timestamp()}")
    suffix = 1
    while backup.exists():
        backup = path.with_name(f"{path.name}.bak-{_timestamp()}.{suffix}")
        suffix += 1
    try:
        path.replace(backup)
        if not _WINDOWS:
            backup.chmod(original_mode)
    except OSError as exc:
        msg = f"Could not back up the existing file at {path}: {exc.strerror}"
        raise KeyWriteError(msg) from exc
    return backup, original_mode


def _restore(backup: Path, target: Path, mode: int) -> None:
    """Put a backup back where it came from, mode and all.

    Used when a write fails after its backup was taken. Failure is swallowed:
    it must not mask the error that triggered the restore.
    """
    try:
        backup.replace(target)
        if not _WINDOWS:
            target.chmod(mode)
    except OSError:  # pragma: no cover - best effort during failure handling
        pass


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
) -> WriteOutcome:
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
        A :class:`WriteOutcome` recording the path written, any backup taken,
        and whether an existing file was replaced.

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
        >>> outcome = secure_write_bytes(d / "secret.bin", b"payload")
        >>> outcome.path.read_bytes()
        b'payload'
    """
    target = resolve_destination(path)
    _reject_symlink(target)

    backup: Path | None = None
    backup_mode: int | None = None
    replaced = target.exists()
    if replaced:
        if not overwrite:
            msg = (
                f"{target} already exists. Refusing to overwrite it, because "
                "replacing key material cannot be undone. Pass overwrite=True "
                "(or --force on the command line) to replace it; the existing "
                "file will be backed up first."
            )
            raise KeyExistsError(msg)
        backup, backup_mode = _backup(target)

    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=dir_mode)
    except OSError as exc:
        if backup is not None and backup_mode is not None:
            _restore(backup, target, backup_mode)
        msg = f"Could not create directory {parent}: {exc.strerror}"
        raise KeyWriteError(msg) from exc

    try:
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=parent
        )
    except OSError as exc:
        # The backup was already taken, so the destination is currently empty.
        # Put it back before reporting, or a failed replacement would leave no
        # file where one used to be.
        if backup is not None and backup_mode is not None:
            _restore(backup, target, backup_mode)
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
        _fsync_directory(parent)
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        if backup is not None and backup_mode is not None:
            _restore(backup, target, backup_mode)
        msg = f"Could not write to {target}: {exc.strerror}"
        raise KeyWriteError(msg) from exc

    return WriteOutcome(
        path=target, backup=backup, replaced=replaced, backup_mode=backup_mode
    )


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
    source = Path(path).expanduser()
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
