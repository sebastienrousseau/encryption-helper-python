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
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, NamedTuple

from .errors import KeyExistsError, KeyReadError, KeyWriteError

__all__ = [
    "InputTooLargeError",
    "WriteOutcome",
    "read_bytes",
    "resolve_destination",
    "secure_write_bytes",
    "secure_write_stream",
]

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


class _Displaced(NamedTuple):
    """A file moved aside to make room for its replacement.

    Bundling the backup path with the mode it had removes the recurring
    ``backup is not None and backup_mode is not None`` guard: there is one
    object, and it either exists or it does not.
    """

    backup: Path
    target: Path
    mode: int

    def restore(self, *, replace: bool = True) -> bool:
        """Put the file back where it came from, mode and all.

        Called when a write fails after its predecessor was displaced. Failure
        is swallowed: a failed rollback must not mask the error that triggered
        it.

        Args:
            replace: Whether whatever is now at the target is this process's
                own failed write, and so may be replaced. When the target was
                taken by *another* process, pass False: its file is not ours
                to destroy, and the original stays at :attr:`backup`.

        Returns:
            True if the original is back at its path, False if it remains
            only at :attr:`backup`.
        """
        try:
            if replace:
                self.backup.replace(self.target)
            else:
                _commit_without_clobbering(self.backup, self.target)
        except (KeyExistsError, OSError):
            return False
        if not _WINDOWS:
            with contextlib.suppress(OSError):
                self.target.chmod(self.mode)
        return True

    def raced(self, exc: KeyExistsError) -> KeyExistsError:
        """Explain a commit race, naming where the previous file now lives."""
        if self.restore(replace=False):
            return exc
        msg = (
            f"{self.target} was created by another process while this write "
            f"was in progress. It was not overwritten; the file that was there "
            f"before is preserved at {self.backup}."
        )
        return KeyExistsError(msg)


def _displace(path: Path) -> _Displaced:
    """Move ``path`` aside to a timestamped sibling.

    The backup keeps the *original* file's permission bits, not the bits of
    whatever is about to replace it. A rollback must restore what was there,
    mode included.

    Args:
        path: Existing file to preserve.

    Returns:
        The :class:`_Displaced` record needed to undo the move.

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
    return _Displaced(backup=backup, target=path, mode=original_mode)


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
    replaced = _reject_existing_destination(target, overwrite=overwrite)

    displaced = _displace(target) if replaced else None
    try:
        _write_atomically(target, data, mode=mode, dir_mode=dir_mode)
    except KeyWriteError:
        # The displaced file is the only copy of the old contents, and the
        # destination is currently empty. Put it back before reporting, or a
        # failed replacement leaves no file where one used to be.
        if displaced is not None:
            displaced.restore()
        raise
    except KeyExistsError as exc:
        # Another process took the name during the write. Its file is not
        # ours to replace, so the old contents may have to stay at the backup.
        if displaced is not None:
            raise displaced.raced(exc) from exc
        raise

    return _outcome(target, displaced, replaced=replaced)


def _reject_existing_destination(target: Path, *, overwrite: bool) -> bool:
    """Report whether ``target`` exists, refusing to clobber it unless told to.

    Args:
        target: Destination being written to.
        overwrite: Whether replacing an existing file is permitted.

    Returns:
        Whether a file is already present at ``target``.

    Raises:
        KeyExistsError: If ``target`` exists and ``overwrite`` is false.
    """
    if not target.exists():
        return False
    if not overwrite:
        msg = (
            f"{target} already exists. Refusing to overwrite it, because "
            "replacing key material cannot be undone. Pass overwrite=True "
            "(or --force on the command line) to replace it; the existing "
            "file will be backed up first."
        )
        raise KeyExistsError(msg)
    return True


def _write_atomically(target: Path, data: bytes, *, mode: int, dir_mode: int) -> None:
    """Write ``data`` to ``target`` via a temporary file in the same directory.

    Creating the temporary alongside the target keeps the final step a rename
    within one filesystem, which is atomic. A crash therefore leaves either the
    old file or the new one, never a half-written key.

    Args:
        target: Final destination.
        data: Bytes to write.
        mode: Permission bits for the resulting file.
        dir_mode: Permission bits for any parent directories created.

    Raises:
        KeyWriteError: If the directory, the temporary file, or the write
            itself fails. The temporary is removed on failure.
    """
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
        _commit_without_clobbering(tmp_path, target)
        _fsync_directory(parent)
    except KeyExistsError:
        # Lost a race for the name. The temporary file holds the complete new
        # content -- for a private key, a second copy of the secret -- so it
        # must not outlive the failed commit.
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
    except OSError as exc:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        msg = f"Could not write to {target}: {exc.strerror}"
        raise KeyWriteError(msg) from exc


def _commit_without_clobbering(tmp_path: Path, target: Path) -> None:
    """Move a finished temporary file into place, never over another file.

    Callers establish that ``target`` is absent first -- either it never
    existed, or the old file has been displaced to a backup. A plain rename
    would still replace anything another process created in between, so the
    commit is a hard link, which fails if the name is taken, followed by
    removing the temporary name.

    A filesystem without hard links (FAT, some network mounts) falls back to
    a rename after re-checking, which narrows the window but cannot close it.

    Raises:
        KeyExistsError: If ``target`` appeared after the caller's check.
        OSError: If the commit fails for any other reason. The temporary
            file is left for the caller to remove.
    """
    try:
        os.link(tmp_path, target)
    except FileExistsError as exc:
        msg = (
            f"{target} was created by another process while this write was "
            "in progress. Nothing was overwritten."
        )
        raise KeyExistsError(msg) from exc
    except OSError:
        # Hard links unsupported here. Re-check, then rename.
        if target.exists() or target.is_symlink():
            msg = (
                f"{target} was created by another process while this write "
                "was in progress. Nothing was overwritten."
            )
            raise KeyExistsError(msg) from None
        tmp_path.replace(target)
        return
    # The link is the commit: the target now holds the new content. Removing
    # the temporary name is cleanup, so its failure must not turn a completed
    # write into a reported failure -- the caller would then roll back a file
    # that was correctly written.
    with contextlib.suppress(OSError):
        tmp_path.unlink()


@contextlib.contextmanager
def secure_write_stream(
    path: str | os.PathLike[str],
    *,
    mode: int = SECRET_FILE_MODE,
    overwrite: bool = False,
    dir_mode: int = SECRET_DIR_MODE,
) -> Iterator[tuple[IO[bytes], list[WriteOutcome]]]:
    """Stream into ``path`` with the guarantees of :func:`secure_write_bytes`.

    For output too large to hold in memory -- a decrypted file, a ciphertext.
    The data goes to a temporary file in the destination directory at
    ``mode``; only once the caller's block completes is it committed. So:

    * a failure or interruption part way through leaves the destination
      untouched and removes the temporary file;
    * with ``overwrite``, the existing file is moved to a timestamped
      ``.bak-`` sibling *at commit time* -- after the new content is complete
      -- and restored if the commit fails;
    * a symbolic link at the destination is refused, as is a file created by
      another process during the write;
    * parent directories are created at ``dir_mode`` and both the file and
      its directory are synced.

    Args:
        path: Destination file path.
        mode: Permission bits for the resulting file.
        overwrite: Replace an existing file, backing it up first.
        dir_mode: Permission bits for any parent directories created.

    Yields:
        A writable binary stream, and a list that receives the
        :class:`WriteOutcome` once the write has been committed.

    Raises:
        KeyExistsError: If the destination exists and ``overwrite`` is false,
            checked before any work is done.
        KeyWriteError: If the destination is a symlink, or the write fails.

    Example:
        >>> import tempfile, pathlib
        >>> d = pathlib.Path(tempfile.mkdtemp())
        >>> with secure_write_stream(d / "big.bin") as (handle, outcome):
        ...     _ = handle.write(b"chunk one, ")
        ...     _ = handle.write(b"chunk two")
        >>> outcome[0].path.read_bytes()
        b'chunk one, chunk two'
    """
    target = resolve_destination(path)
    _reject_symlink(target)
    _reject_existing_destination(target, overwrite=overwrite)

    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=dir_mode)
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=parent
        )
    except OSError as exc:
        msg = f"Could not write to {target}: {exc.strerror}"
        raise KeyWriteError(msg) from exc

    tmp_path = Path(tmp_name)
    outcome: list[WriteOutcome] = []
    try:
        if not _WINDOWS:
            os.fchmod(tmp_fd, mode)
        with os.fdopen(tmp_fd, "wb") as handle:
            yield handle, outcome
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise

    displaced = None
    try:
        # Re-checked at commit: the destination may have changed during a
        # long write. A file that appeared is refused unless overwriting.
        _reject_symlink(target)
        if _reject_existing_destination(target, overwrite=overwrite):
            displaced = _displace(target)
        _commit_without_clobbering(tmp_path, target)
        _fsync_directory(parent)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        if displaced is not None:
            if isinstance(exc, KeyExistsError):
                raise displaced.raced(exc) from exc
            displaced.restore()
        if isinstance(exc, OSError):
            msg = f"Could not write to {target}: {exc.strerror}"
            raise KeyWriteError(msg) from exc
        raise

    outcome.append(_outcome(target, displaced, replaced=displaced is not None))


def _outcome(
    target: Path, displaced: _Displaced | None, *, replaced: bool
) -> WriteOutcome:
    """Build the public result from the internal displacement record."""
    if displaced is None:
        return WriteOutcome(path=target, backup=None, replaced=replaced)
    return WriteOutcome(
        path=target,
        backup=displaced.backup,
        replaced=replaced,
        backup_mode=displaced.mode,
    )


class InputTooLargeError(KeyReadError):
    """A file held more than its reader accepts.

    Attributes:
        path: The file that was read.
        limit: The largest size, in bytes, that would have been accepted.
    """

    def __init__(self, path: Path, limit: int) -> None:
        """Record the file and the limit it exceeded."""
        self.path = path
        self.limit = limit
        super().__init__(f"{path} exceeds the {limit}-byte limit for this input.")


def read_bytes(path: str | os.PathLike[str], *, limit: int | None = None) -> bytes:
    """Read a file in binary mode, raising a typed error on failure.

    With ``limit``, at most ``limit + 1`` bytes are ever read, whatever the
    file claims to be. A size check from ``stat()`` cannot do that: a FIFO,
    ``/dev/zero`` or a process substitution reports a size of 0, and a
    regular file can grow between the check and the read.

    Args:
        path: File to read.
        limit: Largest accepted size in bytes, or :data:`None` for no limit.

    Returns:
        The file's contents.

    Raises:
        InputTooLargeError: If the file holds more than ``limit`` bytes.
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
        if limit is None:
            return source.read_bytes()
        with source.open("rb") as handle:
            data = handle.read(limit + 1)
    except FileNotFoundError as exc:
        msg = f"No such file: {source}"
        raise KeyReadError(msg) from exc
    except IsADirectoryError as exc:
        msg = f"Expected a file but {source} is a directory"
        raise KeyReadError(msg) from exc
    except OSError as exc:
        msg = f"Could not read {source}: {exc.strerror}"
        raise KeyReadError(msg) from exc
    if len(data) > limit:
        raise InputTooLargeError(source, limit)
    return data
