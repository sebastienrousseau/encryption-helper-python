# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Filesystem primitives for handling secret material safely.

The functions here exist because :func:`open` is the wrong tool for writing a
private key. ``open(path, "wb")`` creates the file using the process umask,
which on a typical system yields mode ``0644`` -- world readable. It also
truncates an existing file without warning, which for key material is silent,
unrecoverable data loss.

:func:`secure_write_bytes` addresses both: it creates files at ``0600``,
creates missing directories at ``0700``, warns when a private key is about to
land in a directory other users can write to, refuses to clobber an existing
file unless explicitly told to, backs up anything it does replace, and writes
atomically so an interrupted run cannot leave a truncated key behind.

Reading is the mirror image. :func:`read_bytes` serves the CLI, which must
accept ``--in <(cmd)`` and so opens FIFOs blocking; :func:`read_regular_file`
serves code that reads paths it did not choose, and refuses anything but a
regular file without ever blocking on one.

.. note::
   POSIX permission bits are enforced directly. On Windows they are not: a
   file inherits its folder's ACL, so a key is as private as its folder. See
   :mod:`encryption_helper._platform`.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import secrets
import stat
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, NamedTuple

from . import _platform
from .errors import InvalidArgumentError, KeyExistsError, KeyReadError, KeyWriteError

logger = logging.getLogger(__name__)

__all__ = [
    "InputTooLargeError",
    "NotRegularFileError",
    "WriteOutcome",
    "read_bytes",
    "read_regular_file",
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


def _warn_if_exposed(directory: Path, mode: int) -> None:
    """Warn when a secret is about to be written where others can replace it.

    Advisory rather than a refusal: shared CI workspaces, container mounts
    and managed filesystems have permission models mode bits do not capture,
    and refusing would break them while promising more than can be checked.
    """
    if mode & 0o077:
        return  # Not a secret: a public key may live anywhere.
    reason = _platform.exposed_directory(directory)
    if reason is not None:
        logger.warning(
            "Writing secret material to %s, but %s. Another user could "
            "replace the file. Prefer a directory only you can write to.",
            directory,
            reason,
        )


def _timestamp() -> str:
    """Return a filesystem-safe UTC timestamp for backup filenames."""
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _random_tag() -> str:
    """Return the unpredictable part of a backup name.

    A name built from the clock alone can be guessed to the second. In a
    shared sticky directory another user could then plant an entry -- even a
    dangling symlink -- at the next backup name, which this user may not
    rename over, and so block every ``--force``.
    """
    return secrets.token_hex(4)


#: Characters :func:`tempfile.mkstemp` adds to the destination name: a
#: leading and a joining dot, eight random characters and ``.tmp``.
_TEMP_NAME_OVERHEAD = 14


class _Displaced(NamedTuple):
    """A file moved aside to make room for its replacement.

    Bundling the backup path with the mode it had removes the recurring
    ``backup is not None and backup_mode is not None`` guard: there is one
    object, and it either exists or it does not.
    """

    backup: Path
    target: Path
    mode: int

    def restore(self, *, replace: bool = False) -> bool:
        """Put the file back where it came from, mode and all.

        Called when a write fails after its predecessor was displaced. Failure
        is swallowed: a failed rollback must not mask the error that triggered
        it.

        Args:
            replace: Whether whatever is now at the target is this process's
                own committed write, and so may be replaced. By default the
                restore will not replace anything: a file that appeared at the
                target since the displacement belongs to another process, and
                the original then stays at :attr:`backup`.

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
        with contextlib.suppress(OSError):
            _platform.restrict_path(self.target, self.mode)
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

    The name carries a random tag as well as the time, and a candidate is
    skipped if *anything* has that name -- :func:`os.path.lexists`, not
    :meth:`~pathlib.Path.exists`, which follows symlinks and so reports a
    dangling link as free, letting the rename replace it.

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

    backup = path.with_name(f"{path.name}.bak-{_timestamp()}-{_random_tag()}")
    while os.path.lexists(backup):
        backup = path.with_name(f"{path.name}.bak-{_timestamp()}-{_random_tag()}")
    try:
        path.replace(backup)
    except OSError as exc:
        reason = exc.strerror
        if exc.errno == errno.ENAMETOOLONG:
            reason = (
                f"the name is too long to add the backup suffix "
                f"({len(backup.name) - len(path.name)} characters); "
                "choose a shorter name"
            )
        msg = f"Could not back up the existing file at {path}: {reason}"
        raise KeyWriteError(msg) from exc
    # A rename keeps the inode's mode, so this only reasserts it. It must not
    # fail the displacement: the file has already moved, and an error here
    # would lose the record of where to -- e.g. when the entry displaced is a
    # symlink, whose mode cannot be set on a platform without ``lchmod``.
    with contextlib.suppress(OSError):
        _platform.restrict_path(backup, original_mode)
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
    then committed under the target name. A crash mid-write therefore leaves
    either the old file or the new one, never a half-written key.

    This is :func:`secure_write_stream` with a single write, not a parallel
    implementation. It used to be one, displacing the old file *before*
    writing and cleaning up only after ``OSError``: a SIGTERM or Ctrl-C
    during the write left no file at the destination, the old key under its
    backup name and the new one in a stray temporary file.

    Args:
        path: Destination file path.
        data: Bytes to write.
        mode: Permission bits for the resulting file. Defaults to ``0600``.
        overwrite: If :data:`False` (the default), an existing destination is
            an error. If :data:`True`, the existing file is moved aside to a
            timestamped ``.bak-`` sibling once the new content is complete,
            just before it is committed.
        dir_mode: Permission bits for every parent directory created.

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
    with secure_write_stream(
        path, mode=mode, overwrite=overwrite, dir_mode=dir_mode
    ) as (handle, outcome):
        handle.write(data)
    return outcome[0]


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


def _make_directories(directory: Path, mode: int) -> None:
    """Create ``directory`` and any missing ancestors, each at ``mode``.

    ``Path.mkdir(parents=True, mode=...)`` applies ``mode`` to the last
    level only; the intermediate ones get the umask default, typically
    ``0755``. Each missing level is therefore created explicitly. Levels
    that already exist are not touched: their permissions are the owner's
    choice, and :func:`_warn_if_exposed` reports one that is unsafe.

    Raises:
        KeyWriteError: If a level cannot be created, or a non-directory is
            in the way.
    """
    try:
        missing: list[Path] = []
        level = directory
        while not level.is_dir() and level != level.parent:
            missing.append(level)
            level = level.parent
        for level in reversed(missing):
            level.mkdir(mode=mode, exist_ok=True)
    except OSError as exc:
        msg = f"Could not create directory {directory}: {exc.strerror}"
        raise KeyWriteError(msg) from exc


def _create_temporary(target: Path) -> tuple[int, Path]:
    """Create the exclusive, randomly named temporary file beside ``target``.

    Raises:
        KeyWriteError: If it cannot be created. A name that fits the
            filesystem's limit but not with the temporary suffix gets a
            message saying so, rather than a bare "File name too long" for a
            name the caller can see is valid.
    """
    try:
        fd, name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
    except OSError as exc:
        reason = exc.strerror
        if exc.errno == errno.ENAMETOOLONG:
            reason = (
                "the name is too long for the temporary file an atomic write "
                f"needs ({_TEMP_NAME_OVERHEAD} more characters); choose a "
                "shorter name"
            )
        msg = f"Could not write to {target}: {reason}"
        raise KeyWriteError(msg) from exc
    return fd, Path(name)


def _write_error(
    target: Path, exc: OSError, unrestored: _Displaced | None = None
) -> KeyWriteError:
    """The typed error for a failed write, naming a backup left behind."""
    msg = f"Could not write to {target}: {exc.strerror}"
    if unrestored is not None:
        msg += (
            f". It could not be put back, because another file now has its "
            f"name; the file that was there before is preserved at "
            f"{unrestored.backup}."
        )
    return KeyWriteError(msg)


def _commit_without_clobbering(tmp_path: Path, target: Path) -> None:
    """Move a finished temporary file into place, never over another file.

    Callers establish that ``target`` is absent first -- either it never
    existed, or the old file has been displaced to a backup. A plain rename
    would still replace anything another process created in between, so the
    commit is a hard link, which fails if the name is taken, followed by
    removing the temporary name.

    A filesystem without hard links (FAT, some network mounts) falls back to
    a rename after re-checking, which narrows the window but cannot close it.
    Only an error that means "no hard links here" takes that path -- see
    :func:`~encryption_helper._platform.hard_link_unsupported`. Anything else
    (EACCES, ENOSPC, EIO) is the write failing, and is reported as such.

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
    except OSError as exc:
        if not _platform.hard_link_unsupported(exc):
            raise
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
    # that was correctly written. But the leftover is a second copy of the
    # content -- for a private key, of the secret -- so it is reported.
    try:
        tmp_path.unlink()
    except OSError as exc:
        logger.warning(
            "Wrote %s, but could not remove %s (%s). It is a second copy of "
            "the same content; delete it.",
            target,
            tmp_path,
            exc.strerror,
        )


@contextlib.contextmanager
def secure_write_stream(
    path: str | os.PathLike[str],
    *,
    mode: int = SECRET_FILE_MODE,
    overwrite: bool = False,
    dir_mode: int = SECRET_DIR_MODE,
) -> Iterator[tuple[IO[bytes], list[WriteOutcome]]]:
    """Stream into ``path`` atomically, with restrictive permissions.

    For output too large to hold in memory -- a decrypted file, a ciphertext
    -- and the implementation behind :func:`secure_write_bytes`. The data
    goes to a temporary file in the destination directory at ``mode``; only
    once the caller's block completes is it committed. So:

    * a failure or interruption -- including ``KeyboardInterrupt`` and the
      ``SystemExit`` the CLI raises on SIGTERM -- before the commit leaves the
      destination untouched and removes the temporary file;
    * with ``overwrite``, the existing file is moved to a timestamped
      ``.bak-`` sibling *at commit time* -- after the new content is complete
      -- and restored if the commit fails or is interrupted;
    * a symbolic link at the destination is refused, as is a file created by
      another process during the write, and a rollback never replaces one;
    * every parent directory created gets ``dir_mode``, and both the file and
      its directory are synced.

    Args:
        path: Destination file path.
        mode: Permission bits for the resulting file.
        overwrite: Replace an existing file, backing it up first.
        dir_mode: Permission bits for every parent directory created.

    Yields:
        A writable binary stream, and a list that receives the
        :class:`WriteOutcome` once the write has been committed.

    Raises:
        KeyExistsError: If the destination exists and ``overwrite`` is false,
            checked before any work is done and again at commit.
        KeyWriteError: If the destination is a symlink, or the write fails.
            An exception raised by the caller's own block propagates as is.

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
    _make_directories(parent, dir_mode)
    _warn_if_exposed(parent, mode)
    tmp_fd, tmp_path = _create_temporary(target)

    outcome: list[WriteOutcome] = []
    try:
        # Adopt the descriptor before anything can fail, so it is closed on
        # every path; a failing fchmod used to leak it.
        with os.fdopen(tmp_fd, "wb") as handle:
            try:
                _platform.restrict_descriptor(handle.fileno(), mode)
            except OSError as exc:
                raise _write_error(target, exc) from exc
            yield handle, outcome
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except OSError as exc:
                raise _write_error(target, exc) from exc
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise

    displaced = None
    committed = False
    try:
        # Re-checked at commit: the destination may have changed during a
        # long write. A file that appeared is refused unless overwriting.
        _reject_symlink(target)
        if _reject_existing_destination(target, overwrite=overwrite):
            displaced = _displace(target)
        _commit_without_clobbering(tmp_path, target)
        committed = True
        _platform.fsync_directory(parent)
    except BaseException as exc:
        # The temporary holds the complete new content -- for a private key,
        # a second copy of the secret -- so it must not outlive a failed commit.
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        unrestored = None
        if displaced is not None:
            if isinstance(exc, KeyExistsError):
                raise displaced.raced(exc) from exc
            # Only a target this process committed may be replaced; anything
            # else there was created by someone else since the displacement.
            if not displaced.restore(replace=committed):
                unrestored = displaced
        if isinstance(exc, OSError):
            raise _write_error(target, exc, unrestored) from exc
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

    The open is blocking, deliberately: a FIFO with no writer yet waits for
    one, which is what lets ``--in <(cmd)`` work. It also means a path to a
    FIFO nobody writes to blocks for ever, so for paths an untrusted party
    may have chosen use :func:`read_regular_file`, which never blocks and
    refuses anything but a regular file.

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


class NotRegularFileError(KeyReadError, OSError):
    """A path named a FIFO, device or socket, not a regular file.

    Both a :class:`~encryption_helper.errors.KeyReadError`, so it is caught
    with the rest of this package's errors, and an :class:`OSError` with
    :attr:`~OSError.strerror` and :attr:`~OSError.filename` set, so code that
    already reports ``OSError`` from a read -- a scan listing unreadable
    files, a server turning them into a tool error -- handles it unchanged.
    """

    def __init__(self, path: Path) -> None:
        """Record the path that was not a regular file."""
        super().__init__(None, "not a regular file", str(path))

    def __str__(self) -> str:
        """Say what was refused, without the ``[Errno None]`` prefix."""
        return f"{self.filename} is not a regular file."


def read_regular_file(
    path: str | os.PathLike[str], limit: int, *, prefix: bool = False
) -> bytes:
    """Read at most ``limit`` bytes of a regular file, refusing anything else.

    For paths this process did not choose -- files found by a directory walk,
    or named by a remote client. Three guarantees :func:`read_bytes` does not
    give, because the CLI needs the opposite of each:

    * **It never blocks.** The open is non-blocking, so a FIFO with no writer
      fails fast instead of stalling the caller for ever.
    * **It does not follow a final symlink.** A link swapped in after the path
      was checked fails the open rather than redirecting it.
    * **It reads only regular files.** The type is checked on the open
      descriptor, so there is no window between check and read; a FIFO,
      device or socket raises :class:`NotRegularFileError`, and a directory
      the :class:`IsADirectoryError` its open raises.

    At most ``limit + 1`` bytes are read (``limit`` with ``prefix``), so the
    size a file reports, or gains while being read, cannot raise the cost.
    The path is used as given: no ``~`` expansion and no resolution.

    Args:
        path: File to read.
        limit: Most bytes to return; zero or more.
        prefix: Return the first ``limit`` bytes of a larger file instead of
            refusing it -- for classifying a file by its head.

    Returns:
        The contents, or with ``prefix`` their first ``limit`` bytes.

    Raises:
        InvalidArgumentError: If ``limit`` is negative.
        NotRegularFileError: If ``path`` is not a regular file. Also an
            :class:`OSError` and a :class:`~encryption_helper.errors.KeyReadError`.
        InputTooLargeError: If the file holds more than ``limit`` bytes and
            ``prefix`` is false.
        OSError: If the file cannot be opened or read, unchanged, so the
            caller can report :attr:`~OSError.strerror`. A symlink fails with
            ``ELOOP`` on POSIX.

    Example:
        >>> import tempfile, pathlib
        >>> d = pathlib.Path(tempfile.mkdtemp())
        >>> _ = (d / "notes.txt").write_bytes(b"hello world")
        >>> read_regular_file(d / "notes.txt", 64)
        b'hello world'
        >>> read_regular_file(d / "notes.txt", 5, prefix=True)
        b'hello'
    """
    if limit < 0:
        msg = f"limit must be zero or more, not {limit}"
        raise InvalidArgumentError(msg)
    source = Path(path)
    with open(source, "rb", opener=_platform.safe_opener) as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise NotRegularFileError(source)
        data = handle.read(limit if prefix else limit + 1)
    if not prefix and len(data) > limit:
        raise InputTooLargeError(source, limit)
    return data
