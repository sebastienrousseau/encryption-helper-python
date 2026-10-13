# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Every operating-system difference this package depends on, in one place.

POSIX and Windows protect files differently. POSIX uses owner/group/other
mode bits, which ``os.chmod`` sets. Windows uses ACLs, which mode bits cannot
express: ``os.chmod`` there only toggles the read-only attribute, and a new
file simply inherits its folder's ACL.

So on Windows this package does **not** make a file owner-only. A private key
is exactly as private as the folder it is written to. Doing better needs the
Win32 security API, which this package does not take a dependency on; keep
keys in a folder only you can read, such as one under your user profile.

Callers ask the questions below instead of testing the platform themselves.
:data:`WINDOWS` is read at call time, so a test can simulate either platform
on any host.
"""

from __future__ import annotations

import contextlib
import errno
import os
import stat
import sys
from collections.abc import Iterator
from pathlib import Path

__all__ = [
    "LINK_UNSUPPORTED_ERRNOS",
    "LIST_BY_DESCRIPTOR",
    "SAFE_OPEN_FLAGS",
    "WINDOWS",
    "changed_error",
    "entry_identity",
    "exposed_directory",
    "fsync_directory",
    "group_or_world_readable",
    "hard_link_unsupported",
    "identity_of",
    "open_directory",
    "restrict_descriptor",
    "restrict_path",
    "safe_opener",
]

#: Whether the host uses Windows ACLs rather than POSIX mode bits.
WINDOWS: bool = sys.platform == "win32"

#: Added to the flags of an open of untrusted input. Non-blocking, so a FIFO
#: cannot stall the open; no-follow, so a symbolic link swapped in for a
#: path that was checked is not read through. Windows has neither flag, and
#: no FIFOs in the filesystem namespace to defend against.
SAFE_OPEN_FLAGS: int = getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)

#: ``errno`` values from :func:`os.link` that mean "this filesystem cannot
#: make a hard link here", as opposed to "this link failed". FAT and exFAT
#: report EPERM on Linux; some network and FUSE mounts ENOTSUP, EOPNOTSUPP or
#: ENOSYS; EXDEV and EMLINK mean the link cannot be made at all. Windows maps
#: its codes onto these, and unmapped codes onto EINVAL -- see
#: :func:`hard_link_unsupported`. Anything else -- EACCES, ENOSPC, EIO -- is
#: a real failure of the write, not a reason to fall back to a racier commit.
LINK_UNSUPPORTED_ERRNOS: frozenset[int] = frozenset(
    code
    for code in (
        errno.EPERM,
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
        getattr(errno, "ENOSYS", None),
        errno.EXDEV,
        errno.EMLINK,
    )
    if code is not None
)

#: Windows error codes from ``CreateHardLinkW`` meaning the volume has no hard
#: links: ERROR_INVALID_FUNCTION (FAT), ERROR_NOT_SAME_DEVICE,
#: ERROR_NOT_SUPPORTED and ERROR_TOO_MANY_LINKS.
_WINDOWS_LINK_UNSUPPORTED = frozenset({1, 17, 50, 1142})

#: ``S_IWGRP | S_IWOTH``: someone other than the owner may write.
_WRITABLE_BY_OTHERS = 0o022


def safe_opener(path: str, flags: int) -> int:
    """An ``opener`` for :func:`open` that adds :data:`SAFE_OPEN_FLAGS`."""
    return os.open(path, flags | SAFE_OPEN_FLAGS)


def restrict_descriptor(fd: int, mode: int) -> None:
    """Apply POSIX ``mode`` to an open file. No-op on Windows (ACLs)."""
    if not WINDOWS:
        os.fchmod(fd, mode)


def restrict_path(path: Path, mode: int) -> None:
    """Apply POSIX ``mode`` to a path, never through a symlink.

    :func:`os.chmod` follows a link, so a link swapped in for a backup or a
    restored key would have moved *its target's* permissions instead. Where
    the platform can change a link's own mode (``lchmod``: macOS, the BSDs)
    that is used. Linux has no ``lchmod``, so the file is opened no-follow
    and changed through the descriptor; a file its owner can neither read
    nor write cannot be opened, and falls back to refusing a symlink and
    then changing the mode by name. No-op on Windows (ACLs).

    Raises:
        OSError: If the change fails; ``ELOOP`` if ``path`` is a symlink on a
            platform without ``lchmod``.
    """
    if WINDOWS:
        return
    if os.chmod in os.supports_follow_symlinks:  # pragma: no cover - not Linux
        path.chmod(mode, follow_symlinks=False)
        return
    try:
        fd = os.open(path, os.O_RDONLY | SAFE_OPEN_FLAGS)
    except PermissionError:
        if path.is_symlink():
            raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), str(path)) from None
        path.chmod(mode)
        return
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def hard_link_unsupported(error: OSError) -> bool:
    """Whether a failed :func:`os.link` means the filesystem lacks hard links.

    Only then may a commit fall back to check-then-rename, which cannot rule
    out replacing a file created in between. Every other failure is the
    write failing, and is reported as such.
    """
    # ``winerror`` exists only on Windows, where it is more precise than the
    # errno Python derives from it.
    if getattr(error, "winerror", None) in _WINDOWS_LINK_UNSUPPORTED:
        return True
    return error.errno in LINK_UNSUPPORTED_ERRNOS


def fsync_directory(directory: Path) -> None:
    """Flush a directory entry so a rename survives a crash.

    Renaming a file is atomic, but on many filesystems the *directory entry*
    recording it is not durable until the directory itself is synced. Failure
    is ignored: not every platform or filesystem supports this, and it is a
    durability improvement rather than a correctness requirement. Windows
    cannot open a directory for syncing, and NTFS journals the metadata.
    """
    if WINDOWS:
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:  # pragma: no cover - unusual filesystem
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(fd)
    finally:
        os.close(fd)


def exposed_directory(directory: Path) -> str | None:
    """Say why ``directory`` is unsafe to hold a private key, if it is.

    A key written owner-only is still exposed if someone else can write to
    its directory: they can rename it away and put their own in its place.
    A sticky directory such as ``/tmp`` prevents that, so it is not flagged;
    nor is a directory owned by root, which is how system paths look.

    Returns:
        A short reason, or :data:`None` if nothing is wrong or the platform's
        permissions cannot be judged from mode bits (Windows).
    """
    if WINDOWS:
        return None
    try:
        info = directory.stat()
    except OSError:
        return None
    owner = info.st_uid
    if owner not in (os.geteuid(), 0):
        return f"it is owned by another user (uid {owner})"
    sticky = info.st_mode & stat.S_ISVTX
    if info.st_mode & _WRITABLE_BY_OTHERS and not sticky:
        mode = stat.S_IMODE(info.st_mode)
        return f"other users can write to it (mode {mode:04o})"
    return None


def group_or_world_readable(path: Path) -> int | None:
    """Return a file's mode if others can read it; :data:`None` otherwise.

    Also :data:`None` on Windows, where mode bits do not describe the ACL,
    and when the file cannot be inspected.
    """
    if WINDOWS:
        return None
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    return mode if mode & 0o077 else None


#: Whether a directory can be opened and listed through a descriptor. Then a
#: walk can confirm it lists the directory it found, not whatever the path
#: names by the time it is opened. POSIX; Windows lists by path.
LIST_BY_DESCRIPTOR: bool = os.scandir in os.supports_fd and hasattr(os, "O_DIRECTORY")


def identity_of(status: os.stat_result) -> tuple[int, int]:
    """The ``(device, inode)`` pair that names one file, whatever its path."""
    return status.st_dev, status.st_ino


def changed_error(path: Path) -> OSError:
    """The error for something replaced between being found and being opened."""
    code = getattr(errno, "ESTALE", errno.EIO)
    return OSError(code, "changed while it was being scanned", str(path))


def entry_identity(entry: os.DirEntry[str], parent: Path) -> tuple[int, int]:
    """The identity of a directory entry, without following a link.

    Windows fills ``DirEntry.stat()`` from the directory listing, where the
    inode and device are zero, so the entry is asked by path instead.
    """
    if WINDOWS:  # pragma: no cover - Windows only
        return identity_of(os.lstat(parent / entry.name))
    return identity_of(entry.stat(follow_symlinks=False))


@contextlib.contextmanager
def open_directory(
    path: Path, expected: tuple[int, int] | None, *, follow: bool
) -> Iterator[Iterator[os.DirEntry[str]]]:
    """List ``path``, refusing it if it is no longer the directory expected.

    On POSIX the directory is opened no-follow (unless ``follow``, for a
    root the caller named), its descriptor's identity is compared with
    ``expected``, and the listing is read through that descriptor, so a
    directory swapped for a symbolic link, or a parent swapped above it,
    is refused rather than listed. Entries then name only themselves:
    join them to ``path``, and query them before the listing is closed.

    On Windows a directory cannot be listed by descriptor; its identity is
    checked by path immediately before listing, which narrows the window
    without closing it.

    Raises:
        OSError: If the directory cannot be opened or listed, or with
            :func:`changed_error` if it is not the one expected.
    """
    if not LIST_BY_DESCRIPTOR:  # pragma: no cover - Windows only
        status = path.stat() if follow else path.lstat()
        if expected is not None and identity_of(status) != expected:
            raise changed_error(path)
        with os.scandir(path) as listing:
            yield listing
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if not follow and exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise changed_error(path) from exc
        raise
    try:
        if expected is not None and identity_of(os.fstat(fd)) != expected:
            raise changed_error(path)
        with os.scandir(fd) as listing:
            yield listing
    finally:
        os.close(fd)
