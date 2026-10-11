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
import os
import stat
import sys
from pathlib import Path

__all__ = [
    "SAFE_OPEN_FLAGS",
    "WINDOWS",
    "exposed_directory",
    "fsync_directory",
    "group_or_world_readable",
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
    """Apply POSIX ``mode`` to a path. No-op on Windows (ACLs)."""
    if not WINDOWS:
        path.chmod(mode)


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
