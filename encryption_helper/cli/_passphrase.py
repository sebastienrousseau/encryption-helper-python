# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Sourcing a passphrase, and loading a private key with it.

A passphrase is never read from a command-line value: process arguments are
world-readable through ``/proc`` and land in shell history. Every function
here takes it from an environment variable, a file, or a terminal prompt.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from .._io import (
    read_bytes,
)
from ..errors import (
    KeyReadError,
)
from ..keys import (
    load_private_key_file,
)
from ._constants import EXIT_USAGE, MAX_PASSPHRASE_FILE_BYTES
from ._output import _fail_usage

logger = logging.getLogger(__name__)


def _passphrase_from_source(args: argparse.Namespace) -> bytes | None:
    r"""Read a passphrase from an environment variable or a file.

    Neither source is echoed back on failure. An error says *which* source was
    unusable and why, never what it contained.

    **Environment variable.** Taken verbatim, apart from a whitespace-only
    value being rejected: that is almost always an unset-variable accident,
    and it offers no protection. A value with meaningful leading or trailing
    spaces is preserved.

    **File.** Exactly one trailing newline is removed -- ``LF`` or ``CRLF`` --
    because a text editor appends one and a user who types ``secret`` into a
    file means ``secret``. Nothing else is stripped, so a passphrase may
    legitimately begin or end with a space, contain internal newlines, or not
    be valid UTF-8.

    Returns:
        The passphrase, or :data:`None` if neither source was requested.

    Raises:
        SystemExit: If the named source is missing, empty, or unusable.
    """
    if getattr(args, "passphrase_env", None):
        value = os.environ.get(args.passphrase_env)
        if value is None:
            _fail_usage(f"Environment variable {args.passphrase_env} is not set.")
        if not value.strip():
            _fail_usage(
                f"Environment variable {args.passphrase_env} is empty or "
                "contains only whitespace, which would not protect the key."
            )
        return _as_passphrase_bytes(value)

    if getattr(args, "passphrase_file", None):
        path = Path(args.passphrase_file).expanduser()
        _reject_oversized_passphrase_file(path)
        _warn_if_passphrase_file_is_readable(path)
        data = _strip_one_trailing_newline(read_bytes(path))
        if not data.strip():
            _fail_usage(
                f"Passphrase file {args.passphrase_file} is empty or contains "
                "only whitespace, which would not protect the key."
            )
        return _as_passphrase_bytes(data)

    return None


def _as_passphrase_bytes(value: str | bytes) -> bytes:
    r"""Convert a passphrase to bytes. The one place this transition happens.

    All three sources converge here so no source can acquire its own encoding
    behaviour by accident:

    * the interactive prompt and ``--passphrase-env`` yield :class:`str`, which
      is UTF-8 encoded;
    * ``--passphrase-file`` yields :class:`bytes`, which pass through
      unchanged, so a file may hold a byte-exact secret that is not valid
      UTF-8 -- a random-bytes secret from ``head -c 32 /dev/urandom``, say.

    Args:
        value: Passphrase text or raw bytes.

    Returns:
        The passphrase as bytes, ready for ``BestAvailableEncryption``.

    Example:
        >>> _as_passphrase_bytes("secret")
        b'secret'
        >>> _as_passphrase_bytes(b"\xff\xfe raw")
        b'\xff\xfe raw'
    """
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _reject_oversized_passphrase_file(path: Path) -> None:
    """Refuse a passphrase file larger than :data:`MAX_PASSPHRASE_FILE_BYTES`.

    The size is checked before reading, so an enormous file is never loaded
    into memory. This is robustness rather than a security control: pointing
    ``--passphrase-file`` at a log or a disk image is a mistake, and it should
    fail as one.

    Raises:
        SystemExit: If the file is too large.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return  # read_bytes() will report the real problem in a moment.
    if size > MAX_PASSPHRASE_FILE_BYTES:
        _fail_usage(
            f"Passphrase file {path} is {size} bytes, which exceeds the "
            f"{MAX_PASSPHRASE_FILE_BYTES}-byte limit. A passphrase file is "
            "expected to contain a passphrase."
        )


def _warn_if_passphrase_file_is_readable(path: Path) -> None:
    """Warn if a passphrase file is group- or world-readable on POSIX.

    Deliberately a warning, not a refusal. CI secret mounts, container
    tmpfs and enterprise filesystems have permission models this check cannot
    reason about, so rejecting would break legitimate setups while promising a
    guarantee we cannot make.

    On Windows this is skipped entirely rather than pretending Unix mode bits
    describe an ACL.
    """
    if sys.platform == "win32":
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:  # pragma: no cover - reported by the subsequent read
        return
    if mode & 0o077:
        print(
            f"warning: passphrase file {path} is mode {mode:04o}, readable by "
            "others.\n"
            "         Consider `chmod 600` unless your platform's access "
            "control makes that\n"
            "         unnecessary.",
            file=sys.stderr,
        )


def _strip_one_trailing_newline(data: bytes) -> bytes:
    r"""Remove a single trailing ``LF`` or ``CRLF``, and nothing else.

    Args:
        data: Raw file contents.

    Returns:
        The contents without one trailing line ending.

    Example:
        >>> _strip_one_trailing_newline(b"secret\n")
        b'secret'
        >>> _strip_one_trailing_newline(b"secret\r\n")
        b'secret'
        >>> _strip_one_trailing_newline(b"secret\n\n")
        b'secret\n'
        >>> _strip_one_trailing_newline(b" secret ")
        b' secret '
    """
    if data.endswith(b"\r\n"):
        return data[:-2]
    if data.endswith(b"\n"):
        return data[:-1]
    return data


def _interactive() -> bool:
    """Whether a human is present to answer a prompt."""
    return sys.stdin.isatty() and sys.stderr.isatty()


def _prompt_new_passphrase() -> bytes:
    """Prompt twice for a new passphrase, without echoing it.

    Returns:
        The confirmed passphrase.

    Raises:
        SystemExit: If the two entries differ or the passphrase is empty.
    """
    first = getpass.getpass("Passphrase for the new private key: ")
    if not first.strip():
        _fail_usage(
            "An empty passphrase does not protect the key. Pass "
            "--no-passphrase if you intend to store it unencrypted."
        )
    if getpass.getpass("Confirm passphrase: ") != first:
        _fail_usage("The passphrases did not match.")
    return _as_passphrase_bytes(first)


def _new_key_passphrase(args: argparse.Namespace) -> bytes | None:
    """Decide how a newly generated private key will be protected.

    Storing a private key in plaintext is a real decision, so it has to be a
    deliberate one. A passphrase comes from an explicit source or an
    interactive prompt; going without requires ``--no-passphrase``. There is
    no path that silently produces an unprotected key.

    Returns:
        The passphrase, or :data:`None` if the user opted out explicitly.

    Raises:
        SystemExit: If no source was given and none can be established.
    """
    if args.no_passphrase:
        return None

    supplied = _passphrase_from_source(args)
    if supplied is not None:
        return supplied

    if _interactive():
        return _prompt_new_passphrase()

    print(
        "error: refusing to write an unencrypted private key by default.\n"
        "  Supply a passphrase with --passphrase-env VAR or "
        "--passphrase-file PATH,\n"
        "  or pass --no-passphrase to store the key unencrypted on purpose.",
        file=sys.stderr,
    )
    raise SystemExit(EXIT_USAGE)


def _existing_key_passphrase(args: argparse.Namespace) -> bytes | None:
    """Read the passphrase for an existing key, if one was supplied."""
    return _passphrase_from_source(args)


def _load_private_key(args: argparse.Namespace, path: str) -> PrivateKeyTypes:
    """Load a private key, prompting for a passphrase only if one is needed.

    Tries without a passphrase first, so an unencrypted key never triggers a
    pointless prompt, and prompts once if that fails and a human is present.

    Raises:
        KeyReadError: If the key cannot be loaded.
    """
    supplied = _existing_key_passphrase(args)
    if supplied is not None:
        return load_private_key_file(path, passphrase=supplied)

    try:
        return load_private_key_file(path)
    except KeyReadError:
        if not _interactive():
            raise
    prompt = getpass.getpass(f"Passphrase for {path}: ")
    return load_private_key_file(path, passphrase=_as_passphrase_bytes(prompt))
