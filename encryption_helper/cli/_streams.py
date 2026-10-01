# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Reading input and writing output, in whole and in segments."""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import IO

from .._io import (
    _WINDOWS,
    read_bytes,
    resolve_destination,
    secure_write_bytes,
)
from ..crypto.envelope import (
    AEAD_AES_256_GCM_STREAM,
)
from ..errors import (
    KeyExistsError,
    KeyReadError,
    KeyWriteError,
)
from ._constants import (
    _AEAD_ID_OFFSET,
    _PEEK_SIZE,
    _STDIO,
    DEFAULT_MAX_INPUT_BYTES,
)
from ._output import _fail_usage

logger = logging.getLogger(__name__)


def _read_input(source: str, *, max_size: int = DEFAULT_MAX_INPUT_BYTES) -> bytes:
    """Read from a path, or from stdin when ``source`` is ``-``.

    Enforces a ceiling, because the whole payload is held in memory and peak
    usage is about four times its size. Refusing is better than being killed
    by the OOM reaper half way through writing an output file.

    Raises:
        SystemExit: If the input exceeds ``max_size``.
    """
    if source == _STDIO:
        # Read one byte past the limit so an oversized stream is detected
        # without buffering all of it.
        data = sys.stdin.buffer.read(max_size + 1)
        if len(data) > max_size:
            _fail_usage(
                f"Input exceeds the {max_size}-byte limit. Raise --max-size if "
                "you have the memory for roughly four times that."
            )
        return data

    path = Path(source).expanduser()
    try:
        size = path.stat().st_size
    except OSError:
        size = 0  # read_bytes() reports the real problem in a moment.
    if size > max_size:
        _fail_usage(
            f"{path} is {size} bytes, which exceeds the {max_size}-byte limit. "
            "Raise --max-size if you have the memory for roughly four times "
            "that."
        )
    return read_bytes(path)


def _write_output(destination: str, data: bytes, *, mode: int, force: bool) -> str:
    """Write to a path, or to stdout when ``destination`` is ``-``.

    Returns:
        A human-readable description of where the data went.
    """
    if destination == _STDIO:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return "<stdout>"
    path = secure_write_bytes(destination, data, mode=mode, overwrite=force)
    return str(path)


@contextlib.contextmanager
def _input_stream(source: str) -> Iterator[IO[bytes]]:
    """Yield a readable binary stream for a path, or stdin for ``-``."""
    if source == _STDIO:
        yield sys.stdin.buffer
        return
    path = Path(source).expanduser()
    try:
        handle = path.open("rb")
    except OSError as exc:
        msg = f"Could not read {path}: {exc.strerror}"
        raise KeyReadError(msg) from exc
    try:
        yield handle
    finally:
        handle.close()


@contextlib.contextmanager
def _output_stream(
    destination: str, *, mode: int, force: bool
) -> Iterator[tuple[IO[bytes], list[str]]]:
    """Yield a writable binary stream, committing atomically on success.

    Streaming writes plaintext as each segment is authenticated, so a failure
    part way through leaves an incomplete file. Writing to a temporary file in
    the destination directory and renaming only on success means the caller
    never sees a partial result.

    Yields:
        The stream, and a one-element list that receives the final
        destination description once committed.
    """
    reported: list[str] = []
    if destination == _STDIO:
        yield sys.stdout.buffer, reported
        sys.stdout.buffer.flush()
        reported.append("<stdout>")
        return

    target = resolve_destination(destination)

    # A character device, fifo or socket is not a file to be preserved or
    # replaced. `--out /dev/null` is a legitimate way to discard output, and
    # renaming a temporary file over /dev/null would destroy the device node
    # -- so those destinations are written through directly, with no
    # existence guard and no atomic commit.
    if target.exists() and not target.is_file():
        try:
            handle = target.open("wb")
        except OSError as exc:
            msg = f"Could not write to {target}: {exc.strerror}"
            raise KeyWriteError(msg) from exc
        try:
            yield handle, reported
            handle.flush()
        finally:
            handle.close()
        reported.append(str(target))
        return

    if target.exists() and not force:
        msg = (
            f"{target} already exists. Pass --force to replace it; the "
            "existing file will be backed up first."
        )
        raise KeyExistsError(msg)

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    tmp_path = Path(tmp_name)
    try:
        if not _WINDOWS:
            os.fchmod(tmp_fd, mode)
        with os.fdopen(tmp_fd, "wb") as handle:
            yield handle, reported
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
    tmp_path.replace(target)
    reported.append(str(target))


def _is_streaming_container(source: str) -> bool:
    """Peek a container's AEAD identifier without consuming a stream.

    Only used for a real file; a pipe cannot be rewound, so stdin is handled
    by buffering the header inside the reader instead.
    """
    if source == _STDIO:
        return False
    path = Path(source).expanduser()
    try:
        with path.open("rb") as handle:
            head = handle.read(_PEEK_SIZE)
    except OSError:
        return False
    return len(head) >= _PEEK_SIZE and head[_AEAD_ID_OFFSET] == AEAD_AES_256_GCM_STREAM
