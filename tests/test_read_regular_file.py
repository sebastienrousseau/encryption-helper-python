# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""The public bounded, non-blocking, regular-file-only read.

The MCP server re-implemented one, with its own copy of the open flags,
because the core offered only :func:`read_bytes` -- which blocks on a FIFO
by design, for ``--in <(cmd)``. The inventory scan has a third copy. Both
can now share :func:`read_regular_file`, so its contract is pinned here:
raw ``OSError`` for open failures, :class:`NotRegularFileError` (an
``OSError`` too) for a FIFO or device, and a prefix mode that never raises
for size.
"""

from __future__ import annotations

import errno
import os
import re

import pytest
from encryption_helper import read_regular_file
from encryption_helper._io import InputTooLargeError, NotRegularFileError
from encryption_helper.errors import KeyReadError

from ._support import posix_only


class TestReadRegularFile:
    """L11: the bounded, non-blocking, regular-file-only read, made public."""

    def test_reads_a_file_within_the_limit(self, tmp_path):
        source = tmp_path / "f"
        source.write_bytes(b"x" * 10)
        assert read_regular_file(source, 10) == b"x" * 10

    def test_refuses_a_file_over_the_limit(self, tmp_path):
        source = tmp_path / "f"
        source.write_bytes(b"x" * 11)
        with pytest.raises(InputTooLargeError) as info:
            read_regular_file(source, 10)
        assert info.value.limit == 10
        assert info.value.path == source

    def test_prefix_returns_the_first_limit_bytes(self, tmp_path):
        source = tmp_path / "f"
        source.write_bytes(b"abcdefghij")
        assert read_regular_file(source, 4, prefix=True) == b"abcd"
        assert read_regular_file(source, 40, prefix=True) == b"abcdefghij"

    def test_a_directory_is_refused_by_its_open(self, tmp_path):
        with pytest.raises(OSError, match=r"directory|denied"):
            read_regular_file(tmp_path, 10)

    @posix_only
    def test_the_refusal_is_both_an_os_error_and_a_library_error(self, tmp_path):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises(NotRegularFileError) as info:
            read_regular_file(fifo, 10)
        assert isinstance(info.value, OSError)
        assert isinstance(info.value, KeyReadError)
        assert info.value.filename == str(fifo)
        assert info.value.strerror == "not a regular file"

    @posix_only
    def test_a_fifo_without_a_writer_neither_blocks_nor_is_read(self, tmp_path):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises(NotRegularFileError, match="not a regular file"):
            read_regular_file(fifo, 10)

    @posix_only
    def test_a_device_is_refused(self):
        with pytest.raises(NotRegularFileError):
            read_regular_file("/dev/zero", 10, prefix=True)

    @posix_only
    def test_a_symlink_is_not_followed(self, tmp_path):
        real = tmp_path / "real"
        real.write_bytes(b"data")
        link = tmp_path / "link"
        link.symlink_to(real)
        with pytest.raises(OSError, match=re.escape(os.strerror(errno.ELOOP))) as info:
            read_regular_file(link, 10)
        assert info.value.errno == errno.ELOOP

    def test_a_missing_file_raises_the_os_error(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            read_regular_file(tmp_path / "absent", 10)

    def test_a_negative_limit_is_refused(self, tmp_path):
        with pytest.raises(ValueError, match="limit"):
            read_regular_file(tmp_path / "absent", -1)

    def test_it_is_exported(self):
        import encryption_helper

        assert "read_regular_file" in encryption_helper.__all__
