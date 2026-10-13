# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""One stuck or oversized call must not take the server down.

The server is single-threaded and driven by a model, so every request it
accepts has to finish in bounded time and memory. Before these checks a FIFO
inside the root stalled ``inspect_container`` forever, ``fingerprint_public_key``
read a file of any size, a scan returned every finding, and the message cap
was applied only after the whole line had been buffered.
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading

import pytest
from encryption_helper import encode_public_key, generate
from encryption_helper.keys.load import MAX_KEY_FILE_BYTES

from encryption_helper_mcp import _tools
from encryption_helper_mcp._tools import MAX_SCAN_LIMIT, ToolError, call
from encryption_helper_mcp.server import (
    INVALID_REQUEST,
    MAX_MESSAGE_BYTES,
    PARSE_ERROR,
    serve,
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="FIFOs and O_NOFOLLOW are POSIX"
)


def _finishes(function, *args, timeout: float = 10.0):
    """Run ``function`` in a thread; fail rather than hang if it stalls."""
    outcome: dict[str, object] = {}

    def run() -> None:
        try:
            outcome["value"] = function(*args)
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            outcome["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    assert not worker.is_alive(), f"{function.__name__} did not return"
    if "error" in outcome:
        raise outcome["error"]  # type: ignore[misc]
    return outcome.get("value")


@posix_only
class TestNonRegularFiles:
    @pytest.mark.parametrize("tool", ["inspect_container", "fingerprint_public_key"])
    def test_a_fifo_is_refused_without_blocking(self, tmp_path, tool):
        root = tmp_path.resolve()
        os.mkfifo(root / "trap")
        with pytest.raises(ToolError, match="not a regular file"):
            _finishes(call, root, tool, {"path": "trap"})

    def test_a_link_swapped_in_after_confinement_is_not_followed(self, tmp_path):
        """O_NOFOLLOW closes the window between resolve() and open()."""
        root = tmp_path.resolve()
        (root / "real.pub").write_bytes(b"x")
        (root / "link.pub").symlink_to(root / "real.pub")
        with pytest.raises(ToolError):
            _tools._read_regular_file(root / "link.pub", 10)


class TestSizeLimits:
    def test_an_oversized_public_key_file_is_refused(self, tmp_path):
        root = tmp_path.resolve()
        (root / "huge.pub").write_bytes(b"-" * (MAX_KEY_FILE_BYTES + 1))
        with pytest.raises(ToolError, match="byte limit"):
            call(root, "fingerprint_public_key", {"path": "huge.pub"})

    def test_a_large_container_is_still_inspected_from_its_header(self, tmp_path):
        from encryption_helper import encrypt

        root = tmp_path.resolve()
        key = generate("x25519")
        blob = encrypt(key.public_key(), b"x" * (2 * MAX_KEY_FILE_BYTES))
        (root / "big.enc").write_bytes(blob)
        result = call(root, "inspect_container", {"path": "big.enc"})
        assert result["key_establishment"] == "x25519-hkdf-sha256"


class TestScanLimit:
    @pytest.fixture
    def root(self, tmp_path):
        root = tmp_path.resolve()
        for number in range(5):
            key = generate("ed25519").public_key()
            (root / f"k{number}.pub").write_bytes(encode_public_key(key))
        return root

    def test_findings_are_capped_but_the_summary_is_complete(self, root):
        result = call(root, "scan_directory", {"path": ".", "limit": 2})
        assert len(result["findings"]) == 2
        assert result["truncated"] is True
        assert result["summary"]["examined"] == 5

    def test_under_the_limit_nothing_is_truncated(self, root):
        result = call(root, "scan_directory", {"path": "."})
        assert len(result["findings"]) == 5
        assert result["truncated"] is False

    @pytest.mark.parametrize("limit", [0, -1, MAX_SCAN_LIMIT + 1, "5", True, 2.5])
    def test_an_invalid_limit_is_refused(self, root, limit):
        with pytest.raises(ToolError, match="'limit'"):
            call(root, "scan_directory", {"path": ".", "limit": limit})


class _CountingSource(io.StringIO):
    """Records the largest single read the server asks for."""

    largest = 0

    def readline(self, size: int | None = -1, /) -> str:
        line = super().readline(size)
        type(self).largest = max(type(self).largest, len(line))
        return line


class TestMessageLimit:
    def _ping(self) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}) + "\n"

    def test_an_oversized_line_is_never_held_whole(self, tmp_path):
        source = _CountingSource("x" * (MAX_MESSAGE_BYTES * 3) + "\n" + self._ping())
        sink = io.StringIO()
        serve(tmp_path, source, sink)
        assert _CountingSource.largest <= MAX_MESSAGE_BYTES + 1

    def test_the_session_continues_after_an_oversized_line(self, tmp_path):
        source = io.StringIO("x" * (MAX_MESSAGE_BYTES * 2) + "\n" + self._ping())
        sink = io.StringIO()
        serve(tmp_path, source, sink)
        first, second = (json.loads(line) for line in sink.getvalue().splitlines())
        assert first["error"]["code"] == INVALID_REQUEST
        assert second == {"jsonrpc": "2.0", "id": 9, "result": {}}

    def test_the_limit_is_in_bytes_not_characters(self, tmp_path):
        """Four-byte characters under the character count, over the byte cap."""
        line = "\U0001f512" * (MAX_MESSAGE_BYTES // 4 + 1) + "\n"
        sink = io.StringIO()
        serve(tmp_path, io.StringIO(line), sink)
        assert json.loads(sink.getvalue())["error"]["code"] == INVALID_REQUEST


class TestUndecodableMessages:
    """A line the decoder cannot finish must cost one error, not the session.

    ``json.loads`` raises more than ``JSONDecodeError``: nesting deeper than
    the interpreter's stack raises ``RecursionError``, and an integer longer
    than ``sys.get_int_max_str_digits()`` raises ``ValueError``. Either one
    used to escape ``serve()`` and end the process, so a single message --
    well inside the size limit -- stopped the server for every later call.
    """

    PING = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}) + "\n"

    @pytest.mark.parametrize(
        "line",
        [
            '{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": '
            + "[" * 200_000
            + "\n",
            '{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"n": '
            + "9" * 5000
            + "}}\n",
        ],
        ids=["deep-nesting", "huge-integer"],
    )
    def test_the_session_survives_and_answers_the_next_call(self, tmp_path, line):
        sink = io.StringIO()
        serve(tmp_path, io.StringIO(line + self.PING), sink)
        first, second = (json.loads(out) for out in sink.getvalue().splitlines())
        assert first["error"]["code"] == PARSE_ERROR
        assert first["id"] is None
        assert second == {"jsonrpc": "2.0", "id": 9, "result": {}}
