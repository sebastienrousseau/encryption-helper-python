# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Throttled progress reporting for long streaming operations."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import IO

from ._constants import _STDIO
from ._format import _format_bytes, _format_duration

logger = logging.getLogger(__name__)


class _ProgressReporter:
    """Report streaming progress to stderr, throttled.

    On stderr rather than stdout because stdout may be carrying the
    command's output. Throttled to one update per interval so a fast
    operation does not spend more time formatting than encrypting -- at
    1.5 GB/s with 256 KiB segments there are roughly 6,000 callbacks a
    second, and printing each would dominate the run.

    When the input size is known the line includes a percentage and an ETA.
    Reading from a pipe it cannot be, so only the running total and rate are
    shown.
    """

    #: Minimum seconds between updates.
    INTERVAL = 0.2

    def __init__(self, total: int | None, *, stream: IO[str] | None = None) -> None:
        self._total = total
        self._stream = stream if stream is not None else sys.stderr
        self._started = time.monotonic()
        self._last = 0.0
        self._interactive = self._stream.isatty()

    def __call__(self, processed: int) -> None:
        """Receive a cumulative byte count from the streaming layer."""
        now = time.monotonic()
        if now - self._last < self.INTERVAL:
            return
        self._last = now
        self._write(processed, now, final=False)

    def finish(self, processed: int) -> None:
        """Emit a final line, whatever the throttle said."""
        self._write(processed, time.monotonic(), final=True)
        if self._interactive:
            self._stream.write("\n")
        self._stream.flush()

    def _write(self, processed: int, now: float, *, final: bool) -> None:
        elapsed = max(now - self._started, 1e-9)
        rate = processed / elapsed
        parts = [f"{_format_bytes(processed)}"]
        if self._total:
            percent = min(100.0, processed * 100.0 / self._total)
            parts.append(f"{percent:5.1f}%")
            if rate > 0 and not final:
                remaining = max(self._total - processed, 0) / rate
                parts.append(f"ETA {_format_duration(remaining)}")
        parts.append(f"{_format_bytes(int(rate))}/s")
        if final:
            parts.append(f"in {_format_duration(elapsed)}")
        line = "  ".join(parts)
        # Overwrite in place on a terminal; append lines when redirected, so a
        # log stays readable.
        self._stream.write(f"\r{line}\x1b[K" if self._interactive else f"{line}\n")
        self._stream.flush()


def _make_progress(
    args: argparse.Namespace, source: str
) -> tuple[_ProgressReporter | None, None]:
    """Build a reporter when ``--progress`` was asked for.

    Returns:
        A ``(reporter, None)`` pair; the second element keeps the call site
        symmetrical with other optional-resource helpers.
    """
    if not getattr(args, "progress", False) or args.quiet:
        return None, None
    total: int | None = None
    if source != _STDIO:
        try:
            total = Path(source).expanduser().stat().st_size
        except OSError:  # pragma: no cover - the reader reports it
            total = None
    return _ProgressReporter(total), None
