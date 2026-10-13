# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Human-readable rendering of byte counts and durations."""

from __future__ import annotations

import logging

from ._constants import _UNIT_STEP

logger = logging.getLogger(__name__)


def _format_bytes(count: int) -> str:
    """Render a byte count in the largest unit that keeps it readable."""
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < _UNIT_STEP or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= _UNIT_STEP
    return f"{size:.1f} TiB"  # pragma: no cover - unreachable, loop returns


def _format_duration(seconds: float) -> str:
    """Render a duration compactly."""
    if seconds < 60:  # noqa: PLR2004
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m{secs:02d}s"
