# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Encrypt a file too large to hold in memory.

:func:`encrypt` keeps the whole message in memory, which suits keys and
documents but not a multi-gigabyte archive. The streaming functions process
the payload in independently authenticated segments, so peak memory stays
bounded regardless of input size.

This example uses 8 MiB, which is enough to span many segments while staying
small enough to run on a constrained temporary filesystem -- it writes the
payload three times over, as plaintext, ciphertext and recovered output. The
same code path has been measured against 5 GB at a flat working set of
roughly 30 MB, which is the point: the figure below does not grow with the
input.

Run:
    python examples/06_large_files.py
"""

from __future__ import annotations

import resource
import sys
import time

from _workspace import workspace
from encryption_helper import generate
from encryption_helper.crypto.streaming import (
    DEFAULT_SEGMENT_SIZE,
    decrypt_stream,
    encrypt_stream,
)

PAYLOAD_BYTES = 8 * 1024 * 1024


def peak_memory_mib() -> float:
    """Return this process's peak resident set size in MiB."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # ru_maxrss is reported in kilobytes on Linux and in bytes on macOS.
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    return peak / divisor


def main() -> int:
    """Stream a payload through encryption and back, reporting throughput."""
    directory = workspace()
    plaintext = directory / "archive.bin"
    ciphertext = directory / "archive.enc"
    recovered = directory / "archive.out"

    # A repeating pattern rather than random bytes: this example is measuring
    # the cipher, not the operating system's entropy source.
    plaintext.write_bytes(b"0123456789abcdef" * (PAYLOAD_BYTES // 16))

    key = generate("mlkem")

    # --- Encrypt -----------------------------------------------------------
    # Progress is reported through a callback. The library never prints; the
    # caller decides how, or whether, to display it.
    segments = 0

    def count_segments(_written: int) -> None:
        nonlocal segments
        segments += 1

    started = time.perf_counter()
    with plaintext.open("rb") as source, ciphertext.open("wb") as destination:
        written = encrypt_stream(
            key.public_key(), source, destination, progress=count_segments
        )
    encrypt_seconds = time.perf_counter() - started

    # --- Decrypt -----------------------------------------------------------
    started = time.perf_counter()
    with ciphertext.open("rb") as source, recovered.open("wb") as destination:
        read_back = decrypt_stream(key, source, destination)
    decrypt_seconds = time.perf_counter() - started

    if recovered.read_bytes() != plaintext.read_bytes():  # pragma: no cover
        msg = "round trip did not reproduce the input"
        raise AssertionError(msg)

    mib = PAYLOAD_BYTES / (1024 * 1024)
    overhead = ciphertext.stat().st_size - PAYLOAD_BYTES
    print(f"Payload          {mib:.0f} MiB in {segments} segments")
    print(f"Segment size     {DEFAULT_SEGMENT_SIZE // 1024} KiB")
    print(f"Encrypt          {encrypt_seconds:.2f}s  {mib / encrypt_seconds:.0f} MiB/s")
    print(f"Decrypt          {decrypt_seconds:.2f}s  {mib / decrypt_seconds:.0f} MiB/s")
    print(f"Ciphertext       +{overhead} bytes of framing and tags")
    print(f"Peak memory      {peak_memory_mib():.0f} MiB")
    print(f"Round trip       {written} bytes out, {read_back} bytes back, identical")
    print()
    print("Peak memory does not scale with the payload: each segment is")
    print("encrypted and written before the next is read. The per-segment")
    print("authentication tag is what the extra bytes pay for, and it is also")
    print("what makes reordering, dropping or truncating a segment detectable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
