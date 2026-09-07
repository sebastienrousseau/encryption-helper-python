# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Standalone fuzz runner: no engine, no compiler, no extra dependencies.

Atheris gives better coverage-guided exploration, but it needs a matching
Python build and a compiler, which makes it awkward as a required CI gate.
This runner is deterministic given a seed, so any finding it reports can be
reproduced exactly from the printed command line.

Run:
    python fuzz/run_fuzz.py --iterations 20000
    python fuzz/run_fuzz.py --target decrypt --seed 42
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from collections.abc import Callable

from targets import TARGETS, FuzzFindingError

#: Structured prefixes worth generating often: an input that never resembles a
#: real container only ever exercises the "bad magic" rejection.
_INTERESTING_PREFIXES = (
    b"EHEV",  # correct magic
    b"EHEV\x01\x01\x01\x00",  # correct magic and header fields
    b"EHEV\x02\x01\x01\x00",  # unsupported version
    b"EHEV\xff\xff\xff\xff",  # nonsense header
    b"-----BEGIN PUBLIC KEY-----\n",
    b"-----BEGIN PRIVATE KEY-----\n",
    b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
    b"ssh-rsa ",
    b"ssh-ed25519 ",
    b"\x30\x82",  # DER SEQUENCE
    b"",
)


def generate(rng: random.Random) -> bytes:
    """Produce one input, biased towards shapes the parsers care about."""
    strategy = rng.random()
    if strategy < 0.35:  # noqa: PLR2004
        prefix = rng.choice(_INTERESTING_PREFIXES)
        return prefix + rng.randbytes(rng.randint(0, 512))
    if strategy < 0.5:  # noqa: PLR2004
        # Long runs of one byte find length- and loop-handling bugs.
        return bytes([rng.randint(0, 255)]) * rng.randint(0, 4096)
    if strategy < 0.6:  # noqa: PLR2004
        return b""
    return rng.randbytes(rng.randint(0, 2048))


def run_target(
    name: str, target: Callable[[bytes], None], iterations: int, seed: int
) -> int:
    """Run one target, returning the number of findings."""
    rng = random.Random(seed)  # noqa: S311 - reproducibility, not secrecy
    started = time.perf_counter()

    for iteration in range(iterations):
        data = generate(rng)
        try:
            target(data)
        except FuzzFindingError as finding:
            print(f"\nFINDING in {name} at iteration {iteration}:", file=sys.stderr)
            print(f"  {finding}", file=sys.stderr)
            print(f"  input ({len(data)} bytes): {data[:64]!r}...", file=sys.stderr)
            print(
                f"  reproduce: python fuzz/run_fuzz.py --target {name} "
                f"--seed {seed} --iterations {iteration + 1}",
                file=sys.stderr,
            )
            return 1

    elapsed = time.perf_counter() - started
    rate = iterations / elapsed if elapsed else 0
    print(f"{name:<20} {iterations:>7} iterations  {elapsed:>6.2f}s  {rate:>8.0f}/s")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the requested fuzz targets."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=sorted(TARGETS), help="One target only.")
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=None, help="Default: random.")
    args = parser.parse_args(argv)

    seed = args.seed if args.seed is not None else random.randrange(2**32)  # noqa: S311
    selected = {args.target: TARGETS[args.target]} if args.target else TARGETS

    print(f"seed: {seed}")
    findings = 0
    for name, target in selected.items():
        # `decrypt_mutated` encrypts on every iteration, so it is much slower.
        budget = args.iterations // 20 if name == "decrypt_mutated" else args.iterations
        findings += run_target(name, target, max(1, budget), seed)

    if findings:
        print(f"\n{findings} target(s) reported findings.", file=sys.stderr)
        return 1
    print("\nNo findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
